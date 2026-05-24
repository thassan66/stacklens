import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { rulePacks } from "../src/rule-packs.js";
import { toSarif } from "../src/sarif.js";
import { scanProject } from "../src/scanner.js";
import { resolveAssetPath } from "../src/server.js";

const execFileAsync = promisify(execFile);

test("registers built-in rule packs", () => {
  assert.deepEqual(
    rulePacks.map((pack) => [pack.id, pack.ecosystem]),
    [
      ["@stacklens/common", "common"],
      ["@stacklens/spring", "spring"],
      ["@stacklens/quarkus", "quarkus"],
      ["@stacklens/node", "node"],
      ["@stacklens/react", "react"],
      ["@stacklens/vue", "vue"]
    ]
  );
});

test("detects Spring Boot risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "src", "main", "resources"), { recursive: true });
  await writeFile(
    path.join(root, "pom.xml"),
    `<project>
      <parent>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.1</version>
      </parent>
      <properties><java.version>11</java.version></properties>
      <dependencies>
        <dependency><artifactId>spring-boot-devtools</artifactId></dependency>
      </dependencies>
    </project>`
  );
  await writeFile(
    path.join(root, "src", "main", "resources", "application-prod.yml"),
    `management:
  endpoints:
    web:
      exposure:
        include: "*"
spring:
  datasource:
    password: RealPassword123
`
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Spring Boot"));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/spring" && pack.detected));
  assert.equal(report.ecosystems.spring.springBootVersion, "3.3.1");
  assert.equal(report.ecosystems.spring.javaVersion, "11");
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-actuator-exposes-all"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-hardcoded-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-devtools-not-development-only"));
});

test("detects Quarkus Camel Artemis and deployment risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "src", "main", "resources"), { recursive: true });
  await mkdir(path.join(root, "src", "main", "kubernetes"), { recursive: true });
  await mkdir(path.join(root, "argocd"), { recursive: true });

  await writeFile(
    path.join(root, "pom.xml"),
    `<project>
      <properties>
        <quarkus.platform.version>3.17.1</quarkus.platform.version>
        <maven.compiler.release>11</maven.compiler.release>
      </properties>
      <dependencyManagement>
        <dependencies>
          <dependency>
            <groupId>io.quarkus.platform</groupId>
            <artifactId>quarkus-bom</artifactId>
            <version>\${quarkus.platform.version}</version>
          </dependency>
        </dependencies>
      </dependencyManagement>
      <dependencies>
        <dependency><groupId>io.quarkus</groupId><artifactId>quarkus-resteasy-reactive</artifactId></dependency>
        <dependency><groupId>org.apache.camel.quarkus</groupId><artifactId>camel-quarkus-jms</artifactId></dependency>
        <dependency><groupId>io.quarkus</groupId><artifactId>quarkus-artemis-jms</artifactId></dependency>
      </dependencies>
    </project>`
  );
  await writeFile(
    path.join(root, "src", "main", "resources", "application-prod.properties"),
    `%prod.quarkus.http.insecure-requests=enabled
%prod.quarkus.datasource.password=RealDbPassword123
%prod.quarkus.rest-client.inventory.url=https://user:pass@example.com
%prod.quarkus.messaging.broker-url=tcp://events:61616
%prod.quarkus.artemis.url=tcp://broker:61616
%prod.quarkus.artemis.password=RealBrokerPassword123
%prod.quarkus.artemis.devservices.enabled=true
%prod.quarkus.log.level=DEBUG
%prod.camel.main.tracing=true
camel.component.jms.broker-url=tcp://user:pass@broker:61616
`
  );
  await writeFile(
    path.join(root, "src", "main", "kubernetes", "route.yaml"),
    `apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: quarkus-app
spec:
  to:
    kind: Service
    name: quarkus-app
`
  );
  await writeFile(
    path.join(root, "src", "main", "kubernetes", "deployment.yaml"),
    `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: image-registry.openshift-image-registry.svc:5000/team/quarkus-app:latest
          securityContext:
            privileged: true
          env:
            - name: ARTEMIS_PASSWORD
              value: real-password
`
  );
  await writeFile(
    path.join(root, "argocd", "application.yaml"),
    `apiVersion: argoproj.io/v1alpha1
kind: Application
spec:
  source:
    targetRevision: HEAD
  syncPolicy:
    automated:
      prune: true
`
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Quarkus"));
  assert.ok(report.project.stacks.includes("Apache Camel"));
  assert.ok(report.project.stacks.includes("Apache ActiveMQ Artemis"));
  assert.ok(report.project.stacks.includes("OpenShift"));
  assert.ok(report.project.stacks.includes("Argo CD"));
  assert.ok(!report.project.stacks.includes("Spring Boot"));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/quarkus" && pack.detected));
  assert.equal(report.ecosystems.quarkus.quarkusVersion, "3.17.1");
  assert.equal(report.ecosystems.quarkus.javaVersion, "11");
  assert.equal(report.ecosystems.quarkus.usesCamel, true);
  assert.equal(report.ecosystems.quarkus.usesArtemis, true);
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-older-java-target"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-hardcoded-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "artemis-hardcoded-credential"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-dev-services-prod"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-insecure-http-prod"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-debug-logging-prod"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "camel-tracing-prod"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "camel-endpoint-credentials"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-endpoint-credentials"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "quarkus-plain-tcp-endpoint"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "artemis-plain-tcp-url"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "openshift-route-without-tls"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kubernetes-mutable-image-tag"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kubernetes-privileged-container"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kubernetes-env-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "argocd-mutable-target-revision"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "argocd-auto-prune-enabled"));
});

test("detects generic deployment Helm and Kustomize risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "k8s"), { recursive: true });
  await mkdir(path.join(root, "helm"), { recursive: true });

  await writeFile(
    path.join(root, "k8s", "deployment.yaml"),
    `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: api
          image: registry.example.com/team/api:latest
          env:
            - name: API_TOKEN
              value: real-token
`
  );
  await writeFile(
    path.join(root, "helm", "Chart.yaml"),
    "apiVersion: v2\nname: api\nversion: 0.1.0\n"
  );
  await writeFile(
    path.join(root, "helm", "values-prod.yaml"),
    `image:
  repository: registry.example.com/team/api
  tag: latest
  pullPolicy: Always
database:
  password: RealDbPassword123
`
  );
  await writeFile(
    path.join(root, "kustomization.yaml"),
    `resources:
  - https://github.com/example/platform//base?ref=main
images:
  - name: registry.example.com/team/api
    newTag: latest
`
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Helm"));
  assert.ok(report.project.stacks.includes("Kustomize"));
  assert.ok(!report.project.stacks.includes("Quarkus"));
  assert.equal(report.ecosystems.common.hasHelm, true);
  assert.equal(report.ecosystems.common.hasKustomize, true);
  assert.ok(report.findings.some((finding) => finding.ruleId === "kubernetes-mutable-image-tag"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kubernetes-env-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "helm-mutable-image-tag"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "helm-image-pull-always"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "helm-values-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kustomize-mutable-image-tag"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "kustomize-remote-resource"));
});

test("detects generic Jenkins Terraform AWS Azure and Docker deployment risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "infra"), { recursive: true });
  await mkdir(path.join(root, "aws"), { recursive: true });
  await mkdir(path.join(root, "azure"), { recursive: true });

  await writeFile(path.join(root, "Dockerfile"), "FROM alpine:3.20\n");
  await writeFile(
    path.join(root, "Jenkinsfile"),
    `pipeline {
  agent any
  environment {
    API_TOKEN = 'real-token'
  }
  stages {
    stage('deploy') {
      steps {
        sh 'curl https://example.com/install.sh | bash'
        sh 'docker run --privileged alpine true'
      }
    }
  }
}
`
  );
  await writeFile(
    path.join(root, "infra", "main.tf"),
    `variable "db_password" {
  default = "RealPassword123"
}

resource "aws_security_group" "admin" {
  ingress {
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  password = "RealDbPassword123"
}

resource "aws_s3_bucket_acl" "public" {
  acl = "public-read"
}

resource "azurerm_storage_account" "data" {
  public_network_access_enabled = true
  allow_blob_public_access = true
}
`
  );
  await writeFile(
    path.join(root, "aws", "template.yaml"),
    `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  AdminIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      FromPort: 3389
      ToPort: 3389
      CidrIp: 0.0.0.0/0
  PublicPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyDocument:
        Statement:
          Effect: Allow
          Principal: "*"
          Action: "*"
          Resource: "*"
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
`
  );
  await writeFile(
    path.join(root, "azure", "azure-pipelines.yml"),
    `variables:
  AZURE_CLIENT_SECRET: real-secret
steps:
  - script: echo deploy
`
  );
  await writeFile(
    path.join(root, "azure", "main.bicep"),
    `resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'examplestorage'
  properties: {
    allowBlobPublicAccess: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}
`
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Docker"));
  assert.ok(report.project.stacks.includes("Jenkins"));
  assert.ok(report.project.stacks.includes("Terraform"));
  assert.ok(report.project.stacks.includes("AWS"));
  assert.ok(report.project.stacks.includes("Azure"));
  assert.equal(report.ecosystems.common.hasDocker, true);
  assert.equal(report.ecosystems.common.hasJenkins, true);
  assert.equal(report.ecosystems.common.hasTerraform, true);
  assert.equal(report.ecosystems.common.hasAws, true);
  assert.equal(report.ecosystems.common.hasAzure, true);
  assert.ok(report.findings.some((finding) => finding.ruleId === "jenkins-secret-env"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "jenkins-remote-script-execution"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "jenkins-privileged-docker"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "terraform-secret-default"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "terraform-public-admin-ingress"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "terraform-public-compute-or-database"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "terraform-public-storage"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "aws-public-admin-ingress"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "aws-public-iam-principal"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "aws-wildcard-iam-permission"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "aws-public-resource"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "azure-plain-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "azure-public-network-access"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "azure-public-storage-or-network"));
});

test("detects Node and frontend risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js",
        dev: "curl https://example.com/install.sh | bash"
      },
      dependencies: {
        react: "^19.0.0",
        vite: "^7.0.0"
      }
    })
  );
  await writeFile(path.join(root, ".env.example"), "API_KEY=real-demo-key\n");
  await writeFile(path.join(root, "package-lock.json"), "{}");
  await writeFile(path.join(root, "yarn.lock"), "# demo");

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Node.js"));
  assert.ok(report.project.stacks.includes("React"));
  assert.ok(report.project.stacks.includes("Vite"));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/node" && pack.detected));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/react" && pack.detected));
  assert.equal(report.ecosystems.react.projectCount, 1);
  assert.equal(report.ecosystems.node.packageManager, "Yarn");
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-lifecycle-script"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "remote-script-execution"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "env-example-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "multiple-node-lockfiles"));
});

test("detects Vue frontend configuration risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "src"), { recursive: true });

  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        build: "vite build --mode=development"
      },
      dependencies: {
        vue: "^3.5.0"
      },
      devDependencies: {
        "@vitejs/plugin-vue": "^6.0.0",
        vite: "^7.0.0"
      }
    })
  );
  await writeFile(path.join(root, ".env.local"), "VITE_API_TOKEN=real-browser-token\n");
  await writeFile(
    path.join(root, "nuxt.config.ts"),
    `export default defineNuxtConfig({
  runtimeConfig: {
    secretToken: "server-only-token",
    public: {
      apiToken: "real-runtime-token"
    }
  }
})
`
  );
  await writeFile(path.join(root, "vite.config.ts"), "export default { build: { sourcemap: true } }\n");
  await writeFile(
    path.join(root, "src", "App.vue"),
    "<template><main>Hello</main></template>\n<script setup>import { ref } from 'vue'</script>\n"
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Vue"));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/vue" && pack.detected));
  assert.equal(report.ecosystems.vue.projectCount, 1);
  assert.ok(report.findings.some((finding) => finding.ruleId === "vue-public-env-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "vue-public-runtime-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "vue-build-uses-development-mode"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "vue-production-sourcemaps-enabled"));
  assert.ok(!report.findings.some((finding) => finding.snippet.includes("server-only-token")));
});

test("does not detect Vue from matcher text alone", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, "src"), { recursive: true });
  await writeFile(path.join(root, "package.json"), JSON.stringify({ scripts: { test: "node src/rules.js" } }));
  await writeFile(path.join(root, "src", "rules.js"), "const matcher = /<template\\\\b/;\n");

  const report = await scanProject(root);

  assert.ok(!report.project.stacks.includes("Vue"));
  assert.ok(report.rulePacks.some((pack) => pack.id === "@stacklens/vue" && !pack.detected));
});

test("converts findings to SARIF", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  const report = await scanProject(root);
  const sarif = toSarif(report);
  const result = sarif.runs[0].results.find((item) => item.ruleId === "node-lifecycle-script");

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "stacklens");
  assert.ok(sarif.runs[0].tool.driver.rules.some((rule) => rule.id === "node-lifecycle-script"));
  assert.equal(result.level, "error");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "package.json");
});

test("CLI emits SARIF output", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  const { stdout } = await execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--sarif", root]);
  const sarif = JSON.parse(stdout);

  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.some((result) => result.ruleId === "node-lifecycle-script"));
});

test("CLI rejects conflicting output formats", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--json", "--sarif", "."]),
    (error) => {
      assert.match(error.stderr, /--json or --sarif/);
      return true;
    }
  );
});

test("CLI fail threshold applies to SARIF output", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--sarif", "--fail-on", "high", root]),
    (error) => {
      const sarif = JSON.parse(error.stdout);
      assert.equal(sarif.version, "2.1.0");
      assert.ok(sarif.runs[0].results.some((result) => result.ruleId === "node-lifecycle-script"));
      assert.equal(error.code, 1);
      return true;
    }
  );
});

test("GitHub Action runner writes a SARIF report", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  const githubOutput = path.join(root, "github-output.txt");
  const reportPath = path.join(root, "reports", "stacklens.sarif");
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  const result = await execFileAsync(process.execPath, [path.resolve("src", "action.js")], {
    env: {
      ...process.env,
      GITHUB_WORKSPACE: root,
      GITHUB_OUTPUT: githubOutput,
      INPUT_PATH: ".",
      INPUT_OUTPUT_FORMAT: "sarif",
      INPUT_OUTPUT_FILE: reportPath
    }
  });
  const sarif = JSON.parse(await readFile(reportPath, "utf8"));
  const output = await readFile(githubOutput, "utf8");

  assert.equal(result.stderr, "");
  assert.equal(sarif.version, "2.1.0");
  assert.ok(sarif.runs[0].results.some((item) => item.ruleId === "node-lifecycle-script"));
  assert.match(output, new RegExp(`report-path=${escapeRegExp(reportPath)}`));
});

test("GitHub Action runner preserves report output when fail threshold matches", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  const githubOutput = path.join(root, "github-output.txt");
  const reportPath = path.join(root, "stacklens.json");
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "action.js")], {
      env: {
        ...process.env,
        GITHUB_WORKSPACE: root,
        GITHUB_OUTPUT: githubOutput,
        INPUT_PATH: ".",
        INPUT_OUTPUT_FORMAT: "json",
        INPUT_OUTPUT_FILE: reportPath,
        INPUT_FAIL_ON: "high"
      }
    }),
    (error) => {
      const report = JSON.parse(readFileSync(reportPath, "utf8"));
      assert.equal(error.code, 1);
      assert.equal(report.summary.high, 1);
      return true;
    }
  );
});

test("GitHub Action runner validates output format", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));

  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "action.js")], {
      env: {
        ...process.env,
        GITHUB_WORKSPACE: root,
        INPUT_OUTPUT_FORMAT: "xml"
      }
    }),
    (error) => {
      assert.match(error.stderr, /output-format must be one of/);
      return true;
    }
  );
});

test("CLI changed mode only reports findings in changed files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await mkdir(path.join(root, ".github", "workflows"), { recursive: true });
  await writeFile(
    path.join(root, ".github", "workflows", "ci.yml"),
    "name: ci\non: pull_request\npermissions: write-all\n"
  );
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        test: "node test.js"
      }
    })
  );

  await execFileAsync("git", ["init"], { cwd: root });
  await execFileAsync("git", ["add", "."], { cwd: root });
  await execFileAsync("git", ["-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "initial"], { cwd: root });

  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );
  await execFileAsync("git", ["add", "package.json"], { cwd: root });
  await execFileAsync("git", ["-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "risky package"], { cwd: root });

  const { stdout } = await execFileAsync(process.execPath, [
    path.resolve("src", "cli.js"),
    "--json",
    "--changed",
    "--base",
    "HEAD~1",
    root
  ]);
  const report = JSON.parse(stdout);

  assert.equal(report.diff.mode, "changed");
  assert.equal(report.diff.base, "HEAD~1");
  assert.deepEqual(report.diff.changedFiles, ["package.json"]);
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-lifecycle-script"));
  assert.ok(!report.findings.some((finding) => finding.ruleId === "workflow-write-all"));
});

test("CLI fail threshold exits non-zero when severity matches", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      }
    })
  );

  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--json", "--fail-on", "high", root]),
    (error) => {
      const report = JSON.parse(error.stdout);
      assert.equal(report.summary.high, 1);
      assert.equal(error.code, 1);
      return true;
    }
  );
});

test("CLI fail threshold exits zero when severity does not match", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      dependencies: {
        express: "5.0.0"
      }
    })
  );

  const { stdout } = await execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--json", "--fail-on", "high", root]);
  const report = JSON.parse(stdout);

  assert.equal(report.summary.high, 0);
  assert.ok(report.summary.medium > 0);
});

test("CLI validates fail threshold severity", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [path.resolve("src", "cli.js"), "--json", "--fail-on", "critical", "."]),
    (error) => {
      assert.match(error.stderr, /--fail-on must be one of/);
      return true;
    }
  );
});

test("detects expanded Node package hygiene risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  const dependencies = Object.fromEntries(
    Array.from({ length: 61 }, (_, index) => [`package-${index}`, "1.0.0"])
  );
  dependencies.express = "^5.0.0";

  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      engines: {
        node: ">=16"
      },
      scripts: {
        fetch: "NODE_TLS_REJECT_UNAUTHORIZED=0 node scripts/fetch.js"
      },
      dependencies
    })
  );
  await writeFile(path.join(root, ".env"), "API_KEY=real-production-key\n");

  const report = await scanProject(root);

  assert.ok(report.findings.some((finding) => finding.ruleId === "script-disables-transport-security"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "missing-node-lockfile"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-dependency-bloat"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-unpinned-dependencies"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-old-engine-target"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "committed-env-secret"));
});

test("detects outdated npm lockfile formats", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      dependencies: {
        express: "5.0.0"
      }
    })
  );
  await writeFile(
    path.join(root, "package-lock.json"),
    JSON.stringify({
      name: "legacy-lockfile",
      lockfileVersion: 1
    })
  );

  const report = await scanProject(root);

  assert.ok(report.findings.some((finding) => finding.ruleId === "old-npm-lockfile-version"));
});

test("detects common GitHub Actions risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "ci.yml"),
    "name: ci\non: pull_request_target\npermissions: write-all\n"
  );

  const report = await scanProject(root);

  assert.ok(report.findings.some((finding) => finding.ruleId === "workflow-write-all"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "workflow-pull-request-target"));
});

test("detects nested Node and Spring projects", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "stacklens-"));
  const nodeDir = path.join(root, "apps", "web");
  const springDir = path.join(root, "services", "api");
  await mkdir(path.join(springDir, "src", "main", "resources"), { recursive: true });
  await mkdir(nodeDir, { recursive: true });

  await writeFile(
    path.join(nodeDir, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js"
      },
      dependencies: {
        react: "^19.0.0"
      }
    })
  );
  await writeFile(path.join(nodeDir, "yarn.lock"), "# demo");

  await writeFile(
    path.join(springDir, "pom.xml"),
    `<project>
      <parent>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.1</version>
      </parent>
      <properties><java.version>11</java.version></properties>
    </project>`
  );
  await writeFile(
    path.join(springDir, "src", "main", "resources", "application.yml"),
    "server.error.include-stacktrace=always\n"
  );

  const report = await scanProject(root);

  assert.ok(report.project.stacks.includes("Node.js"));
  assert.ok(report.project.stacks.includes("React"));
  assert.ok(report.project.stacks.includes("Spring Boot"));
  assert.equal(report.ecosystems.node.packageManager, "Yarn");
  assert.equal(report.ecosystems.spring.springBootVersion, "3.3.1");
  assert.ok(report.findings.some((finding) => finding.file === "apps/web/package.json" && finding.ruleId === "node-lifecycle-script"));
  assert.ok(report.findings.some((finding) => finding.file === "services/api/pom.xml" && finding.ruleId === "spring-older-java-target"));
});

test("dashboard asset resolver handles query strings and blocks traversal", () => {
  assert.equal(path.basename(resolveAssetPath("/")), "index.html");
  assert.equal(path.basename(resolveAssetPath("/app.js?v=1")), "app.js");
  assert.equal(resolveAssetPath("/../src/server.js"), null);
  assert.equal(resolveAssetPath("/%2e%2e/src/server.js"), null);
  assert.equal(resolveAssetPath("/%"), null);
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
