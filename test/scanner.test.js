import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanProject } from "../src/scanner.js";
import { resolveAssetPath } from "../src/server.js";

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
  assert.equal(report.ecosystems.spring.springBootVersion, "3.3.1");
  assert.equal(report.ecosystems.spring.javaVersion, "11");
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-actuator-exposes-all"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-hardcoded-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "spring-devtools-not-development-only"));
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
  assert.equal(report.ecosystems.node.packageManager, "Yarn");
  assert.ok(report.findings.some((finding) => finding.ruleId === "node-lifecycle-script"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "remote-script-execution"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "env-example-secret"));
  assert.ok(report.findings.some((finding) => finding.ruleId === "multiple-node-lockfiles"));
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
