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
      ["@stacklens/node", "node"],
      ["@stacklens/react", "react"]
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
