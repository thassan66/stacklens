import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { scanProject } from "../src/scanner.js";

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
