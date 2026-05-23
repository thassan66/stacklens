#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const workspace = process.env.GITHUB_WORKSPACE || process.cwd();

const scanPath = input("path") || ".";
const outputFormat = input("output-format") || "sarif";
const outputFile = input("output-file") || defaultOutputFile(outputFormat);
const failOn = input("fail-on");

if (!["json", "sarif"].includes(outputFormat)) {
  fail(`output-format must be one of: json, sarif`);
}

if (failOn && !["high", "medium", "low"].includes(failOn)) {
  fail(`fail-on must be one of: high, medium, low`);
}

const reportPath = resolveWorkspacePath(outputFile);
const args = [path.join(repoRoot, "src", "cli.js"), outputFormat === "sarif" ? "--sarif" : "--json"];
if (failOn) {
  args.push("--fail-on", failOn);
}
args.push(resolveWorkspacePath(scanPath));

const result = spawnSync(process.execPath, args, {
  cwd: workspace,
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024
});

if (result.stdout) {
  mkdirSync(path.dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, result.stdout);
  writeOutput("report-path", reportPath);
}

if (result.stderr) {
  process.stderr.write(result.stderr);
}

process.exitCode = result.status ?? 1;

function input(name) {
  return process.env[`INPUT_${name.toUpperCase().replaceAll("-", "_")}`]?.trim() ?? "";
}

function defaultOutputFile(format) {
  return format === "sarif" ? "stacklens.sarif" : "stacklens.json";
}

function resolveWorkspacePath(value) {
  return path.isAbsolute(value) ? value : path.resolve(workspace, value);
}

function writeOutput(name, value) {
  const line = `${name}=${value}\n`;
  if (process.env.GITHUB_OUTPUT) {
    writeFileSync(process.env.GITHUB_OUTPUT, line, { flag: "a" });
  } else {
    process.stdout.write(line);
  }
}

function fail(message) {
  process.stderr.write(`stacklens-action: ${message}\n`);
  process.exit(1);
}
