import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { detectStacks, getPackResult, listRulePackSummaries, runRulePacks } from "./rule-packs.js";

const ignoredDirectories = new Set([
  ".git",
  ".gradle",
  ".idea",
  ".mvn",
  ".next",
  ".nuxt",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target"
]);

const maxFileBytes = 512 * 1024;

export async function scanProject(projectPath) {
  const root = path.resolve(projectPath);
  const rootStat = await stat(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`Project path is not a directory: ${root}`);
  }

  const files = await collectReadableFiles(root);
  const context = createContext(root, files);
  const packResults = runRulePacks(context);
  const spring = getPackResult(packResults, "spring");
  const node = getPackResult(packResults, "node");
  const findings = sortFindings(packResults.flatMap(({ result }) => result.findings ?? []));
  const stacks = detectStacks(packResults);

  return {
    project: {
      root,
      name: path.basename(root),
      stacks,
      fileCount: files.length
    },
    rulePacks: listRulePackSummaries(packResults),
    ecosystems: {
      spring: omitFindings(spring),
      node: omitFindings(node)
    },
    findings,
    summary: summarize(findings)
  };
}

async function collectReadableFiles(root) {
  const files = [];

  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!ignoredDirectories.has(entry.name)) {
          await walk(entryPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      const relativePath = path.relative(root, entryPath);
      if (!isInterestingPath(relativePath)) continue;

      try {
        const fileStat = await stat(entryPath);
        if (fileStat.size > maxFileBytes) continue;
        const content = await readFile(entryPath, "utf8");
        files.push({
          absolutePath: entryPath,
          relativePath,
          content,
          lines: content.split(/\r?\n/).map((text, index) => ({ text, number: index + 1 }))
        });
      } catch {
        continue;
      }
    }
  }

  await walk(root);
  return files;
}

function createContext(root, files) {
  return {
    root,
    files,
    fileMap: new Map(files.map((file) => [file.relativePath, file])),
    finding
  };
}

function finding({ severity, file, line, category, ruleId, title, message, snippet }) {
  return {
    severity,
    file,
    line,
    category,
    ruleId,
    title,
    message,
    snippet: normalizeSnippet(snippet)
  };
}

function isInterestingPath(relativePath) {
  const basename = path.basename(relativePath);
  return (
    [
      "package.json",
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lockb",
      "pom.xml",
      "build.gradle",
      "build.gradle.kts",
      "Dockerfile",
      "docker-compose.yml",
      "docker-compose.yaml",
      "compose.yml",
      "compose.yaml",
      ".env",
      ".env.example",
      ".env.sample"
    ].includes(basename) ||
    /(^|\/)application([-.\w]*)\.(properties|ya?ml)$/i.test(relativePath) ||
    /^\.github\/workflows\/.+\.ya?ml$/i.test(relativePath)
  );
}

function omitFindings(result) {
  const { findings, ...rest } = result;
  return rest;
}

function sortFindings(findings) {
  const order = { high: 0, medium: 1, low: 2 };
  return findings.sort((a, b) => {
    return order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line;
  });
}

function summarize(findings) {
  return findings.reduce(
    (summary, item) => {
      summary[item.severity] += 1;
      summary.byCategory[item.category] = (summary.byCategory[item.category] ?? 0) + 1;
      return summary;
    },
    { high: 0, medium: 0, low: 0, byCategory: {} }
  );
}

function normalizeSnippet(snippet) {
  if (!snippet) return "";
  const value = String(snippet).trim();
  return value.length > 180 ? `${value.slice(0, 177)}...` : value;
}
