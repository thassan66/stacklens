const lifecycleScripts = new Set(["preinstall", "install", "postinstall", "prepare", "prepublish"]);

export function scanNode(context) {
  const packageFiles = context.files.filter((file) => basename(file.relativePath) === "package.json");
  if (packageFiles.length === 0) {
    return { detected: false, frameworks: [], findings: [] };
  }

  const frameworks = new Set();
  const packageManagers = new Set();
  const findings = [];

  for (const packageFile of packageFiles) {
    let parsed;
    try {
      parsed = JSON.parse(packageFile.content);
    } catch {
      findings.push(
        context.finding({
          severity: "medium",
          file: packageFile.relativePath,
          line: 1,
          category: "Node.js",
          ruleId: "invalid-package-json",
          title: "package.json could not be parsed",
          message: "Invalid package metadata can break installs, scripts, and CI detection.",
          snippet: "Invalid JSON"
        })
      );
      continue;
    }

    const dependencies = {
      ...parsed.dependencies,
      ...parsed.devDependencies,
      ...parsed.optionalDependencies,
      ...parsed.peerDependencies
    };

    for (const framework of detectFrameworks(dependencies)) {
      frameworks.add(framework);
    }

    const packageManager = detectPackageManager(context, dirname(packageFile.relativePath));
    if (packageManager !== "unknown") {
      packageManagers.add(packageManager);
    }

    findings.push(
      ...scanScripts(context, packageFile, parsed.scripts ?? {}),
      ...scanLockfiles(context, packageFile)
    );
  }

  findings.push(...scanEnvExamples(context));

  return {
    detected: true,
    frameworks: Array.from(frameworks).sort(),
    packageManager: summarizePackageManagers(packageManagers),
    packageManagers: Array.from(packageManagers).sort(),
    packageCount: packageFiles.length,
    findings
  };
}

function scanScripts(context, packageFile, scripts) {
  const findings = [];

  for (const [name, command] of Object.entries(scripts)) {
    if (typeof command !== "string") {
      continue;
    }

    if (lifecycleScripts.has(name)) {
      findings.push(context.finding({
        severity: "high",
        file: packageFile.relativePath,
        line: findLine(packageFile.content, `"${name}"`),
        category: "Node.js",
        ruleId: "node-lifecycle-script",
        title: `${name} runs automatically`,
        message: "Lifecycle scripts execute during install or publish flows and should be reviewed carefully.",
        snippet: command
      }));
    }

    if (/\b(curl|wget)\b[^|;&\n]*\|\s*(bash|sh|zsh|node|python)\b/i.test(command)) {
      findings.push(context.finding({
        severity: "high",
        file: packageFile.relativePath,
        line: findLine(packageFile.content, command),
        category: "Node.js",
        ruleId: "remote-script-execution",
        title: "Script downloads and executes remote code",
        message: "Piping network content into an interpreter is risky for local developers and CI.",
        snippet: command
      }));
    }

    if (/(~\/\.ssh|\.npmrc|NPM_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)/i.test(command)) {
      findings.push(context.finding({
        severity: "high",
        file: packageFile.relativePath,
        line: findLine(packageFile.content, command),
        category: "Node.js",
        ruleId: "script-references-credentials",
        title: "Script references local credentials or tokens",
        message: "Scripts that touch credentials should be isolated and documented.",
        snippet: command
      }));
    }
  }

  return findings;
}

function scanLockfiles(context, packageFile) {
  const packageDirectory = dirname(packageFile.relativePath);
  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"].filter((name) =>
    context.fileMap.has(joinRelative(packageDirectory, name))
  );

  if (lockfiles.length <= 1) {
    return [];
  }

  return [
    context.finding({
      severity: "low",
      file: packageFile.relativePath,
      line: 1,
      category: "Node.js",
      ruleId: "multiple-node-lockfiles",
      title: "Multiple package manager lockfiles found",
      message: "Mixed lockfiles can cause different dependency trees locally and in CI.",
      snippet: lockfiles.join(", ")
    })
  ];
}

function scanEnvExamples(context) {
  const findings = [];
  const envFiles = context.files.filter((file) => /(^|\/)\.env(\.example|\.sample)?$/i.test(file.relativePath));

  for (const file of envFiles) {
    for (const line of file.lines) {
      if (/(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)=([^$\s#][^\s#]+)/i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "Node.js",
          ruleId: "env-example-secret",
          title: "Environment file contains a concrete secret-like value",
          message: "Use placeholders in committed env templates and keep real values out of source control.",
          snippet: redactEnvLine(line.text.trim())
        }));
      }
    }
  }

  return findings;
}

function detectFrameworks(dependencies) {
  const frameworks = [];
  if (dependencies.next) frameworks.push("Next.js");
  if (dependencies.react) frameworks.push("React");
  if (dependencies.vue) frameworks.push("Vue");
  if (dependencies["@angular/core"]) frameworks.push("Angular");
  if (dependencies.vite) frameworks.push("Vite");
  if (dependencies.express) frameworks.push("Express");
  if (dependencies.fastify) frameworks.push("Fastify");
  return frameworks;
}

function detectPackageManager(context, packageDirectory) {
  if (context.fileMap.has(joinRelative(packageDirectory, "pnpm-lock.yaml"))) return "pnpm";
  if (context.fileMap.has(joinRelative(packageDirectory, "yarn.lock"))) return "Yarn";
  if (context.fileMap.has(joinRelative(packageDirectory, "bun.lockb"))) return "Bun";
  if (context.fileMap.has(joinRelative(packageDirectory, "package-lock.json"))) return "npm";
  return "unknown";
}

function summarizePackageManagers(packageManagers) {
  if (packageManagers.size === 0) return "unknown";
  if (packageManagers.size === 1) return Array.from(packageManagers)[0];
  return "multiple";
}

function basename(relativePath) {
  return relativePath.split(/[\\/]/).at(-1);
}

function dirname(relativePath) {
  const index = relativePath.lastIndexOf("/");
  return index === -1 ? "" : relativePath.slice(0, index);
}

function joinRelative(directory, name) {
  return directory ? `${directory}/${name}` : name;
}

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function redactEnvLine(line) {
  const [key] = line.split("=");
  return `${key}=********`;
}
