const lifecycleScripts = new Set(["preinstall", "install", "postinstall", "prepare", "prepublish"]);

export function scanNode(context) {
  const packageFile = context.fileMap.get("package.json");
  if (!packageFile) {
    return { detected: false, frameworks: [], findings: [] };
  }

  let parsed;
  try {
    parsed = JSON.parse(packageFile.content);
  } catch {
    return {
      detected: true,
      frameworks: [],
      findings: [
        context.finding({
          severity: "medium",
          file: "package.json",
          line: 1,
          category: "Node.js",
          ruleId: "invalid-package-json",
          title: "package.json could not be parsed",
          message: "Invalid package metadata can break installs, scripts, and CI detection.",
          snippet: "Invalid JSON"
        })
      ]
    };
  }

  const dependencies = {
    ...parsed.dependencies,
    ...parsed.devDependencies,
    ...parsed.optionalDependencies,
    ...parsed.peerDependencies
  };
  const frameworks = detectFrameworks(dependencies);
  const findings = [
    ...scanScripts(context, packageFile, parsed.scripts ?? {}),
    ...scanLockfiles(context),
    ...scanEnvExamples(context)
  ];

  return {
    detected: true,
    frameworks,
    packageManager: detectPackageManager(context),
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
        file: "package.json",
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
        file: "package.json",
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
        file: "package.json",
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

function scanLockfiles(context) {
  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"].filter((name) =>
    context.fileMap.has(name)
  );

  if (lockfiles.length <= 1) {
    return [];
  }

  return [
    context.finding({
      severity: "low",
      file: "package.json",
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

function detectPackageManager(context) {
  if (context.fileMap.has("pnpm-lock.yaml")) return "pnpm";
  if (context.fileMap.has("yarn.lock")) return "Yarn";
  if (context.fileMap.has("bun.lockb")) return "Bun";
  if (context.fileMap.has("package-lock.json")) return "npm";
  return "unknown";
}

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function redactEnvLine(line) {
  const [key] = line.split("=");
  return `${key}=********`;
}
