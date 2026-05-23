const lifecycleScripts = new Set(["preinstall", "install", "postinstall", "prepare", "prepublish"]);
const dependencySections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const dependencyBloatThreshold = 60;

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
      ...scanLockfiles(context, packageFile, parsed),
      ...scanDependencies(context, packageFile, parsed),
      ...scanEngines(context, packageFile, parsed.engines ?? {})
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

    if (/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|strict-ssl\s+false|--no-check-certificate|--insecure\b/i.test(command)) {
      findings.push(context.finding({
        severity: "high",
        file: packageFile.relativePath,
        line: findLine(packageFile.content, command),
        category: "Node.js",
        ruleId: "script-disables-transport-security",
        title: "Script disables transport security checks",
        message: "Install or build scripts should not bypass TLS certificate verification.",
        snippet: command
      }));
    }
  }

  return findings;
}

function scanLockfiles(context, packageFile, parsed) {
  const packageDirectory = dirname(packageFile.relativePath);
  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"].filter((name) =>
    context.fileMap.has(joinRelative(packageDirectory, name))
  );

  const findings = [];

  if (hasDependencies(parsed) && lockfiles.length === 0) {
    findings.push(context.finding({
      severity: "medium",
      file: packageFile.relativePath,
      line: 1,
      category: "Node.js",
      ruleId: "missing-node-lockfile",
      title: "Package has dependencies but no lockfile",
      message: "Committed lockfiles keep local installs and CI on the same dependency tree.",
      snippet: "No package manager lockfile found"
    }));
  }

  if (lockfiles.length > 1) {
    findings.push(context.finding({
      severity: "low",
      file: packageFile.relativePath,
      line: 1,
      category: "Node.js",
      ruleId: "multiple-node-lockfiles",
      title: "Multiple package manager lockfiles found",
      message: "Mixed lockfiles can cause different dependency trees locally and in CI.",
      snippet: lockfiles.join(", ")
    }));
  }

  findings.push(...scanPackageLockVersion(context, packageDirectory));

  return findings;
}

function scanPackageLockVersion(context, packageDirectory) {
  const lockfilePath = joinRelative(packageDirectory, "package-lock.json");
  const lockfile = context.fileMap.get(lockfilePath);
  if (!lockfile) {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(lockfile.content);
  } catch {
    return [
      context.finding({
        severity: "medium",
        file: lockfile.relativePath,
        line: 1,
        category: "Node.js",
        ruleId: "invalid-package-lock",
        title: "package-lock.json could not be parsed",
        message: "Invalid lockfiles can break reproducible installs in local and CI environments.",
        snippet: "Invalid JSON"
      })
    ];
  }

  if (Number(parsed.lockfileVersion) >= 2) {
    return [];
  }

  return [
    context.finding({
      severity: "low",
      file: lockfile.relativePath,
      line: findLine(lockfile.content, "\"lockfileVersion\""),
      category: "Node.js",
      ruleId: "old-npm-lockfile-version",
      title: "Older npm lockfile format",
      message: "Older npm lockfile formats can lose metadata used by modern npm installs.",
      snippet: `lockfileVersion ${parsed.lockfileVersion ?? "missing"}`
    })
  ];
}

function scanDependencies(context, packageFile, parsed) {
  const findings = [];
  const dependencies = dependencySections.flatMap((section) =>
    Object.entries(parsed[section] ?? {}).map(([name, version]) => ({ section, name, version }))
  );
  const runtimeDependencyCount = Object.keys(parsed.dependencies ?? {}).length;

  if (runtimeDependencyCount >= dependencyBloatThreshold) {
    findings.push(context.finding({
      severity: "medium",
      file: packageFile.relativePath,
      line: findLine(packageFile.content, "\"dependencies\""),
      category: "Node.js",
      ruleId: "node-dependency-bloat",
      title: "Large runtime dependency surface",
      message: "A large dependency set increases install time, review burden, and supply-chain exposure.",
      snippet: `${runtimeDependencyCount} runtime dependencies`
    }));
  }

  const unpinned = dependencies.filter((dependency) => isUnpinnedVersion(dependency.version));
  if (unpinned.length > 0) {
    findings.push(context.finding({
      severity: "low",
      file: packageFile.relativePath,
      line: findLine(packageFile.content, `"${unpinned[0].name}"`),
      category: "Node.js",
      ruleId: "node-unpinned-dependencies",
      title: "Dependencies use floating version ranges",
      message: "Floating dependency ranges can produce different installs over time, especially without strict lockfile discipline.",
      snippet: unpinned.slice(0, 5).map((dependency) => `${dependency.name}@${dependency.version}`).join(", ")
    }));
  }

  return findings;
}

function scanEngines(context, packageFile, engines) {
  if (typeof engines.node !== "string") {
    return [];
  }

  const minimumMajor = parseMinimumNodeMajor(engines.node);
  if (!minimumMajor || minimumMajor >= 20) {
    return [];
  }

  return [
    context.finding({
      severity: "medium",
      file: packageFile.relativePath,
      line: findLine(packageFile.content, "\"node\""),
      category: "Node.js",
      ruleId: "node-old-engine-target",
      title: "Older Node.js engine target",
      message: "Older Node.js targets can limit dependency upgrades and security support windows.",
      snippet: `node ${engines.node}`
    })
  ];
}

function scanEnvExamples(context) {
  const findings = [];
  const envFiles = context.files.filter((file) => /(^|\/)\.env(\.example|\.sample)?$/i.test(file.relativePath));

  for (const file of envFiles) {
    for (const line of file.lines) {
      if (/(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)=([^$\s#][^\s#]+)/i.test(line.text)) {
        const isTemplate = /\.env\.(example|sample)$/i.test(file.relativePath);
        findings.push(context.finding({
          severity: isTemplate ? "medium" : "high",
          file: file.relativePath,
          line: line.number,
          category: "Node.js",
          ruleId: isTemplate ? "env-example-secret" : "committed-env-secret",
          title: isTemplate
            ? "Environment file contains a concrete secret-like value"
            : "Committed .env file contains a concrete secret-like value",
          message: isTemplate
            ? "Use placeholders in committed env templates and keep real values out of source control."
            : "Real .env files should not be committed with concrete secrets.",
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

function hasDependencies(parsed) {
  return dependencySections.some((section) => Object.keys(parsed[section] ?? {}).length > 0);
}

function isUnpinnedVersion(version) {
  if (typeof version !== "string") return false;
  const value = version.trim();
  if (!value || /^(file:|link:|workspace:|\$)/i.test(value)) return false;
  return (
    value === "*" ||
    /\bx\b/i.test(value) ||
    /\blatest\b/i.test(value) ||
    /^[~^><=]/.test(value) ||
    /\s+-\s+|\s+\|\|\s+/.test(value)
  );
}

function parseMinimumNodeMajor(range) {
  const match = String(range).match(/(\d+)(?:\.\d+)?(?:\.\d+)?/);
  return match ? Number(match[1]) : null;
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
