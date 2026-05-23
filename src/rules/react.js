const publicEnvPrefixes = ["REACT_APP_", "VITE_", "NEXT_PUBLIC_"];
const secretKeyPattern = /(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)/i;

export function scanReact(context) {
  const packageFiles = context.files.filter((file) => basename(file.relativePath) === "package.json");
  const projects = [];
  const findings = [];

  for (const packageFile of packageFiles) {
    const parsed = parsePackage(packageFile);
    if (!parsed) continue;

    const dependencies = {
      ...parsed.dependencies,
      ...parsed.devDependencies,
      ...parsed.optionalDependencies,
      ...parsed.peerDependencies
    };
    const packageDirectory = dirname(packageFile.relativePath);
    const sourceFiles = filesInPackage(context, packageDirectory).filter((file) => /\.[cm]?[jt]sx?$/i.test(file.relativePath));

    if (!dependencies.react && !sourceFiles.some((file) => /\bfrom\s+["']react["']|\brequire\(["']react["']\)/.test(file.content))) {
      continue;
    }

    projects.push(packageFile.relativePath);
    findings.push(
      ...scanFrontendEnv(context, packageDirectory),
      ...scanBuildConfig(context, packageDirectory, packageFile, parsed),
      ...scanCsp(context, packageDirectory),
      ...scanErrorBoundary(context, packageDirectory, dependencies, sourceFiles)
    );
  }

  if (projects.length === 0) {
    return { detected: false, findings: [] };
  }

  return {
    detected: true,
    projectCount: projects.length,
    findings
  };
}

function scanFrontendEnv(context, packageDirectory) {
  const findings = [];
  const envFiles = filesInPackage(context, packageDirectory).filter((file) => /(^|\/)\.env(\.example|\.sample)?$/i.test(file.relativePath));

  for (const file of envFiles) {
    for (const line of file.lines) {
      const match = line.text.trim().match(/^([A-Z0-9_]+)\s*=\s*([^#\s].*)$/i);
      if (!match) continue;

      const key = match[1];
      const value = match[2].trim();
      if (!publicEnvPrefixes.some((prefix) => key.startsWith(prefix))) continue;
      if (!secretKeyPattern.test(key) || isPlaceholder(value)) continue;

      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "React",
        ruleId: "react-public-env-secret",
        title: "Frontend environment variable exposes a secret-like value",
        message: "React public env prefixes are bundled into client-side code and should not carry secrets.",
        snippet: `${key}=********`
      }));
    }
  }

  return findings;
}

function scanBuildConfig(context, packageDirectory, packageFile, parsed) {
  const findings = [];
  const buildScript = parsed.scripts?.build;

  if (typeof buildScript === "string" && /GENERATE_SOURCEMAP\s*=\s*true|SOURCEMAP\s*=\s*true/i.test(buildScript)) {
    findings.push(context.finding({
      severity: "medium",
      file: packageFile.relativePath,
      line: findLine(packageFile.content, buildScript),
      category: "React",
      ruleId: "react-production-sourcemaps-enabled",
      title: "Production build appears to enable source maps",
      message: "Public production source maps can expose source structure and implementation details.",
      snippet: buildScript
    }));
  }

  const configFiles = filesInPackage(context, packageDirectory).filter((file) => /(^|\/)vite\.config\.[cm]?[jt]s$/i.test(file.relativePath));
  for (const file of configFiles) {
    for (const line of file.lines) {
      if (/\bsourcemap\s*:\s*true\b/i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "React",
          ruleId: "react-production-sourcemaps-enabled",
          title: "Production build appears to enable source maps",
          message: "Public production source maps can expose source structure and implementation details.",
          snippet: line.text.trim()
        }));
      }
    }
  }

  return findings;
}

function scanCsp(context, packageDirectory) {
  const findings = [];
  const htmlFiles = filesInPackage(context, packageDirectory).filter((file) => /(^|\/)index\.html$/i.test(file.relativePath));

  for (const file of htmlFiles) {
    for (const line of file.lines) {
      if (/content-security-policy/i.test(line.text) && /'unsafe-inline'|'unsafe-eval'|\*/i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "React",
          ruleId: "react-unsafe-csp",
          title: "Content Security Policy allows unsafe sources",
          message: "Unsafe CSP sources reduce browser protections against injected scripts.",
          snippet: line.text.trim()
        }));
      }
    }
  }

  return findings;
}

function scanErrorBoundary(context, packageDirectory, dependencies, sourceFiles) {
  if (dependencies["react-error-boundary"] || sourceFiles.length === 0) {
    return [];
  }

  const hasComponentSource = sourceFiles.some((file) => /<[A-Z][A-Za-z0-9]*\b|function\s+[A-Z][A-Za-z0-9]*\s*\(/.test(file.content));
  if (!hasComponentSource) {
    return [];
  }

  const hasBoundary = sourceFiles.some((file) =>
    /componentDidCatch|getDerivedStateFromError|ErrorBoundary|react-error-boundary/.test(file.content)
  );
  if (hasBoundary) {
    return [];
  }

  const file = sourceFiles[0];
  return [
    context.finding({
      severity: "low",
      file: file.relativePath,
      line: 1,
      category: "React",
      ruleId: "react-missing-error-boundary",
      title: "No React error boundary signal found",
      message: "Apps with route or page-level React components should define an error boundary strategy.",
      snippet: relativePackagePath(packageDirectory) || "React source files"
    })
  ];
}

function filesInPackage(context, packageDirectory) {
  return context.files.filter((file) => {
    if (!packageDirectory) return !file.relativePath.includes("/") || file.relativePath.startsWith("src/");
    return file.relativePath === packageDirectory || file.relativePath.startsWith(`${packageDirectory}/`);
  });
}

function parsePackage(packageFile) {
  try {
    return JSON.parse(packageFile.content);
  } catch {
    return null;
  }
}

function isPlaceholder(value) {
  return /^\$\{[^}]+}$/.test(value) || /^(changeme|example|dummy|test|placeholder|your[-_]?value)$/i.test(value);
}

function basename(relativePath) {
  return relativePath.split(/[\\/]/).at(-1);
}

function dirname(relativePath) {
  const index = relativePath.lastIndexOf("/");
  return index === -1 ? "" : relativePath.slice(0, index);
}

function relativePackagePath(packageDirectory) {
  return packageDirectory ? `${packageDirectory}/src` : "src";
}

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}
