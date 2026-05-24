const publicEnvPrefixes = ["VITE_", "NUXT_PUBLIC_"];
const secretKeyPattern = /(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|ACCESS[_-]?KEY)/i;
const configFilePattern = /(^|\/)(vite|nuxt|vue)\.config\.[cm]?[jt]s$/i;

export function scanVue(context) {
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
    const packageFilesInScope = filesInPackage(context, packageDirectory);
    const sourceFiles = packageFilesInScope.filter((file) => /\.vue$/i.test(file.relativePath) || /\.[cm]?[jt]s$/i.test(file.relativePath));

    if (!isVueProject(dependencies, sourceFiles)) {
      continue;
    }

    projects.push(packageFile.relativePath);
    findings.push(
      ...scanFrontendEnv(context, packageDirectory),
      ...scanRuntimeConfig(context, packageDirectory),
      ...scanBuildConfig(context, packageDirectory, packageFile, parsed)
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

function isVueProject(dependencies, sourceFiles) {
  return Boolean(
    dependencies.vue ||
    dependencies.nuxt ||
    dependencies["@vitejs/plugin-vue"] ||
    sourceFiles.some((file) => /\.vue$/i.test(file.relativePath)) ||
    sourceFiles.some((file) => /\bfrom\s+["']vue["']|\brequire\(["']vue["']\)/.test(file.content))
  );
}

function scanFrontendEnv(context, packageDirectory) {
  const findings = [];
  const envFiles = filesInPackage(context, packageDirectory).filter((file) => /(^|\/)\.env(\.[\w.-]+)?$/i.test(file.relativePath));

  for (const file of envFiles) {
    for (const line of file.lines) {
      const match = line.text.trim().match(/^([A-Z0-9_]+)\s*=\s*([^#\s].*)$/i);
      if (!match) continue;

      const key = match[1];
      const value = match[2].trim();
      if (!publicEnvPrefixes.some((prefix) => key.startsWith(prefix))) continue;
      if (!secretKeyPattern.test(key) || isPlaceholder(value) || isEmptyValue(value)) continue;

      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Vue",
        ruleId: "vue-public-env-secret",
        title: "Vue public environment variable exposes a secret-like value",
        message: "Vite and Nuxt public env prefixes are bundled into client-side code and should not carry secrets.",
        snippet: `${key}=********`
      }));
    }
  }

  return findings;
}

function scanRuntimeConfig(context, packageDirectory) {
  const findings = [];
  const configFiles = filesInPackage(context, packageDirectory).filter((file) => configFilePattern.test(file.relativePath));

  for (const file of configFiles) {
    const publicRuntimeLines = findPublicRuntimeConfigLines(file);
    if (publicRuntimeLines.size === 0) continue;

    for (const [index, line] of file.lines.entries()) {
      if (!publicRuntimeLines.has(index)) continue;
      if (!secretKeyPattern.test(line.text) || !hasConcreteStringValue(line.text)) continue;

      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Vue",
        ruleId: "vue-public-runtime-secret",
        title: "Public runtime config contains a secret-like value",
        message: "Nuxt public runtime config is exposed to the browser and should not contain secrets.",
        snippet: redactRuntimeConfigLine(line.text.trim())
      }));
    }
  }

  return findings;
}

function scanBuildConfig(context, packageDirectory, packageFile, parsed) {
  const findings = [];
  const buildScript = parsed.scripts?.build;

  if (typeof buildScript === "string" && /(?:^|\s)(?:--mode(?:\s+|=)development|NODE_ENV\s*=\s*development)(?:\s|$)/i.test(buildScript)) {
    findings.push(context.finding({
      severity: "medium",
      file: packageFile.relativePath,
      line: findLine(packageFile.content, buildScript),
      category: "Vue",
      ruleId: "vue-build-uses-development-mode",
      title: "Vue production build appears to use development mode",
      message: "Production builds should not run with development mode flags or environment values.",
      snippet: buildScript
    }));
  }

  const configFiles = filesInPackage(context, packageDirectory).filter((file) => configFilePattern.test(file.relativePath));
  for (const file of configFiles) {
    for (const line of file.lines) {
      if (/\bsourcemap\s*:\s*true\b|build\s*:\s*\{[^}]*sourcemap\s*:\s*true/i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "Vue",
          ruleId: "vue-production-sourcemaps-enabled",
          title: "Vue production build appears to enable source maps",
          message: "Public production source maps can expose source structure and implementation details.",
          snippet: line.text.trim()
        }));
      }
    }
  }

  return findings;
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

function hasConcreteStringValue(line) {
  const match = line.match(/[:=]\s*["'`]([^"'`]+)["'`]/);
  return Boolean(match?.[1] && !isPlaceholder(match[1]));
}

function isPlaceholder(value) {
  const normalized = value.trim().replace(/^["'`](.*)["'`]$/, "$1");
  return /^\$\{[^}]+}$/.test(normalized) || /^(changeme|example|dummy|test|placeholder|your[-_]?value)$/i.test(normalized);
}

function isEmptyValue(value) {
  return value.trim().replace(/^["'`](.*)["'`]$/, "$1").length === 0;
}

function findPublicRuntimeConfigLines(file) {
  const lineIndexes = new Set();
  let braceDepth = 0;
  let runtimeDepth = null;
  let publicDepth = null;

  for (const [index, line] of file.lines.entries()) {
    const text = line.text;
    const startsRuntime = /\b(publicRuntimeConfig|runtimeConfig)\s*:/i.test(text);

    if (startsRuntime && runtimeDepth === null) {
      runtimeDepth = braceDepth;
    }

    if (runtimeDepth !== null && publicDepth === null && /\b(publicRuntimeConfig|public)\s*:/i.test(text)) {
      publicDepth = braceDepth;
    }

    if (publicDepth !== null || /\bpublicRuntimeConfig\s*:/i.test(text)) {
      lineIndexes.add(index);
    }

    braceDepth += countBraces(text);

    if (publicDepth !== null && braceDepth <= publicDepth) {
      publicDepth = null;
    }

    if (runtimeDepth !== null && braceDepth <= runtimeDepth) {
      runtimeDepth = null;
    }
  }

  return lineIndexes;
}

function countBraces(line) {
  const opened = line.match(/\{/g)?.length ?? 0;
  const closed = line.match(/}/g)?.length ?? 0;
  return opened - closed;
}

function redactRuntimeConfigLine(line) {
  return line.replace(/(["'`])([^"'`]+)\1/g, "$1********$1");
}

function basename(relativePath) {
  return relativePath.split(/[\\/]/).at(-1);
}

function dirname(relativePath) {
  const index = relativePath.lastIndexOf("/");
  return index === -1 ? "" : relativePath.slice(0, index);
}

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}
