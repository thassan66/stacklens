const applicationConfigPattern = /(^|\/)application([-.\w]*)\.(properties|ya?ml)$/i;
const manifestPathPattern = /(^|\/)(src\/main\/kubernetes|k8s|kubernetes|openshift|deploy|deployments|manifests|argocd|\.argocd|helm|charts)\/.+\.(ya?ml|json)$/i;
const secretKeyPattern = /(password|passwd|secret|token|api[-_.]?key|private[-_.]?key|client[-_.]?secret|access[-_.]?key)/i;

export function scanQuarkus(context) {
  const builds = detectBuilds(context);
  const configFiles = context.files.filter((file) => applicationConfigPattern.test(file.relativePath));
  const configEntries = configFiles.flatMap((file) => parseApplicationConfig(file));
  const quarkusConfigFiles = configFiles.filter((file) => configEntries.some((entry) => entry.file === file.relativePath && entry.key.startsWith("quarkus.")));

  if (builds.length === 0 && quarkusConfigFiles.length === 0) {
    return { detected: false, findings: [] };
  }

  const extensions = uniqueValues(builds.flatMap((build) => build.extensions));
  const manifestFiles = context.files.filter(isManifestFile);
  const deploymentSignals = detectDeploymentSignals(manifestFiles);
  const usesCamel = extensions.some((extension) => extension.startsWith("camel-quarkus-")) ||
    configEntries.some((entry) => entry.key.startsWith("camel."));
  const usesArtemis = extensions.some((extension) => /artemis|pooled-jms|jms/i.test(extension)) ||
    configEntries.some((entry) => /artemis/i.test(entry.key));

  return {
    detected: true,
    buildTool: summarizeValues(builds.map((build) => build.tool)),
    buildTools: uniqueValues(builds.map((build) => build.tool)),
    quarkusVersion: summarizeValues(builds.map((build) => build.quarkusVersion)),
    quarkusVersions: uniqueValues(builds.map((build) => build.quarkusVersion)),
    javaVersion: summarizeValues(builds.map((build) => build.javaVersion)),
    javaVersions: uniqueValues(builds.map((build) => build.javaVersion)),
    projectCount: Math.max(builds.length, quarkusConfigFiles.length ? 1 : 0),
    extensions,
    usesCamel,
    usesArtemis,
    hasOpenShift: deploymentSignals.hasOpenShift,
    hasArgoCd: deploymentSignals.hasArgoCd,
    configFileCount: configFiles.length,
    manifestFileCount: manifestFiles.length,
    findings: [
      ...builds.flatMap((build) => scanBuild(context, build)),
      ...scanConfigs(context, configEntries),
      ...scanManifests(context, manifestFiles)
    ]
  };
}

function detectBuilds(context) {
  return [
    ...context.files.filter((file) => /(^|\/)pom\.xml$/i.test(file.relativePath)).flatMap(detectMavenBuild),
    ...context.files.filter((file) => /(^|\/)build\.gradle(\.kts)?$/i.test(file.relativePath)).flatMap(detectGradleBuild)
  ];
}

function detectMavenBuild(file) {
  const detected = /<groupId>\s*io\.quarkus\s*<\/groupId>|<artifactId>\s*quarkus-|quarkus-maven-plugin|quarkus-bom/i.test(file.content);
  if (!detected) return [];

  return [{
    tool: "Maven",
    file,
    quarkusVersion: firstMatch(file.content, [
      /<quarkus\.platform\.version>([^<]+)<\/quarkus\.platform\.version>/i,
      /<quarkus\.version>([^<]+)<\/quarkus\.version>/i,
      /<artifactId>\s*quarkus-bom\s*<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>/i
    ]),
    javaVersion: firstMatch(file.content, [
      /<maven\.compiler\.release>([^<]+)<\/maven\.compiler\.release>/i,
      /<maven\.compiler\.target>([^<]+)<\/maven\.compiler\.target>/i,
      /<java\.version>([^<]+)<\/java\.version>/i
    ]),
    extensions: collectMavenExtensions(file.content)
  }];
}

function detectGradleBuild(file) {
  const detected = /\bio\.quarkus\b|io\.quarkus:/i.test(file.content);
  if (!detected) return [];

  return [{
    tool: file.relativePath.endsWith(".kts") ? "Gradle Kotlin" : "Gradle",
    file,
    quarkusVersion: firstMatch(file.content, [
      /id\s*\(?\s*["']io\.quarkus["']\s*\)?\s*version\s*["']([^"']+)["']/i,
      /quarkusPluginVersion\s*=\s*["']([^"']+)["']/i,
      /quarkusPlatformVersion\s*=\s*["']([^"']+)["']/i
    ]),
    javaVersion: firstMatch(file.content, [
      /sourceCompatibility\s*=\s*["']?([^"'\n]+)["']?/i,
      /JavaVersion\.VERSION_(\d+)/i,
      /languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)/i
    ]),
    extensions: collectGradleExtensions(file.content)
  }];
}

function collectMavenExtensions(content) {
  return uniqueValues([...content.matchAll(/<artifactId>\s*((?:quarkus|camel-quarkus)-[^<]+)\s*<\/artifactId>/gi)]
    .map((match) => match[1].trim())
    .filter(isRuntimeExtension));
}

function collectGradleExtensions(content) {
  const dependencyExtensions = [...content.matchAll(/(?:io\.quarkus|org\.apache\.camel\.quarkus):([^:'"\s)]+)/gi)]
    .map((match) => match[1].trim())
    .filter(isRuntimeExtension);
  return uniqueValues(dependencyExtensions);
}

function isRuntimeExtension(name) {
  return !/^(quarkus-bom|quarkus-maven-plugin|quarkus-gradle-plugin)$/i.test(name);
}

function scanBuild(context, build) {
  const findings = [];

  if (build.javaVersion && /^1\.8$|^8$|^11$/.test(String(build.javaVersion).trim())) {
    findings.push(context.finding({
      severity: "medium",
      file: build.file.relativePath,
      line: findLine(build.file.content, String(build.javaVersion)),
      category: "Quarkus",
      ruleId: "quarkus-older-java-target",
      title: "Older Java target detected for Quarkus",
      message: "Older Java targets limit Quarkus upgrade options and may conflict with newer platform baselines.",
      snippet: String(build.javaVersion)
    }));
  }

  return findings;
}

function scanConfigs(context, entries) {
  const findings = [];

  for (const entry of entries) {
    const key = entry.key.toLowerCase();
    const value = String(entry.value ?? "");
    const isProd = isProdProfile(entry.profile);

    if (secretKeyPattern.test(key) && hasConcreteSecret(value)) {
      const isArtemis = /artemis|jms|amqp/.test(key);
      findings.push(context.finding({
        severity: "high",
        file: entry.file,
        line: entry.line,
        category: isArtemis ? "Artemis" : "Config",
        ruleId: isArtemis ? "artemis-hardcoded-credential" : "quarkus-hardcoded-secret",
        title: isArtemis ? "Artemis credential is hardcoded" : "Quarkus config contains a hardcoded secret-like value",
        message: "Move credentials to Kubernetes Secrets, sealed secrets, or deployment-time configuration.",
        snippet: `${entry.rawKey}=${redact(value)}`
      }));
    }

    if (/\.devservices\.enabled$/i.test(key) && isBooleanTrue(value) && isProd) {
      findings.push(context.finding({
        severity: "medium",
        file: entry.file,
        line: entry.line,
        category: "Quarkus",
        ruleId: "quarkus-dev-services-prod",
        title: "Quarkus Dev Services is enabled in a production profile",
        message: "Dev Services should stay local-only and should not be enabled in production profiles.",
        snippet: `${entry.rawKey}=${entry.value}`
      }));
    }

    if (key === "quarkus.http.insecure-requests" && /^(enabled|true)$/i.test(stripQuotes(value)) && isProd) {
      findings.push(context.finding({
        severity: "medium",
        file: entry.file,
        line: entry.line,
        category: "Quarkus",
        ruleId: "quarkus-insecure-http-prod",
        title: "Quarkus allows insecure HTTP requests in production",
        message: "Production deployments should redirect or disable insecure HTTP unless TLS is terminated and controlled upstream.",
        snippet: `${entry.rawKey}=${entry.value}`
      }));
    }

    if (key === "quarkus.swagger-ui.always-include" && isBooleanTrue(value) && isProd) {
      findings.push(context.finding({
        severity: "medium",
        file: entry.file,
        line: entry.line,
        category: "Quarkus",
        ruleId: "quarkus-swagger-ui-prod",
        title: "Swagger UI is always included in production",
        message: "Public API exploration surfaces should be intentionally protected or disabled in production.",
        snippet: `${entry.rawKey}=${entry.value}`
      }));
    }

    if (/^quarkus\.log(\.|$)/i.test(key) && /\.level$|^quarkus\.log\.level$/i.test(key) && /^(debug|trace)$/i.test(stripQuotes(value)) && isProd) {
      findings.push(context.finding({
        severity: "medium",
        file: entry.file,
        line: entry.line,
        category: "Quarkus",
        ruleId: "quarkus-debug-logging-prod",
        title: "Verbose Quarkus logging is enabled in production",
        message: "DEBUG or TRACE logging in production can expose sensitive data and increase log volume.",
        snippet: `${entry.rawKey}=${entry.value}`
      }));
    }

    if (key.startsWith("camel.") && /(tracing|message-history|source-location-enabled)$/i.test(key) && isBooleanTrue(value) && isProd) {
      findings.push(context.finding({
        severity: "medium",
        file: entry.file,
        line: entry.line,
        category: "Camel",
        ruleId: "camel-tracing-prod",
        title: "Camel diagnostic tracing is enabled in production",
        message: "Camel tracing and message history can expose headers, payload metadata, and route internals.",
        snippet: `${entry.rawKey}=${entry.value}`
      }));
    }

    if (key.startsWith("camel.") && /(uri|url|broker|endpoint)/i.test(key) && hasCredentialInUri(value)) {
      findings.push(context.finding({
        severity: "high",
        file: entry.file,
        line: entry.line,
        category: "Camel",
        ruleId: "camel-endpoint-credentials",
        title: "Camel endpoint URI includes credentials",
        message: "Credentials embedded in endpoint URIs can leak through config, logs, metrics, or deployment manifests.",
        snippet: `${entry.rawKey}=${redactUri(value)}`
      }));
    }

    if (/artemis/i.test(key) && /(url|broker-url|connection-url)$/i.test(key) && /^tcp:\/\//i.test(stripQuotes(value)) && isProd) {
      findings.push(context.finding({
        severity: "low",
        file: entry.file,
        line: entry.line,
        category: "Artemis",
        ruleId: "artemis-plain-tcp-url",
        title: "Artemis broker URL uses plain TCP in production",
        message: "Plain TCP broker connections should be reviewed when traffic can leave a trusted cluster network.",
        snippet: `${entry.rawKey}=${redactUri(value)}`
      }));
    }
  }

  return findings;
}

function scanManifests(context, manifestFiles) {
  return manifestFiles.flatMap((file) => [
    ...scanRoute(context, file),
    ...scanKubernetesSecret(context, file),
    ...scanContainerManifest(context, file),
    ...scanArgoApplication(context, file)
  ]);
}

function scanRoute(context, file) {
  if (!/kind:\s*Route\b|"kind"\s*:\s*"Route"/i.test(file.content)) return [];

  const findings = [];
  if (!/^\s*tls\s*:/mi.test(file.content)) {
    findings.push(context.finding({
      severity: "medium",
      file: file.relativePath,
      line: findLine(file.content, "kind: Route"),
      category: "OpenShift",
      ruleId: "openshift-route-without-tls",
      title: "OpenShift Route does not define TLS",
      message: "Routes exposed outside the cluster should declare TLS termination unless another controlled layer handles it.",
      snippet: "kind: Route"
    }));
  }

  for (const line of file.lines) {
    if (/insecureEdgeTerminationPolicy\s*:\s*Allow/i.test(line.text)) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "OpenShift",
        ruleId: "openshift-route-allows-insecure-edge",
        title: "OpenShift Route allows insecure edge traffic",
        message: "Allowing insecure traffic on TLS routes should be intentional and documented.",
        snippet: line.text.trim()
      }));
    }
  }

  return findings;
}

function scanKubernetesSecret(context, file) {
  if (!/kind:\s*Secret\b|"kind"\s*:\s*"Secret"/i.test(file.content)) return [];

  const findings = [];
  let dataIndent = null;

  for (const line of file.lines) {
    const dataMatch = line.text.match(/^(\s*)(data|stringData)\s*:\s*$/i);
    if (dataMatch) {
      dataIndent = dataMatch[1].length;
      continue;
    }

    if (dataIndent === null) continue;

    const indent = line.text.match(/^(\s*)/)?.[1].length ?? 0;
    if (line.text.trim() && indent <= dataIndent) {
      dataIndent = null;
      continue;
    }

    const entryMatch = line.text.match(/^\s*([A-Za-z0-9_.-]+)\s*:\s*(.+)$/);
    if (!entryMatch) continue;

    const value = stripQuotes(entryMatch[2]);
    if (!hasConcreteSecret(value)) continue;

    findings.push(context.finding({
      severity: "high",
      file: file.relativePath,
      line: line.number,
      category: "Kubernetes",
      ruleId: "kubernetes-committed-secret",
      title: "Kubernetes Secret contains committed data",
      message: "Secret manifests should be generated, sealed, or injected by deployment tooling instead of committed with values.",
      snippet: `${entryMatch[1]}: ********`
    }));
  }

  return findings;
}

function scanContainerManifest(context, file) {
  const findings = [];

  for (const line of file.lines) {
    const imageMatch = line.text.match(/\bimage\s*:\s*["']?([^"'\s#]+)["']?/i);
    if (imageMatch && isMutableImageRef(imageMatch[1])) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Kubernetes",
        ruleId: "kubernetes-mutable-image-tag",
        title: "Container image uses a mutable tag",
        message: "Use immutable tags or digests so Argo CD and OpenShift deploy the reviewed image.",
        snippet: line.text.trim()
      }));
    }

    if (/\b(privileged|allowPrivilegeEscalation)\s*:\s*true\b|\brunAsUser\s*:\s*0\b/i.test(line.text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Kubernetes",
        ruleId: "kubernetes-privileged-container",
        title: "Container security context is privileged",
        message: "Privileged containers and root users should be avoided unless the workload has a documented platform exception.",
        snippet: line.text.trim()
      }));
    }
  }

  findings.push(...scanEnvSecretValues(context, file));
  return findings;
}

function scanEnvSecretValues(context, file) {
  const findings = [];

  for (let index = 0; index < file.lines.length; index += 1) {
    const nameMatch = file.lines[index].text.match(/^\s*-\s*name\s*:\s*["']?([^"'\s#]+)["']?/i);
    if (!nameMatch || !secretKeyPattern.test(nameMatch[1])) continue;

    const lookahead = file.lines.slice(index + 1, index + 7);
    if (lookahead.some((line) => /\bvalueFrom\s*:/i.test(line.text))) continue;

    const valueLine = lookahead.find((line) => /\bvalue\s*:/i.test(line.text));
    if (!valueLine) continue;

    const value = stripQuotes(valueLine.text.replace(/^.*\bvalue\s*:\s*/i, "").trim());
    if (!hasConcreteSecret(value)) continue;

    findings.push(context.finding({
      severity: "high",
      file: file.relativePath,
      line: valueLine.number,
      category: "Kubernetes",
      ruleId: "kubernetes-env-secret",
      title: "Manifest env var contains a secret-like value",
      message: "Use valueFrom with Kubernetes Secrets or OpenShift secret references instead of plain env values.",
      snippet: `${nameMatch[1]}=********`
    }));
  }

  return findings;
}

function scanArgoApplication(context, file) {
  if (!/argoproj\.io\/v1alpha1/i.test(file.content) || !/kind:\s*Application\b/i.test(file.content)) return [];

  const findings = [];
  for (const line of file.lines) {
    const revisionMatch = line.text.match(/\btargetRevision\s*:\s*["']?(HEAD|main|master)["']?/i);
    if (revisionMatch) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Argo CD",
        ruleId: "argocd-mutable-target-revision",
        title: "Argo CD Application tracks a mutable target revision",
        message: "Pin release tags or immutable commit SHAs for production promotion paths.",
        snippet: line.text.trim()
      }));
    }

    if (/\bprune\s*:\s*true\b/i.test(line.text) && /automated\s*:/i.test(file.content)) {
      findings.push(context.finding({
        severity: "low",
        file: file.relativePath,
        line: line.number,
        category: "Argo CD",
        ruleId: "argocd-auto-prune-enabled",
        title: "Argo CD automated prune is enabled",
        message: "Automated prune is useful, but production apps should pair it with clear promotion and rollback controls.",
        snippet: line.text.trim()
      }));
    }
  }

  return findings;
}

function detectDeploymentSignals(files) {
  return {
    hasOpenShift: files.some((file) => /route\.openshift\.io|kind:\s*(Route|DeploymentConfig)\b|openshift/i.test(file.content)),
    hasArgoCd: files.some((file) => /argoproj\.io\/v1alpha1|kind:\s*Application\b/i.test(file.content))
  };
}

function parseApplicationConfig(file) {
  const defaultProfile = inferProfile(file.relativePath);
  const entries = file.relativePath.endsWith(".properties")
    ? parseProperties(file)
    : parseYamlLike(file);

  return entries.map((entry) => normalizeConfigEntry(file.relativePath, entry, defaultProfile));
}

function parseProperties(file) {
  return file.lines.flatMap((line) => {
    const trimmed = line.text.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("!")) return [];
    const separator = trimmed.search(/[=:]/);
    if (separator === -1) return [];
    return [{ key: trimmed.slice(0, separator).trim(), value: trimmed.slice(separator + 1).trim(), line: line.number }];
  });
}

function parseYamlLike(file) {
  const entries = [];
  const stack = [];

  for (const line of file.lines) {
    const text = line.text.replace(/\s+#.*$/, "");
    const match = text.match(/^(\s*)["']?([%A-Za-z0-9_.-]+)["']?\s*:\s*(.*)$/);
    if (!match) continue;
    const indent = match[1].length;
    const key = stripQuotes(match[2]);
    const value = stripQuotes(match[3].trim());
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const fullKey = [...stack.map((entry) => entry.key), key].join(".");
    if (value !== "") entries.push({ key: fullKey, value, line: line.number });
    stack.push({ indent, key });
  }

  return entries;
}

function normalizeConfigEntry(file, entry, defaultProfile) {
  const rawKey = stripQuotes(entry.key);
  const profileMatch = rawKey.match(/^%([^.]+)\.(.+)$/);
  const profile = profileMatch?.[1] ?? defaultProfile;
  const key = profileMatch?.[2] ?? rawKey;

  return {
    file,
    rawKey,
    key,
    value: entry.value,
    line: entry.line,
    profile
  };
}

function inferProfile(relativePath) {
  const match = relativePath.match(/application[-.]([^.]+)\.(properties|ya?ml)$/i);
  return match?.[1] ?? "default";
}

function isManifestFile(file) {
  return manifestPathPattern.test(file.relativePath);
}

function isProdProfile(profile) {
  return /^(prod|production)$/i.test(profile);
}

function isBooleanTrue(value) {
  return /^true$/i.test(stripQuotes(value));
}

function hasConcreteSecret(value) {
  const trimmed = stripQuotes(value);
  return Boolean(
    trimmed &&
    !/^\$\{[^}]+}$/.test(trimmed) &&
    !/^\{\{[^}]+}}$/.test(trimmed) &&
    !/^<[^>]+>$/.test(trimmed) &&
    !/^(changeme|example|dummy|test|password|secret|token|placeholder|your[-_]?value)$/i.test(trimmed)
  );
}

function hasCredentialInUri(value) {
  const text = stripQuotes(value);
  return /:\/\/[^:@/\s]+:[^@/\s]+@/.test(text) || /[?&](password|passwd|token|secret|api[-_]?key)=([^&\s]+)/i.test(text);
}

function isMutableImageRef(image) {
  if (image.includes("@sha256:")) return false;
  const imageName = image.split("/").at(-1) ?? image;
  if (!imageName.includes(":")) return true;
  return imageName.toLowerCase().endsWith(":latest");
}

function summarizeValues(values) {
  const unique = uniqueValues(values);
  if (unique.length === 0) return null;
  if (unique.length === 1) return unique[0];
  return "multiple";
}

function uniqueValues(values) {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

function firstMatch(content, patterns) {
  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match?.[1]) return match[1].trim();
  }
  return null;
}

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function stripQuotes(value) {
  return String(value ?? "").trim().replace(/^["'](.*)["']$/, "$1");
}

function redact(value) {
  const text = stripQuotes(value);
  if (text.length <= 4) return "****";
  return `${text.slice(0, 2)}${"*".repeat(Math.min(8, text.length - 2))}`;
}

function redactUri(value) {
  return stripQuotes(value)
    .replace(/:\/\/([^:@/\s]+):([^@/\s]+)@/g, "://$1:********@")
    .replace(/([?&](password|passwd|token|secret|api[-_]?key)=)[^&\s]+/gi, "$1********");
}
