export function scanSpring(context) {
  const builds = detectBuilds(context);
  const configFiles = context.files.filter((file) => /(^|\/)application([-.\w]*)\.(properties|ya?ml)$/i.test(file.relativePath));

  if (!builds.some((build) => build.detected) && configFiles.length === 0) {
    return { detected: false, findings: [] };
  }

  const detectedBuilds = builds.filter((build) => build.detected);

  return {
    detected: true,
    buildTool: summarizeValues(detectedBuilds.map((build) => build.tool)),
    buildTools: uniqueValues(detectedBuilds.map((build) => build.tool)),
    springBootVersion: summarizeValues(detectedBuilds.map((build) => build.springBootVersion)),
    springBootVersions: uniqueValues(detectedBuilds.map((build) => build.springBootVersion)),
    javaVersion: summarizeValues(detectedBuilds.map((build) => build.javaVersion)),
    javaVersions: uniqueValues(detectedBuilds.map((build) => build.javaVersion)),
    projectCount: detectedBuilds.length,
    profiles: Array.from(new Set(configFiles.map((file) => inferProfile(file.relativePath)))).sort(),
    configFileCount: configFiles.length,
    findings: [
      ...detectedBuilds.flatMap((build) => scanBuild(context, build)),
      ...scanConfigs(context, configFiles)
    ]
  };
}

function detectBuilds(context) {
  const builds = [];

  for (const pom of context.files.filter((file) => /(^|\/)pom\.xml$/i.test(file.relativePath))) {
    const detected = /spring-boot/i.test(pom.content);
    if (!detected) continue;

    builds.push({
      detected,
      tool: "Maven",
      file: pom,
      springBootVersion: firstMatch(pom.content, [
        /<spring-boot\.version>([^<]+)<\/spring-boot\.version>/i,
        /<artifactId>spring-boot-starter-parent<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>/i
      ]),
      javaVersion: firstMatch(pom.content, [
        /<java\.version>([^<]+)<\/java\.version>/i,
        /<maven\.compiler\.release>([^<]+)<\/maven\.compiler\.release>/i,
        /<maven\.compiler\.target>([^<]+)<\/maven\.compiler\.target>/i
      ])
    });
  }

  for (const gradle of context.files.filter((file) => /(^|\/)build\.gradle(\.kts)?$/i.test(file.relativePath))) {
    const detected = /org\.springframework\.boot/i.test(gradle.content);
    if (!detected) continue;

    builds.push({
      detected,
      tool: gradle.relativePath.endsWith(".kts") ? "Gradle Kotlin" : "Gradle",
      file: gradle,
      springBootVersion: firstMatch(gradle.content, [
        /id\s+['"]org\.springframework\.boot['"]\s+version\s+['"]([^'"]+)['"]/i
      ]),
      javaVersion: firstMatch(gradle.content, [
        /sourceCompatibility\s*=\s*['"]?([^'"\n]+)['"]?/i,
        /JavaVersion\.VERSION_(\d+)/i,
        /languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)/i
      ])
    });
  }

  return builds;
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

function scanBuild(context, build) {
  const findings = [];
  if (!build.file) return findings;

  if (build.javaVersion && /^1\.8$|^8$|^11$/.test(String(build.javaVersion).trim())) {
    findings.push(context.finding({
      severity: "medium",
      file: build.file.relativePath,
      line: findLine(build.file.content, String(build.javaVersion)),
      category: "Spring",
      ruleId: "spring-older-java-target",
      title: "Older Java target detected",
      message: "Java 8 or 11 can limit modern Spring Boot upgrade paths and support windows.",
      snippet: String(build.javaVersion)
    }));
  }

  if (/spring-boot-devtools/i.test(build.file.content) && !/optional>\s*true\s*<\/optional>|developmentOnly/i.test(build.file.content)) {
    findings.push(context.finding({
      severity: "medium",
      file: build.file.relativePath,
      line: findLine(build.file.content, "spring-boot-devtools"),
      category: "Spring",
      ruleId: "spring-devtools-not-development-only",
      title: "spring-boot-devtools may not be development-only",
      message: "DevTools should be optional or development-only so it is not packaged unexpectedly.",
      snippet: lineAt(build.file.content, findLine(build.file.content, "spring-boot-devtools"))
    }));
  }

  return findings;
}

function scanConfigs(context, configFiles) {
  const findings = [];

  for (const file of configFiles) {
    const entries = file.relativePath.endsWith(".properties")
      ? parseProperties(file)
      : parseYamlLike(file);
    const profile = inferProfile(file.relativePath);
    const isProd = /(^|[-.])prod(uction)?($|[-.])/i.test(profile);

    for (const entry of entries) {
      const key = entry.key.toLowerCase();
      const value = String(entry.value ?? "");

      if (key === "management.endpoints.web.exposure.include") {
        const exposed = value.split(",").map((item) => item.trim().toLowerCase());
        if (exposed.includes("*")) {
          findings.push(context.finding({
            severity: "high",
            file: file.relativePath,
            line: entry.line,
            category: "Actuator",
            ruleId: "spring-actuator-exposes-all",
            title: "All Actuator endpoints are exposed",
            message: "Exposing every Actuator endpoint can reveal sensitive operational data.",
            snippet: `${entry.key}=${entry.value}`
          }));
        }

        for (const endpoint of ["env", "heapdump", "beans", "logfile", "shutdown"]) {
          if (exposed.includes(endpoint)) {
            findings.push(context.finding({
              severity: endpoint === "shutdown" ? "high" : "medium",
              file: file.relativePath,
              line: entry.line,
              category: "Actuator",
              ruleId: `spring-actuator-exposes-${endpoint}`,
              title: `Actuator exposes ${endpoint}`,
              message: `${endpoint} should be reviewed carefully before exposure outside local development.`,
              snippet: `${entry.key}=${entry.value}`
            }));
          }
        }
      }

      if (key === "management.endpoint.shutdown.enabled" && value.toLowerCase() === "true") {
        findings.push(context.finding({
          severity: "high",
          file: file.relativePath,
          line: entry.line,
          category: "Actuator",
          ruleId: "spring-actuator-shutdown-enabled",
          title: "Actuator shutdown endpoint is enabled",
          message: "The shutdown endpoint can stop the application and should be disabled unless tightly controlled.",
          snippet: `${entry.key}=${entry.value}`
        }));
      }

      if (/(password|secret|token|api[-_.]?key|private[-_.]?key|client[-_.]?secret)/i.test(key) && hasConcreteSecret(value)) {
        findings.push(context.finding({
          severity: "high",
          file: file.relativePath,
          line: entry.line,
          category: "Config",
          ruleId: "spring-hardcoded-secret",
          title: "Hardcoded secret-like value",
          message: "Move secrets to environment variables, a secret manager, or deployment-time configuration.",
          snippet: `${entry.key}=${redact(value)}`
        }));
      }

      if (key === "server.error.include-stacktrace" && value.toLowerCase() === "always") {
        findings.push(context.finding({
          severity: isProd ? "high" : "medium",
          file: file.relativePath,
          line: entry.line,
          category: "Config",
          ruleId: "spring-stacktrace-always",
          title: "Stack traces are always included in error responses",
          message: "Always returning stack traces can disclose internals to callers.",
          snippet: `${entry.key}=${entry.value}`
        }));
      }

      if (isProd && key.startsWith("logging.level.") && value.toUpperCase() === "DEBUG") {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: entry.line,
          category: "Spring",
          ruleId: "spring-debug-logging-prod",
          title: "DEBUG logging is enabled in a production profile",
          message: "Debug logs can expose sensitive data and increase noise or cost.",
          snippet: `${entry.key}=${entry.value}`
        }));
      }
    }
  }

  return findings;
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
    const match = text.match(/^(\s*)([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
    if (!match) continue;
    const indent = match[1].length;
    const key = match[2];
    const value = match[3].trim().replace(/^['"]|['"]$/g, "");
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const fullKey = [...stack.map((entry) => entry.key), key].join(".");
    if (value !== "") entries.push({ key: fullKey, value, line: line.number });
    stack.push({ indent, key });
  }

  return entries;
}

function inferProfile(relativePath) {
  const match = relativePath.match(/application[-.]([^.]+)\.(properties|ya?ml)$/i);
  return match?.[1] ?? "default";
}

function hasConcreteSecret(value) {
  const trimmed = value.trim();
  return Boolean(trimmed && !/^\$\{[^}]+}$/.test(trimmed) && !/^(changeme|example|dummy|test|password|secret)$/i.test(trimmed));
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

function lineAt(content, lineNumber) {
  return content.split(/\r?\n/)[lineNumber - 1]?.trim() ?? "";
}

function redact(value) {
  const text = String(value);
  if (text.length <= 4) return "****";
  return `${text.slice(0, 2)}${"*".repeat(Math.min(8, text.length - 2))}`;
}
