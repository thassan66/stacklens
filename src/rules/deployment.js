const deploymentPathPattern = /(^|\/)(src\/main\/kubernetes|k8s|kubernetes|openshift|deploy|deployments|manifests|argocd|\.argocd|helm|charts)\/.+\.(ya?ml|json)$/i;
const deploymentBasenamePattern = /^(chart|deployment|deploymentconfig|route|service|secret|kustomization|values)([-.\w]*)?\.ya?ml$/i;
const secretKeyPattern = /(password|passwd|secret|token|api[-_.]?key|private[-_.]?key|client[-_.]?secret|access[-_.]?key)/i;

export function scanDeployments(context) {
  const files = collectDeploymentFiles(context);

  return files.flatMap((file) => [
    ...scanRoute(context, file),
    ...scanKubernetesSecret(context, file),
    ...scanContainerManifest(context, file),
    ...scanArgoApplication(context, file),
    ...scanHelmValues(context, file),
    ...scanKustomize(context, file)
  ]);
}

export function collectDeploymentFiles(context) {
  return context.files.filter(isDeploymentFile);
}

export function detectDeploymentSignals(files) {
  return {
    hasOpenShift: files.some((file) => /route\.openshift\.io|kind:\s*(Route|DeploymentConfig)\b|openshift/i.test(file.content)),
    hasArgoCd: files.some((file) => /argoproj\.io\/v1alpha1|kind:\s*Application\b/i.test(file.content)),
    hasHelm: files.some((file) => /(^|\/)(Chart|values)([-.\w]*)?\.ya?ml$/i.test(file.relativePath) || /(^|\/)(helm|charts)\//i.test(file.relativePath)),
    hasKustomize: files.some((file) => /(^|\/)kustomization\.ya?ml$/i.test(file.relativePath))
  };
}

function isDeploymentFile(file) {
  return deploymentPathPattern.test(file.relativePath) || deploymentBasenamePattern.test(basename(file.relativePath));
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
        message: "Use immutable tags or digests so deployment tooling rolls out the reviewed image.",
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
      message: "Use valueFrom with Kubernetes Secrets or platform secret references instead of plain env values.",
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

function scanHelmValues(context, file) {
  if (!isHelmValuesFile(file)) return [];

  const findings = [];
  const imageSectionLines = findSectionLineIndexes(file, "image");

  for (const [index, line] of file.lines.entries()) {
    const keyValue = parseYamlKeyValue(line.text);
    if (!keyValue) continue;

    const key = keyValue.key.toLowerCase();
    const value = stripQuotes(keyValue.value);

    if (key === "tag" && isMutableImageRef(`image:${value}`) && isNearSection(index, imageSectionLines, 8)) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Helm",
        ruleId: "helm-mutable-image-tag",
        title: "Helm values use a mutable image tag",
        message: "Use immutable tags or digests in Helm values for repeatable deployments.",
        snippet: line.text.trim()
      }));
    }

    if (key === "pullpolicy" && /^always$/i.test(value) && isNearSection(index, imageSectionLines, 8)) {
      findings.push(context.finding({
        severity: "low",
        file: file.relativePath,
        line: line.number,
        category: "Helm",
        ruleId: "helm-image-pull-always",
        title: "Helm values force image pull on every start",
        message: "Always pulling images can hide mutable tag drift and slow rollouts.",
        snippet: line.text.trim()
      }));
    }

    if (secretKeyPattern.test(key) && hasConcreteSecret(value)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Helm",
        ruleId: "helm-values-secret",
        title: "Helm values contain a secret-like value",
        message: "Use external secret management or encrypted values instead of committing concrete credentials.",
        snippet: `${keyValue.key}: ********`
      }));
    }
  }

  return findings;
}

function scanKustomize(context, file) {
  if (!/kustomization\.ya?ml$/i.test(basename(file.relativePath))) return [];

  const findings = [];

  for (const line of file.lines) {
    const keyValue = parseYamlKeyValue(line.text);
    if (keyValue?.key.toLowerCase() === "newtag" && isMutableImageRef(`image:${stripQuotes(keyValue.value)}`)) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Kustomize",
        ruleId: "kustomize-mutable-image-tag",
        title: "Kustomize image override uses a mutable tag",
        message: "Use immutable tags or digests for image overrides in Kustomize overlays.",
        snippet: line.text.trim()
      }));
    }

    if (/^\s*-\s*(https?:\/\/|git::|github\.com\/|bitbucket\.org\/|gitlab\.com\/)/i.test(line.text.trim())) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Kustomize",
        ruleId: "kustomize-remote-resource",
        title: "Kustomize references a remote resource",
        message: "Remote Kustomize bases should be pinned and reviewed because they affect rendered deployment output.",
        snippet: line.text.trim()
      }));
    }
  }

  return findings;
}

function isHelmValuesFile(file) {
  return /(^|\/)values([-.\w]*)?\.ya?ml$/i.test(file.relativePath);
}

function parseYamlKeyValue(text) {
  const match = text.match(/^\s*([A-Za-z0-9_.-]+)\s*:\s*(.+?)\s*$/);
  if (!match) return null;
  return { key: match[1], value: match[2] };
}

function findSectionLineIndexes(file, key) {
  return file.lines
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => new RegExp(`^\\s*${key}\\s*:\\s*$`, "i").test(line.text))
    .map(({ index }) => index);
}

function isNearSection(index, sectionIndexes, maxDistance) {
  return sectionIndexes.length === 0 || sectionIndexes.some((sectionIndex) => index > sectionIndex && index - sectionIndex <= maxDistance);
}

function isMutableImageRef(image) {
  if (image.includes("@sha256:")) return false;
  const imageName = image.split("/").at(-1) ?? image;
  if (!imageName.includes(":")) return true;
  return imageName.toLowerCase().endsWith(":latest");
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

function findLine(content, needle) {
  const index = content.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function stripQuotes(value) {
  return String(value ?? "").trim().replace(/^["'](.*)["']$/, "$1");
}

function basename(relativePath) {
  return relativePath.split(/[\\/]/).at(-1);
}
