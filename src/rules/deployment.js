const deploymentPathPattern = /(^|\/)(src\/main\/kubernetes|k8s|kubernetes|openshift|deploy|deployments|manifests|argocd|\.argocd|helm|charts|infra|infrastructure|terraform|tf|cloudformation|cfn|aws|azure|bicep|pipelines|ci|cd|jenkins)\/.+\.(ya?ml|json|tf|tfvars|bicep|groovy)$/i;
const deploymentBasenamePattern = /^(?:(chart|deployment|deploymentconfig|route|service|secret|kustomization|values|cloudformation|serverless|template)([-.\w]*)?\.ya?ml|Jenkinsfile(\..+)?|azure-pipelines\.ya?ml|.+\.tf|.+\.tfvars(\.json)?|.+\.bicep)$/i;
const secretKeyPattern = /(password|passwd|secret|token|api[-_.]?key|private[-_.]?key|client[-_.]?secret|access[-_.]?key)/i;

export function scanDeployments(context) {
  const files = collectDeploymentFiles(context);

  return files.flatMap((file) => [
    ...scanRoute(context, file),
    ...scanKubernetesSecret(context, file),
    ...scanContainerManifest(context, file),
    ...scanArgoApplication(context, file),
    ...scanHelmValues(context, file),
    ...scanKustomize(context, file),
    ...scanJenkins(context, file),
    ...scanTerraform(context, file),
    ...scanAwsManifest(context, file),
    ...scanAzureManifest(context, file)
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
    hasKustomize: files.some((file) => /(^|\/)kustomization\.ya?ml$/i.test(file.relativePath)),
    hasJenkins: files.some(isJenkinsFile),
    hasTerraform: files.some(isTerraformFile),
    hasAws: files.some(isAwsFile),
    hasAzure: files.some(isAzureFile)
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

function scanJenkins(context, file) {
  if (!isJenkinsFile(file)) return [];

  const findings = [];
  for (const line of file.lines) {
    if (/\b(curl|wget)\b[^|;&\n]*\|\s*(bash|sh|zsh|node|python)\b/i.test(line.text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Jenkins",
        ruleId: "jenkins-remote-script-execution",
        title: "Jenkins pipeline downloads and executes remote code",
        message: "Piping network content into an interpreter is risky in CI/CD jobs.",
        snippet: line.text.trim()
      }));
    }

    if (/\bdocker\s+run\b.*--privileged|--privileged.*\bdocker\s+run\b/i.test(line.text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Jenkins",
        ruleId: "jenkins-privileged-docker",
        title: "Jenkins pipeline runs a privileged Docker container",
        message: "Privileged containers in CI can expose the worker host and credentials.",
        snippet: line.text.trim()
      }));
    }

    const secret = findSecretAssignment(line.text);
    if (secret && !/credentials\s*\(/i.test(line.text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Jenkins",
        ruleId: "jenkins-secret-env",
        title: "Jenkins pipeline contains a plain secret-like value",
        message: "Use Jenkins credentials bindings instead of hardcoded pipeline secrets.",
        snippet: `${secret.key}=********`
      }));
    }
  }

  return findings;
}

function scanTerraform(context, file) {
  if (!isTerraformFile(file)) return [];

  const findings = [];
  for (const [index, line] of file.lines.entries()) {
    const text = line.text.trim();
    const secret = findSecretAssignment(text);
    if (secret) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Terraform",
        ruleId: "terraform-secret-default",
        title: "Terraform file contains a secret-like literal",
        message: "Use variables without committed defaults, secret stores, or CI-provided values for Terraform credentials.",
        snippet: `${secret.key}=********`
      }));
    }

    const defaultValue = text.match(/\bdefault\s*=\s*["']([^"']+)["']/i);
    if (defaultValue && hasConcreteSecret(defaultValue[1]) && nearbyText(file, index, 5).some((nearby) => secretKeyPattern.test(nearby))) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Terraform",
        ruleId: "terraform-secret-default",
        title: "Terraform variable contains a secret-like default",
        message: "Use variables without committed defaults, secret stores, or CI-provided values for Terraform credentials.",
        snippet: "default=********"
      }));
    }

    if (/cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"/i.test(text)) {
      const isAdminPort = nearbyText(file, index, 8).some((nearby) => /\b(from_port|to_port)\s*=\s*(22|3389)\b/i.test(nearby));
      findings.push(context.finding({
        severity: isAdminPort ? "high" : "medium",
        file: file.relativePath,
        line: line.number,
        category: "Terraform",
        ruleId: isAdminPort ? "terraform-public-admin-ingress" : "terraform-public-ingress",
        title: isAdminPort ? "Terraform exposes an admin port to the internet" : "Terraform allows public network ingress",
        message: "Public ingress should be scoped to expected source ranges, especially for administrative ports.",
        snippet: text
      }));
    }

    if (/\b(publicly_accessible|associate_public_ip_address|map_public_ip_on_launch)\s*=\s*true\b/i.test(text)) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Terraform",
        ruleId: "terraform-public-compute-or-database",
        title: "Terraform enables public network exposure",
        message: "Public IP or public database exposure should be intentional and protected by network policy.",
        snippet: text
      }));
    }

    if (/\bacl\s*=\s*"public-read"|\bblock_public_(acls|policy)\s*=\s*false|\bignore_public_acls\s*=\s*false|\brestrict_public_buckets\s*=\s*false/i.test(text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Terraform",
        ruleId: "terraform-public-storage",
        title: "Terraform may allow public storage access",
        message: "Public storage access should be blocked unless the bucket or account is explicitly designed for public assets.",
        snippet: text
      }));
    }
  }

  return findings;
}

function scanAwsManifest(context, file) {
  if (!isAwsFile(file)) return [];

  const findings = [];
  for (const [index, line] of file.lines.entries()) {
    const text = line.text.trim();

    if (/\b(CidrIp|CidrIpv6)\s*:\s*["']?(0\.0\.0\.0\/0|::\/0)["']?/i.test(text) || /"CidrIp"\s*:\s*"0\.0\.0\.0\/0"/i.test(text)) {
      const isAdminPort = nearbyText(file, index, 8).some((nearby) => /\b(FromPort|ToPort)\s*:\s*(22|3389)\b|"(FromPort|ToPort)"\s*:\s*(22|3389)/i.test(nearby));
      findings.push(context.finding({
        severity: isAdminPort ? "high" : "medium",
        file: file.relativePath,
        line: line.number,
        category: "AWS",
        ruleId: isAdminPort ? "aws-public-admin-ingress" : "aws-public-ingress",
        title: isAdminPort ? "AWS template exposes an admin port to the internet" : "AWS template allows public ingress",
        message: "Public ingress should be scoped to expected source ranges, especially for administrative ports.",
        snippet: text
      }));
    }

    if (/\bPrincipal\s*:\s*["']?\*["']?|"\s*Principal\s*"\s*:\s*"\*"/i.test(text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "AWS",
        ruleId: "aws-public-iam-principal",
        title: "AWS policy allows a wildcard principal",
        message: "Wildcard principals can grant access outside the intended account or workload boundary.",
        snippet: text
      }));
    }

    if (/\b(PubliclyAccessible)\s*:\s*true\b|\b(BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)\s*:\s*false\b/i.test(text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "AWS",
        ruleId: "aws-public-resource",
        title: "AWS template enables public resource exposure",
        message: "Public database or storage access should be avoided unless it is explicitly required and controlled.",
        snippet: text
      }));
    }
  }

  if (hasWildcardIamStatement(file.content)) {
    findings.push(context.finding({
      severity: "high",
      file: file.relativePath,
      line: findLine(file.content, "Action:"),
      category: "AWS",
      ruleId: "aws-wildcard-iam-permission",
      title: "AWS policy appears to allow wildcard permissions",
      message: "Wildcard Action and Resource permissions should be narrowed to the least privilege needed.",
      snippet: "Action/Resource wildcard policy"
    }));
  }

  return findings;
}

function scanAzureManifest(context, file) {
  if (!isAzureFile(file)) return [];

  const findings = [];
  const shouldScanSecrets = !isTerraformFile(file);

  for (const line of file.lines) {
    const text = line.text.trim();
    const secret = findSecretAssignment(text);

    if (shouldScanSecrets && secret) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Azure",
        ruleId: "azure-plain-secret",
        title: "Azure deployment file contains a plain secret-like value",
        message: "Use secret variables, Key Vault references, or deployment-time injection instead of committed secrets.",
        snippet: `${secret.key}=********`
      }));
    }

    if (/\b(publicNetworkAccess|public_network_access_enabled)\s*[:=]\s*["']?(Enabled|true)["']?/i.test(text)) {
      findings.push(context.finding({
        severity: "medium",
        file: file.relativePath,
        line: line.number,
        category: "Azure",
        ruleId: "azure-public-network-access",
        title: "Azure resource enables public network access",
        message: "Public network access should be restricted unless the resource is intentionally internet-facing.",
        snippet: text
      }));
    }

    if (/\b(allowBlobPublicAccess|allow_blob_public_access)\s*[:=]\s*true\b|\bdefaultAction\s*:\s*Allow\b/i.test(text)) {
      findings.push(context.finding({
        severity: "high",
        file: file.relativePath,
        line: line.number,
        category: "Azure",
        ruleId: "azure-public-storage-or-network",
        title: "Azure deployment allows broad storage or network access",
        message: "Storage public access and default-allow network ACLs should be avoided for production resources.",
        snippet: text
      }));
    }
  }

  return findings;
}

function isHelmValuesFile(file) {
  return /(^|\/)values([-.\w]*)?\.ya?ml$/i.test(file.relativePath);
}

function isJenkinsFile(file) {
  return /^Jenkinsfile(\..+)?$/i.test(basename(file.relativePath)) || /(^|\/)jenkins\/.+\.(groovy|jenkinsfile)$/i.test(file.relativePath);
}

function isTerraformFile(file) {
  return /\.tf(vars)?(\.json)?$/i.test(file.relativePath);
}

function isAwsFile(file) {
  return /(^|\/)(aws|cloudformation|cfn)\//i.test(file.relativePath) ||
    /(^|\/)(cloudformation|template|serverless)([-.\w]*)?\.(ya?ml|json)$/i.test(file.relativePath) ||
    /\b(AWSTemplateFormatVersion|AWS::|aws_)/i.test(file.content);
}

function isAzureFile(file) {
  return /(^|\/)(azure|bicep)\//i.test(file.relativePath) ||
    /(^|\/)azure-pipelines\.ya?ml$/i.test(file.relativePath) ||
    /\.bicep$/i.test(file.relativePath) ||
    /\b(azurerm_|Microsoft\.|AzureCLI@|AzurePowerShell@)/i.test(file.content);
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

function nearbyText(file, index, distance) {
  const start = Math.max(0, index - distance);
  const end = Math.min(file.lines.length, index + distance + 1);
  return file.lines.slice(start, end).map((line) => line.text);
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

function findSecretAssignment(text) {
  const assignment = text.match(/([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[-_.]?key|private[-_.]?key|client[-_.]?secret|access[-_.]?key)[A-Za-z0-9_.-]*)\s*(?:=|:)\s*["']?([^"',\]\s}]+)["']?/i);
  if (!assignment) return null;

  const key = assignment[1];
  const value = assignment[2];
  if (!hasConcreteSecret(value)) return null;
  return { key, value };
}

function hasWildcardIamStatement(content) {
  const statements = content.split(/\bStatement\b/i);
  return statements.some((statement) =>
    /\bEffect\s*:\s*Allow\b|"Effect"\s*:\s*"Allow"/i.test(statement) &&
    (/\bAction\s*:\s*["']?\*["']?|"Action"\s*:\s*"\*"/i.test(statement) || /-\s*["']?\*["']?/i.test(statement)) &&
    (/\bResource\s*:\s*["']?\*["']?|"Resource"\s*:\s*"\*"/i.test(statement) || /-\s*["']?\*["']?/i.test(statement))
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
