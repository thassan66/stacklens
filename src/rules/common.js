export function scanCommon(context) {
  return [
    ...scanDocker(context),
    ...scanGitHubActions(context)
  ];
}

function scanDocker(context) {
  const findings = [];
  const dockerFiles = context.files.filter((file) =>
    /(^|\/)(Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)$/i.test(file.relativePath)
  );

  for (const file of dockerFiles) {
    for (const line of file.lines) {
      if (/["']?\d+:\d+["']?/.test(line.text)) {
        findings.push(context.finding({
          severity: "low",
          file: file.relativePath,
          line: line.number,
          category: "Docker",
          ruleId: "docker-port-published",
          title: "Docker publishes local ports",
          message: "Published ports are useful locally, but should be reviewed before sharing compose files.",
          snippet: line.text.trim()
        }));
      }

      if (/\/var\/run\/docker\.sock|~\/|source:\s*\//i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "Docker",
          ruleId: "docker-sensitive-mount",
          title: "Docker references a sensitive host mount",
          message: "Host mounts can expose credentials, source files, or the Docker daemon to containers.",
          snippet: line.text.trim()
        }));
      }
    }
  }

  return findings;
}

function scanGitHubActions(context) {
  const findings = [];
  const workflows = context.files.filter((file) => /^\.github\/workflows\/.+\.ya?ml$/i.test(file.relativePath));

  for (const file of workflows) {
    for (const line of file.lines) {
      if (/permissions:\s*write-all/i.test(line.text)) {
        findings.push(context.finding({
          severity: "high",
          file: file.relativePath,
          line: line.number,
          category: "CI/CD",
          ruleId: "workflow-write-all",
          title: "GitHub Actions grants write-all permissions",
          message: "Broad workflow permissions increase the blast radius of compromised jobs or dependencies.",
          snippet: line.text.trim()
        }));
      }

      if (/\bpull_request_target\b\s*:|:\s*pull_request_target\b/i.test(line.text)) {
        findings.push(context.finding({
          severity: "medium",
          file: file.relativePath,
          line: line.number,
          category: "CI/CD",
          ruleId: "workflow-pull-request-target",
          title: "Workflow uses pull_request_target",
          message: "pull_request_target can expose privileged context when handling untrusted pull requests.",
          snippet: line.text.trim()
        }));
      }
    }
  }

  return findings;
}
