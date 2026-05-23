const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json";
const sarifVersion = "2.1.0";
const severityLevels = {
  high: "error",
  medium: "warning",
  low: "note"
};

export function toSarif(report) {
  const rules = collectRules(report.findings);

  return {
    version: sarifVersion,
    $schema: sarifSchema,
    runs: [
      {
        tool: {
          driver: {
            name: "stacklens",
            informationUri: "https://github.com/thassan66/stacklens",
            rules
          }
        },
        results: report.findings.map(toSarifResult)
      }
    ]
  };
}

function collectRules(findings) {
  const rules = new Map();

  for (const finding of findings) {
    if (rules.has(finding.ruleId)) continue;

    rules.set(finding.ruleId, {
      id: finding.ruleId,
      name: finding.title,
      shortDescription: {
        text: finding.title
      },
      fullDescription: {
        text: finding.message
      },
      defaultConfiguration: {
        level: severityLevels[finding.severity] ?? "warning"
      },
      properties: {
        category: finding.category,
        severity: finding.severity
      }
    });
  }

  return Array.from(rules.values()).sort((a, b) => a.id.localeCompare(b.id));
}

function toSarifResult(finding) {
  return {
    ruleId: finding.ruleId,
    level: severityLevels[finding.severity] ?? "warning",
    message: {
      text: finding.message
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: toArtifactUri(finding.file)
          },
          region: {
            startLine: Math.max(1, Number(finding.line) || 1)
          }
        }
      }
    ],
    properties: {
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      snippet: finding.snippet
    }
  };
}

function toArtifactUri(file) {
  return String(file).replaceAll("\\", "/");
}
