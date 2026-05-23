let currentReport = null;
let activeFilter = "all";

async function loadReport() {
  const response = await fetch("/api/report");
  currentReport = await response.json();
  render(currentReport);
}

function render(report) {
  document.querySelector("#project-path").textContent = report.project.root;
  renderScore(report);
  renderSummary(report);
  renderStackFacts(report);
  renderFilters(report);
  renderFindings(report);
}

function renderScore(report) {
  const score = document.querySelector("#risk-score");
  if (report.summary.high > 0) {
    score.textContent = "High risk";
    score.style.color = "var(--high)";
  } else if (report.summary.medium > 0) {
    score.textContent = "Review";
    score.style.color = "var(--medium)";
  } else {
    score.textContent = "Looks clean";
    score.style.color = "var(--ok)";
  }
}

function renderSummary(report) {
  const metrics = [
    ["High", report.summary.high],
    ["Medium", report.summary.medium],
    ["Low", report.summary.low],
    ["Stacks", report.project.stacks.length]
  ];
  document.querySelector("#summary-grid").innerHTML = metrics
    .map(([label, value]) => `
      <article class="metric">
        <div class="metric-label">${escapeHtml(label)}</div>
        <div class="metric-value">${escapeHtml(String(value))}</div>
      </article>
    `)
    .join("");
}

function renderStackFacts(report) {
  const spring = report.ecosystems.spring;
  const node = report.ecosystems.node;
  const facts = [
    ["Project", report.project.name],
    ["Detected", report.project.stacks.join(", ") || "Unknown"],
    ["Files scanned", String(report.project.fileCount)],
    ["Spring Boot", spring.springBootVersion ?? "Not detected"],
    ["Java", spring.javaVersion ?? "Not detected"],
    ["Node package manager", node.packageManager ?? "Not detected"]
  ];

  document.querySelector("#stack-facts").innerHTML = facts
    .map(([label, value]) => `
      <div class="fact">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </div>
    `)
    .join("");
}

function renderFilters(report) {
  const filters = ["all", "high", "medium", "low"];
  document.querySelector("#filters").innerHTML = filters
    .map((filter) => `
      <button class="${filter === activeFilter ? "active" : ""}" data-filter="${filter}">
        ${escapeHtml(labelFor(filter, report))}
      </button>
    `)
    .join("");

  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      activeFilter = button.dataset.filter;
      renderFilters(currentReport);
      renderFindings(currentReport);
    });
  });
}

function renderFindings(report) {
  const findings = report.findings.filter((finding) => activeFilter === "all" || finding.severity === activeFilter);
  const container = document.querySelector("#findings");

  if (findings.length === 0) {
    container.innerHTML = `<div class="empty">No findings for this view.</div>`;
    return;
  }

  container.innerHTML = findings
    .map((finding) => `
      <article class="finding">
        <div><span class="badge ${finding.severity}">${escapeHtml(finding.severity)}</span></div>
        <div>
          <h3>${escapeHtml(finding.title)}</h3>
          <p>${escapeHtml(finding.message)}</p>
          <div class="location">${escapeHtml(finding.file)}:${finding.line} · ${escapeHtml(finding.category)}</div>
          ${finding.snippet ? `<code>${escapeHtml(finding.snippet)}</code>` : ""}
        </div>
      </article>
    `)
    .join("");
}

function labelFor(filter, report) {
  if (filter === "all") return `All (${report.findings.length})`;
  return `${filter.charAt(0).toUpperCase()}${filter.slice(1)} (${report.summary[filter]})`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

loadReport().catch((error) => {
  document.querySelector("#findings").innerHTML = `<div class="empty">${escapeHtml(error.message)}</div>`;
});
