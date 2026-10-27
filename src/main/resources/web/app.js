"use strict";

const form = document.getElementById("analysis-form");
const logInput = document.getElementById("log-file");
const rulebookInput = document.getElementById("rulebook-file");
const analyzeButton = document.getElementById("analyze-button");
const statusElement = document.getElementById("analysis-status");

const MAX_LOG_BYTES = 10 * 1024 * 1024;
const MAX_RULEBOOK_BYTES = 1024 * 1024;

function setStatus(message, isError = false) {
  statusElement.textContent = message;
  statusElement.classList.toggle("error", isError);
}

function countItems(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") return Object.keys(value).length;
  return 0;
}

function entriesOf(value) {
  if (Array.isArray(value)) {
    return value.map((item, index) => [String(index), item]);
  }
  if (value && typeof value === "object") {
    return Object.entries(value);
  }
  return [];
}

function displayValue(value) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "—";
  return JSON.stringify(value);
}

function addCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = displayValue(value);
  if (className) cell.className = className;
  row.appendChild(cell);
}

function renderThreats(data) {
  const table = document.getElementById("threat-table");
  table.replaceChildren();

  const scores = entriesOf(data.threatScores);
  const levels = data.riskLevels || {};

  document.getElementById("suspicious-count").textContent =
    countItems(data.suspiciousIps);

  let highRiskCount = 0;

  for (const [ip, score] of scores) {
    const level = typeof levels === "object" && !Array.isArray(levels)
      ? levels[ip] || "UNKNOWN"
      : "UNKNOWN";

    if (level === "HIGH") highRiskCount++;

    const row = document.createElement("tr");
    addCell(row, ip);
    addCell(row, score);
    addCell(
      row,
      level,
      ["HIGH", "MEDIUM", "LOW"].includes(level)
        ? `risk-${level.toLowerCase()}`
        : ""
    );
    table.appendChild(row);
  }

  document.getElementById("high-risk-count").textContent = highRiskCount;

  if (scores.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.className = "empty-state";
    cell.textContent = "No scored IPs found.";
    row.appendChild(cell);
    table.appendChild(row);
  }
}

let flaggedEvents = [];

const eventSearch = document.getElementById("event-search");
const eventLevel = document.getElementById("event-level");

function renderEventTable() {
  const table = document.getElementById("event-table");
  const query = eventSearch.value.trim().toLowerCase();
  const selectedLevel = eventLevel.value;

  const filtered = flaggedEvents.filter((event) => {
    const level = String(event.level ?? "");
    const searchable = [
      event.timestamp,
      event.level,
      event.sourceIp,
      event.target,
      event.action,
      event.rawContent,
      event.lineNumber
    ].map((value) => String(value ?? "")).join(" ").toLowerCase();

    return searchable.includes(query)
      && (!selectedLevel || level === selectedLevel);
  });

  table.replaceChildren();

  document.getElementById("event-count").textContent =
    `${filtered.length} of ${flaggedEvents.length} events`;

  if (filtered.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-state";
    cell.textContent = flaggedEvents.length
      ? "No events match your filters."
      : "No flagged events found.";
    row.appendChild(cell);
    table.appendChild(row);
    return;
  }

  for (const event of filtered) {
    const row = document.createElement("tr");

    addCell(row, event.timestamp);
    addCell(row, event.level);
    addCell(row, event.sourceIp);
    addCell(row, event.target);
    addCell(row, event.action);
    addCell(row, event.lineNumber);

    row.title = String(event.rawContent ?? "");
    table.appendChild(row);
  }
}

function renderEvents(data) {
  flaggedEvents = Array.isArray(data.flaggedEntries)
    ? data.flaggedEntries
    : [];

  document.getElementById("flagged-count").textContent =
    flaggedEvents.length;

  document.getElementById("malformed-count").textContent =
    countItems(data.malformedLines);

  const levels = [...new Set(
    flaggedEvents.map((event) => String(event.level ?? ""))
  )].filter(Boolean).sort();

  eventLevel.replaceChildren();

  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "All severity levels";
  eventLevel.appendChild(allOption);

  for (const level of levels) {
    const option = document.createElement("option");
    option.value = level;
    option.textContent = level;
    eventLevel.appendChild(option);
  }

  eventSearch.value = "";
  eventLevel.value = "";

  renderEventTable();
}

eventSearch.addEventListener("input", renderEventTable);
eventLevel.addEventListener("change", renderEventTable);

function createChartRow(label, value, maxValue, category) {
  const row = document.createElement("div");
  row.className = "chart-row";

  const heading = document.createElement("div");
  heading.className = "chart-row-heading";

  const name = document.createElement("span");
  name.textContent = label;

  const count = document.createElement("strong");
  count.textContent = String(value);

  heading.append(name, count);

  const track = document.createElement("div");
  track.className = "chart-track";

  const bar = document.createElement("div");
  bar.className = "chart-bar";
  bar.dataset.category = category;
  bar.style.width = `${maxValue > 0 ? value / maxValue * 100 : 0}%`;

  track.appendChild(bar);
  row.append(heading, track);

  return row;
}

function renderCharts(data) {
  const riskChart = document.getElementById("risk-chart");
  const threatChart = document.getElementById("threat-chart");

  riskChart.replaceChildren();
  threatChart.replaceChildren();

  const riskCounts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  const riskLevels = data.riskLevels || {};

  for (const level of Object.values(riskLevels)) {
    if (Object.hasOwn(riskCounts, level)) {
      riskCounts[level]++;
    }
  }

  const maxRisk = Math.max(1, ...Object.values(riskCounts));

  for (const [level, count] of Object.entries(riskCounts)) {
    riskChart.appendChild(
      createChartRow(level, count, maxRisk, level.toLowerCase())
    );
  }

  const topThreats = Object.entries(data.threatScores || {})
    .map(([ip, score]) => [ip, Number(score)])
    .filter(([, score]) => Number.isFinite(score) && score >= 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  if (topThreats.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No threat scores found.";
    threatChart.appendChild(empty);
    return;
  }

  const maxScore = Math.max(1, ...topThreats.map(([, score]) => score));

  for (const [ip, score] of topThreats) {
    const level = String(riskLevels[ip] || "LOW").toLowerCase();

    threatChart.appendChild(
      createChartRow(ip, score, maxScore, level)
    );
  }
}

let latestAnalysis = null;

const downloadButton = document.getElementById("download-report");

function downloadAnalysisReport() {
  if (!latestAnalysis) return;

  const report = {
    reportType: "TraceFinder Security Analysis",
    generatedAt: new Date().toISOString(),
    ...latestAnalysis
  };

  const blob = new Blob(
    [JSON.stringify(report, null, 2)],
    { type: "application/json" }
  );

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  const timestamp = new Date().toISOString()
    .replace(/[:.]/g, "-");

  link.href = url;
  link.download = `tracefinder-report-${timestamp}.json`;

  document.body.appendChild(link);
  link.click();
  link.remove();

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

downloadButton.addEventListener("click", downloadAnalysisReport);

function renderResults(data) {
  latestAnalysis = data;
  downloadButton.disabled = false;

  renderCharts(data);
  renderThreats(data);
  renderEvents(data);
}

logInput.addEventListener("change", () => {
  document.getElementById("log-filename").textContent =
    logInput.files[0]?.name || "No file selected";
});

rulebookInput.addEventListener("change", () => {
  document.getElementById("rulebook-filename").textContent =
    rulebookInput.files[0]?.name || "No file selected";
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  latestAnalysis = null;
  downloadButton.disabled = true;

  const logFile = logInput.files[0];
  const rulebookFile = rulebookInput.files[0];

  if (!logFile || !rulebookFile) {
    setStatus("Select both a log file and a rulebook.", true);
    return;
  }

  if (logFile.size > MAX_LOG_BYTES) {
    setStatus("Log file exceeds the 10 MB limit.", true);
    return;
  }

  if (rulebookFile.size > MAX_RULEBOOK_BYTES) {
    setStatus("Rulebook exceeds the 1 MB limit.", true);
    return;
  }

  analyzeButton.disabled = true;
  setStatus("Analyzing security logs...");

  try {
    const [logs, rulebook] = await Promise.all([
      logFile.text(),
      rulebookFile.text()
    ]);

    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logs, rulebook })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        typeof data.error === "string"
          ? data.error
          : data.message || `Analysis failed (HTTP ${response.status}).`
      );
    }

    renderResults(data);
    setStatus("Analysis completed successfully.");
    document.getElementById("overview").scrollIntoView({
      behavior: "smooth"
    });
  } catch (error) {
    setStatus(error.message || "Analysis failed.", true);
  } finally {
    analyzeButton.disabled = false;
  }
});
