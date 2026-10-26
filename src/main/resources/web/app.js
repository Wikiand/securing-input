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

function renderEvents(data) {
  const container = document.getElementById("events-container");
  container.replaceChildren();
  container.classList.remove("empty-state");

  const events = entriesOf(data.flaggedEntries);

  document.getElementById("flagged-count").textContent = events.length;
  document.getElementById("malformed-count").textContent =
    countItems(data.malformedLines);

  if (events.length === 0) {
    container.classList.add("empty-state");
    container.textContent = "No flagged events found.";
    return;
  }

  for (const [key, event] of events) {
    const item = document.createElement("div");
    item.className = "event-item";

    const label = document.createElement("strong");
    label.textContent = `Event ${key}`;

    const detail = document.createElement("div");
    detail.textContent = displayValue(event);

    item.append(label, detail);
    container.appendChild(item);
  }
}

function renderResults(data) {
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
