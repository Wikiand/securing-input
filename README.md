# TraceFinder

**TraceFinder** is a Java-based security log analysis application that detects suspicious activity, identifies malformed log entries, and evaluates threats using configurable severity rules.

Initially developed as a command-line application as part of my ongoing software development training at Kood, TraceFinder has since been extended with a browser-based Security Operations Center (SOC) dashboard and a REST API.

The dashboard builds on the original CLI implementation, reusing the same log parsing, validation, rulebook processing, and threat analysis components. Both interfaces remain available.

## Overview

TraceFinder processes structured access logs against a CSV rulebook to identify potentially suspicious events and produce actionable security analysis.

The application supports two interfaces:

- **Command-line interface (CLI):** Processes log files and generates detailed plain-text security reports.
- **SOC dashboard:** Provides an interactive browser interface for uploading logs, reviewing threat indicators, investigating suspicious IP addresses, and exporting analysis results.

The underlying analysis engine is shared between both interfaces.

## Features

### Log Analysis

- Parse structured security logs containing timestamps, activity levels, source IPs, resources, and actions.
- Evaluate events against a configurable CSV severity rulebook.
- Flag events with severity scores of 3 or higher.
- Identify unknown activity levels and malformed log entries.
- Count activity by severity level.
- Identify suspicious source IP addresses.
- Calculate severity-weighted threat scores for suspicious IPs.
- Classify threats into LOW, MEDIUM, and HIGH risk levels.

### Command-Line Interface

- Analyze complete log files.
- Filter events using an optional time window.
- Configure custom medium and high risk thresholds.
- Generate plain-text security reports.
- Report malformed entries without terminating analysis of valid records.
- Provide descriptive errors for invalid arguments, files, and rulebooks.

### SOC Dashboard

- Upload log files and CSV rulebooks through a browser.
- Analyze security events using the shared Java analysis engine.
- View security metrics and risk distribution charts.
- Explore top threat sources.
- Search and filter flagged events.
- Investigate individual suspicious IP addresses.
- Review event timelines and original log evidence.
- Copy evidence and export analysis results as JSON.
- Use a responsive, dark-themed security interface.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Java 17 |
| Build and dependency management | Apache Maven |
| HTTP server | Java `HttpServer` |
| JSON processing | Jackson |
| Frontend | HTML, CSS, JavaScript |
| Testing | JUnit 5 |
| Code coverage | JaCoCo |
| Version control | Git |

The application uses Java's built-in HTTP server rather than a web framework such as Spring Boot.

## Architecture

TraceFinder separates input handling, log parsing, analysis, reporting, and presentation.

```text
                      TraceFinder
                           |
              +------------+------------+
              |                         |
          Java CLI                  SOC Dashboard
              |                         |
         File inputs                 Browser UI
              |                         |
              |                    REST API
              |                         |
              +------------+------------+
                           |
                    Shared Core Engine
                           |
              +------------+------------+
              |            |            |
          LogReader    RulebookReader  Parser
              |            |            |
              +------------+------------+
                           |
                        Analyzer
                           |
                     AnalysisResult
                           |
              +------------+------------+
              |                         |
         ReportWriter               JSON Response
              |                         |
        Text Report               SOC Dashboard
```

The CLI and REST API both rely on the same core analysis components, keeping detection behavior consistent across interfaces.

## Project Structure

```text
trace-finder/
├── pom.xml
├── README.md
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   ├── Main.java
│   │   │   ├── TraceFinderServer.java
│   │   │   ├── TraceFinderAnalyzeHandler.java
│   │   │   ├── TraceFinderStaticHandler.java
│   │   │   ├── Analyzer.java
│   │   │   ├── AnalysisResult.java
│   │   │   ├── Parser.java
│   │   │   ├── LogReader.java
│   │   │   ├── RulebookReader.java
│   │   │   ├── ReportWriter.java
│   │   │   ├── RiskThresholds.java
│   │   │   └── ...
│   │   └── resources/
│   │       └── web/
│   │           ├── index.html
│   │           ├── styles.css
│   │           └── app.js
│   └── test/
│       └── java/
│           ├── AnalyzerTest.java
│           ├── ParserTest.java
│           ├── LogReaderTest.java
│           ├── RulebookReaderTest.java
│           ├── RiskThresholdsTest.java
│           ├── TraceFinderServerTest.java
│           └── ...
├── test-data/
└── target/                    # Generated by Maven
```

## Getting Started

### Prerequisites

- JDK 17
- Apache Maven
- Git
- A modern web browser for the dashboard

### Clone the Repository

```bash
git clone https://github.com/Wikiand/securing-input.git
cd securing-input
```

### Build and Test

```bash
mvn clean verify
```

This compiles the project, runs the automated tests, and generates the JaCoCo coverage report.

Java 17 is the supported runtime and compilation target.

## Command-Line Usage

The CLI accepts a log file, CSV rulebook, and output report path.

### Standard Analysis

```bash
java -cp target/classes Main logs.txt rules.csv report.txt
```

### Time-Window Analysis

```bash
java -cp target/classes Main \
  logs.txt rules.csv report.txt \
  "2024-03-15 02:00:00" \
  "2024-03-15 03:30:00"
```

Timestamps must use the format:

```text
yyyy-MM-dd HH:mm:ss
```

The start time is inclusive and the end time is exclusive:

```text
[start, end)
```

### Custom Risk Thresholds

```bash
java -cp target/classes Main \
  logs.txt rules.csv report.txt \
  --risk-medium=5 \
  --risk-high=10
```

The CLI supports either a time window or custom risk thresholds in a single invocation, not both together.

## Input Formats

### Log File

Each log entry contains five pipe-separated fields:

```text
timestamp | level | source_ip | resource | action
```

Example:

```text
2024-03-15 02:14:33 | INFO | 192.168.1.10 | /home | view
2024-03-15 02:15:10 | WARN | 192.168.1.11 | /login | failed
2024-03-15 02:16:45 | ERROR | 192.168.1.12 | /admin | denied
2024-03-15 02:18:20 | ALERT | 192.168.1.12 | /config | accessed
```

### CSV Rulebook

The rulebook defines severity scores for recognized activity levels.

```csv
level,severity_score
INFO,1
WARN,3
ERROR,5
ALERT,9
```

The required header is:

```text
level,severity_score
```

Severity scores must be nonnegative integers, and normalized rulebook levels must be unique.

## Detection and Threat Scoring

### Event Flagging

A parsed event is flagged when its activity level exists in the rulebook and its severity score is at least 3.

Unknown levels are recorded separately as unknown patterns.

### Suspicious IP Identification

An IP address is considered suspicious when at least one of its events is flagged.

The suspicious IP activity count includes all parsed events associated with that IP, not only flagged events.

### Threat Score Calculation

TraceFinder calculates a source IP's threat score by summing the severity scores of its flagged events.

For example:

```text
Source IP: 192.168.1.12

WARN   = 3
ERROR  = 5
ALERT  = 9
------------
Total  = 17
Risk   = HIGH
```

### Risk Classification

The default thresholds are:

| Threat Score | Classification |
|---|---|
| 0–4 | LOW |
| 5–9 | MEDIUM |
| 10 and above | HIGH |

The CLI supports configurable thresholds. The REST API currently uses the default medium threshold of 5 and high threshold of 10.

## CLI Report

The command-line application generates a plain-text report containing:

1. Security Overview
2. Flagged Events by Severity
3. Top 5 Suspicious IPs
4. Activity Summary
5. Flagged Entries
6. Suspicious Activity by IP
7. Suspicious IP Threat Scores
8. Unknown Patterns
9. Malformed Lines

The report includes the generation timestamp and indicates whether the analysis covered the complete file or a specified time window.

Flagged entries retain their original log content and source line numbers to support investigation.

## SOC Dashboard

The browser-based SOC dashboard extends the original CLI with interactive analysis and investigation capabilities.

### Start the Server

After building the project, generate the runtime dependency classpath:

```bash
mvn dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
```

Start the server:

```bash
java -cp "target/classes:$(cat target/classpath.txt)" TraceFinderServer
```

Open the dashboard:

```text
http://127.0.0.1:8080
```

The server binds to the local loopback interface, making the dashboard accessible locally rather than exposing it on the network.

### Investigation Workflow

1. Upload a structured log file.
2. Upload the corresponding CSV severity rulebook.
3. Run the analysis.
4. Review the security overview and threat charts.
5. Filter flagged events and investigate suspicious IPs.
6. Inspect event timelines and original log evidence.
7. Export the analysis results as JSON.

## REST API Reference

The SOC dashboard communicates with a lightweight Java REST API.

### Health Check

```http
GET /api/health
```

Example response:

```json
{
  "status": "ok",
  "service": "TraceFinder API"
}
```

### Analyze Logs

```http
POST /api/analyze
Content-Type: application/json
```

Example request:

```json
{
  "logs": "2024-03-15 02:15:10 | WARN | 192.168.1.11 | /login | failed",
  "rulebook": "level,severity_score\nINFO,1\nWARN,3\nERROR,5\nALERT,9"
}
```

A successful response contains:

```json
{
  "activitySummary": {
    "WARN": 1
  },
  "flaggedEntries": [
    {
      "lineNumber": 1,
      "rawContent": "2024-03-15 02:15:10 | WARN | 192.168.1.11 | /login | failed",
      "timestamp": [2024, 3, 15, 2, 15, 10],
      "level": "WARN",
      "sourceIp": "192.168.1.11",
      "target": "/login",
      "action": "failed"
    }
  ],
  "suspiciousIps": {
    "192.168.1.11": 1
  },
  "threatScores": {
    "192.168.1.11": 3
  },
  "riskLevels": {
    "192.168.1.11": "LOW"
  },
  "unknownPatterns": [],
  "malformedLines": []
}
```


### API Error Responses

| HTTP Status | Meaning |
|---|---|
| 400 | Invalid JSON, invalid request data, or invalid input files |
| 405 | Unsupported HTTP method |
| 413 | Request or input exceeds configured size limits |
| 415 | Unsupported content type |

Error responses use a JSON object containing an `error` message.

## Input Validation and Security

TraceFinder applies input validation across both its CLI and REST API interfaces.

### File and Request Limits

| Input | Maximum Size |
|---|---|
| Log file | 10 MiB |
| CSV rulebook | 1 MiB |
| Individual log line | 8,192 characters |
| HTTP request body | 12 MiB |

### Validation Controls

- Reject oversized input files and HTTP requests.
- Validate the required CSV rulebook header and column structure.
- Reject duplicate normalized rulebook levels.
- Reject negative or non-integer severity scores.
- Validate structured log fields and timestamps.
- Detect malformed log entries without discarding valid entries.
- Reject invalid UTF-8 input.
- Handle hidden, zero-width, and control characters.
- Reject invalid or non-regular file inputs.
- Preserve source line numbers for investigation and reporting.
- Use descriptive application exceptions for unrecoverable input failures.

The API processes submitted content using temporary files and attempts to delete those files after analysis.

The dashboard is intended for local use and does not provide authentication or persistent storage.

## Testing

TraceFinder uses JUnit 5 for automated testing and JaCoCo for code coverage.

The test suite covers:

- Log parsing and validation
- Rulebook parsing and validation
- Input sanitization
- Log file reading and size limits
- Activity analysis and event flagging
- Time-window filtering
- Threat scoring and risk thresholds
- Plain-text report generation
- CLI argument validation and error handling
- HTTP server and API behavior

The latest verified Maven test run completed with **96 passing tests, zero failures, and zero errors**.

### Run Tests

```bash
mvn test
```

### Run Full Verification

```bash
mvn clean verify
```

### View Coverage

After running the tests, open:

```text
target/site/jacoco/index.html
```

JaCoCo provides instruction, branch, method, class, and line coverage information.

## Project Evolution

TraceFinder began as a command-line security log analyzer focused on structured parsing, rulebook-based detection, and reliable report generation.

Its subsequent development introduced time-window filtering, defensive input validation, custom exceptions, threat scoring, and configurable risk classification.

The SOC dashboard and REST API were then added as an extension of the same application, allowing the existing analysis engine to support browser-based investigations without replacing the original CLI.

This development is part of my ongoing software development training at Kood, combining Java backend engineering, secure input handling, automated testing, and practical cybersecurity analysis.
