import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class ReportWriterTest {

    @Test
    void reportContainsAllFiveSections() throws Exception {
        Rulebook rulebook = new Rulebook();

        rulebook.addRule("INFO", 1);
        rulebook.addRule("WARN", 3);

        LogEntry info = new LogEntry(
                1,
                "2024-03-15 02:14:33 | INFO | 192.168.1.10 | /home | view",
                LocalDateTime.of(2024, 3, 15, 2, 14, 33),
                "INFO",
                "192.168.1.10",
                "/home",
                "view"
        );

        LogEntry warn = new LogEntry(
                2,
                "2024-03-15 02:15:33 | WARN | 192.168.1.10 | /login | failed",
                LocalDateTime.of(2024, 3, 15, 2, 15, 33),
                "WARN",
                "192.168.1.10",
                "/login",
                "failed"
        );

        Analyzer analyzer = new Analyzer();

        AnalysisResult result = analyzer.analyze(
                Arrays.asList(info, warn),
                rulebook
        );

        Path output = Files.createTempFile("report", ".txt");

        ReportWriter writer = new ReportWriter();

        writer.write(
                output,
                result,
                rulebook,
                Arrays.asList()
        );

        String report = Files.readString(output);

        assertTrue(report.contains("Activity Summary"));
        assertTrue(report.contains("Flagged Entries"));
        assertTrue(report.contains("Suspicious Activity by IP"));
        assertTrue(report.contains("Unknown Patterns"));
        assertTrue(report.contains("Malformed Lines"));

        assertTrue(report.contains(
                "2024-03-15 02:15:33 | WARN | 192.168.1.10 | /login | failed"
        ));

        assertTrue(report.contains("192.168.1.10: 2 total log entries"));

        Files.deleteIfExists(output);
    }

    @Test
    void reportContainsFullFileTimeWindow() throws Exception {
        Rulebook rulebook = new Rulebook();

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(),
                rulebook
        );

        Path output = Files.createTempFile("report", ".txt");

        ReportWriter writer = new ReportWriter();

        writer.write(
                output,
                result,
                rulebook,
                Arrays.asList()
        );

        String report = Files.readString(output);

        assertTrue(report.contains("=== Log Analysis Report ==="));
        assertTrue(report.contains("Generated: "));
        assertTrue(report.contains("Time Window: full file"));

        Files.deleteIfExists(output);
    }

    @Test
    void reportContainsSelectedTimeWindow() throws Exception {
        Rulebook rulebook = new Rulebook();

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(),
                rulebook
        );

        Path output = Files.createTempFile("report", ".txt");

        ReportWriter writer = new ReportWriter();

        writer.write(
                output,
                result,
                rulebook,
                Arrays.asList(),
                LocalDateTime.of(2024, 3, 15, 2, 0, 0),
                LocalDateTime.of(2024, 3, 15, 3, 30, 0)
        );

        String report = Files.readString(output);

        assertTrue(report.contains(
                "Time Window: 2024-03-15 02:00:00 to 2024-03-15 03:30:00"
        ));

        Files.deleteIfExists(output);
    }

    @Test
    void reportContainsAccurateSecurityOverview() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);
        rulebook.addRule("WARN", 3);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(1, "normal", timestamp,
                                "INFO", "192.168.1.10", "/home", "view"),
                        new LogEntry(2, "warning", timestamp,
                                "WARN", "192.168.1.10", "/login", "failed"),
                        new LogEntry(3, "normal", timestamp,
                                "INFO", "192.168.1.20", "/home", "view"),
                        new LogEntry(4, "unknown", timestamp,
                                "DEBUG", "192.168.1.30", "/home", "view")
                ),
                rulebook
        );

        Path output = Files.createTempFile("security-overview", ".txt");

        try {
            new ReportWriter().write(
                    output,
                    result,
                    rulebook,
                    Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(report.contains(
                    "Security Overview\n=================\n"
            ));
            assertTrue(report.contains("Total Parsed Events: 4"));
            assertTrue(report.contains("Flagged Events: 1"));
            assertTrue(report.contains("Suspicious IPs: 1"));
            assertTrue(report.contains("Unknown Patterns: 1"));
            assertTrue(report.contains("Malformed Lines: 0"));

            assertTrue(
                    report.indexOf("Security Overview")
                            < report.indexOf("Activity Summary")
            );
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void securityOverviewCountsMalformedLines() throws Exception {
        Rulebook rulebook = new Rulebook();

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(),
                rulebook
        );

        Path output = Files.createTempFile("malformed-overview", ".txt");

        try {
            new ReportWriter().write(
                    output,
                    result,
                    rulebook,
                    Arrays.asList(
                            new MalformedLine(5, "invalid log entry"),
                            new MalformedLine(9, "missing timestamp")
                    )
            );

            String report = Files.readString(output);

            assertTrue(report.contains("Total Parsed Events: 0"));
            assertTrue(report.contains("Flagged Events: 0"));
            assertTrue(report.contains("Malformed Lines: 2"));
            assertTrue(report.contains("Line 5: invalid log entry"));
            assertTrue(report.contains("Line 9: missing timestamp"));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void flaggedEntriesIncludeOriginalLineNumbers() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("WARN", 3);

        LogEntry warning = new LogEntry(
                42,
                "2024-03-15 02:00:00 | WARN | 192.168.1.10 | /login | failed",
                LocalDateTime.of(2024, 3, 15, 2, 0),
                "WARN",
                "192.168.1.10",
                "/login",
                "failed"
        );

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(warning),
                rulebook
        );

        Path output = Files.createTempFile("flagged-lines", ".txt");

        try {
            new ReportWriter().write(
                    output,
                    result,
                    rulebook,
                    Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(report.contains(
                    "Line 42: 2024-03-15 02:00:00 | WARN | "
                    + "192.168.1.10 | /login | failed"
            ));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void securityOverviewShowsFlaggedEventsBySeverity() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);
        rulebook.addRule("WARN", 3);
        rulebook.addRule("ERROR", 5);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(1, "normal", timestamp,
                                "INFO", "192.168.1.10", "/home", "view"),
                        new LogEntry(2, "warning one", timestamp,
                                "WARN", "192.168.1.20", "/login", "failed"),
                        new LogEntry(3, "error", timestamp,
                                "ERROR", "192.168.1.30", "/admin", "denied"),
                        new LogEntry(4, "warning two", timestamp,
                                "WARN", "192.168.1.20", "/login", "failed")
                ),
                rulebook
        );

        Path output = Files.createTempFile("severity-overview", ".txt");

        try {
            new ReportWriter().write(
                    output,
                    result,
                    rulebook,
                    Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(report.contains("Flagged Events: 3"));
            assertTrue(report.contains("Flagged Events by Severity"));
            assertTrue(report.contains("Severity 5: 1 event"));
            assertTrue(report.contains("Severity 3: 2 events"));
            assertFalse(report.contains("Severity 1:"));

            assertTrue(
                    report.indexOf("Flagged Events by Severity")
                            < report.indexOf("Activity Summary")
            );
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void severityBreakdownShowsNoneWhenNoEventsAreFlagged() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(1, "normal", timestamp,
                                "INFO", "192.168.1.10", "/home", "view")
                ),
                rulebook
        );

        Path output = Files.createTempFile("empty-severity", ".txt");

        try {
            new ReportWriter().write(
                    output,
                    result,
                    rulebook,
                    Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(report.contains(
                    "Flagged Events by Severity\n"
                    + "--------------------------\n"
                    + "None found."
            ));
            assertTrue(report.contains("Flagged Events: 0"));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void securityOverviewShowsTopFiveSuspiciousIps() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);
        rulebook.addRule("WARN", 3);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);
        java.util.List<LogEntry> entries = new java.util.ArrayList<>();

        for (int i = 1; i <= 7; i++) {
            String ip = "192.168.1." + i;
            entries.add(new LogEntry(
                    entries.size() + 1, "warning", timestamp,
                    "WARN", ip, "/login", "failed"
            ));

            int count = i == 6 ? 5 : i == 7 ? 5 : i;

            for (int j = 1; j < count; j++) {
                entries.add(new LogEntry(
                        entries.size() + 1, "normal", timestamp,
                        "INFO", ip, "/home", "view"
                ));
            }
        }

        AnalysisResult result = new Analyzer().analyze(entries, rulebook);
        Path output = Files.createTempFile("top-ips", ".txt");

        try {
            new ReportWriter().write(
                    output, result, rulebook, Arrays.asList()
            );

            String report = Files.readString(output);
            int start = report.indexOf("Top 5 Suspicious IPs");
            int end = report.indexOf("Activity Summary");
            assertTrue(start >= 0, "Top 5 subsection is missing");
            assertTrue(end > start, "Top 5 subsection is misplaced");

            String overview = report.substring(start, end);

            String[] expected = {
                    "192.168.1.5: 5 total log entries",
                    "192.168.1.6: 5 total log entries",
                    "192.168.1.7: 5 total log entries",
                    "192.168.1.4: 4 total log entries",
                    "192.168.1.3: 3 total log entries"
            };

            int previous = -1;
            for (String line : expected) {
                int position = overview.indexOf(line);
                assertTrue(position > previous,
                        "Missing or incorrectly ordered: " + line);
                previous = position;
            }

            assertFalse(overview.contains("192.168.1.2:"));
            assertFalse(overview.contains("192.168.1.1:"));

            assertTrue(report.contains(
                    "Suspicious Activity by IP"
            ));
            assertTrue(report.contains(
                    "192.168.1.1: 1 total log entries"
            ));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void topSuspiciousIpsShowsNoneWhenEmpty() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(
                                1, "normal", timestamp,
                                "INFO", "192.168.1.10", "/home", "view"
                        )
                ),
                rulebook
        );

        Path output = Files.createTempFile("empty-top-ips", ".txt");

        try {
            new ReportWriter().write(
                    output, result, rulebook, Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(report.contains(
                    "Top 5 Suspicious IPs\n"
                    + "--------------------\n"
                    + "None found.\n"
            ));

            assertTrue(report.contains("Suspicious IPs: 0"));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void reportRanksSuspiciousIpsByThreatScore() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);
        rulebook.addRule("WARN", 3);
        rulebook.addRule("ERROR", 5);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(1, "warning", timestamp,
                                "WARN", "192.168.1.30", "/login", "failed"),
                        new LogEntry(2, "error", timestamp,
                                "ERROR", "192.168.1.20", "/admin", "denied"),
                        new LogEntry(3, "error", timestamp,
                                "ERROR", "192.168.1.10", "/admin", "denied"),
                        new LogEntry(4, "warning", timestamp,
                                "WARN", "192.168.1.30", "/login", "failed"),
                        new LogEntry(5, "normal", timestamp,
                                "INFO", "192.168.1.20", "/home", "view")
                ),
                rulebook
        );

        Path output = Files.createTempFile("threat-scores", ".txt");

        try {
            new ReportWriter().write(
                    output, result, rulebook, Arrays.asList()
            );

            String report = Files.readString(output);
            int start = report.indexOf("Suspicious IP Threat Scores");
            int end = report.indexOf("Unknown Patterns", start);

            assertTrue(start >= 0, "Threat-score section is missing");
            assertTrue(end > start, "Threat-score section is misplaced");

            String section = report.substring(start, end);

            int first = section.indexOf("192.168.1.30: 6");
            int second = section.indexOf("192.168.1.10: 5");
            int third = section.indexOf("192.168.1.20: 5");

            assertTrue(first >= 0 && second > first && third > second,
                    "Threat scores must be sorted by score, then IP");
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void threatScoresShowNoneWhenEmpty() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("INFO", 1);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(),
                rulebook
        );

        Path output = Files.createTempFile("empty-threat-scores", ".txt");

        try {
            new ReportWriter().write(
                    output, result, rulebook, Arrays.asList()
            );

            String report = Files.readString(output);

            assertTrue(
                    report.contains(
                            "Suspicious IP Threat Scores\n"
                            + "===========================\n"
                            + "None found."
                    ),
                    "Empty threat-score section should display None found."
            );
        } finally {
            Files.deleteIfExists(output);
        }
    }


    @Test
    void threatScoresDisplayRiskClassifications() throws Exception {
        Rulebook rulebook = new Rulebook();
        rulebook.addRule("LOW_EVENT", 3);
        rulebook.addRule("FOUR_EVENT", 4);
        rulebook.addRule("FIVE_EVENT", 5);
        rulebook.addRule("NINE_EVENT", 9);
        rulebook.addRule("TEN_EVENT", 10);

        LocalDateTime timestamp = LocalDateTime.of(2024, 3, 15, 2, 0);

        AnalysisResult result = new Analyzer().analyze(
                Arrays.asList(
                        new LogEntry(1, "low", timestamp,
                                "LOW_EVENT", "192.168.1.10", "/a", "event"),
                        new LogEntry(2, "four", timestamp,
                                "FOUR_EVENT", "192.168.1.20", "/b", "event"),
                        new LogEntry(3, "five", timestamp,
                                "FIVE_EVENT", "192.168.1.30", "/c", "event"),
                        new LogEntry(4, "nine", timestamp,
                                "NINE_EVENT", "192.168.1.40", "/d", "event"),
                        new LogEntry(5, "ten", timestamp,
                                "TEN_EVENT", "192.168.1.50", "/e", "event")
                ),
                rulebook
        );

        Path output = Files.createTempFile("risk-classification", ".txt");

        try {
            new ReportWriter().write(
                    output, result, rulebook, Arrays.asList()
            );

            String report = Files.readString(output);
            int start = report.indexOf("Suspicious IP Threat Scores");
            int end = report.indexOf("Unknown Patterns", start);

            assertTrue(start >= 0 && end > start);

            String section = report.substring(start, end);

            assertTrue(section.contains("192.168.1.10: 3 (LOW)"));
            assertTrue(section.contains("192.168.1.20: 4 (LOW)"));
            assertTrue(section.contains("192.168.1.30: 5 (MEDIUM)"));
            assertTrue(section.contains("192.168.1.40: 9 (MEDIUM)"));
            assertTrue(section.contains("192.168.1.50: 10 (HIGH)"));
        } finally {
            Files.deleteIfExists(output);
        }
    }

}
