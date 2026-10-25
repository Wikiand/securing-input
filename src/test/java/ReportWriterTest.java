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
}
