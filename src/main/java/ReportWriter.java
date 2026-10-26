import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

public class ReportWriter {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void write(
            Path outputPath,
            AnalysisResult result,
            Rulebook rulebook,
            java.util.List<MalformedLine> malformedLines) throws IOException {

        write(
                outputPath,
                result,
                rulebook,
                malformedLines,
                null,
                null
        );
    }

    public void write(
            Path outputPath,
            AnalysisResult result,
            Rulebook rulebook,
            java.util.List<MalformedLine> malformedLines,
            LocalDateTime start,
            LocalDateTime end) throws IOException {

        StringBuilder report = new StringBuilder();

        report.append("=== Log Analysis Report ===\n");
        report.append("Generated: ")
                .append(LocalDateTime.now().format(TIMESTAMP_FORMAT))
                .append("\n");

        if (start == null || end == null) {
            report.append("Time Window: full file\n");
        } else {
            report.append("Time Window: ")
                    .append(start.format(TIMESTAMP_FORMAT))
                    .append(" to ")
                    .append(end.format(TIMESTAMP_FORMAT))
                    .append("\n");
        }

        // Security Overview
        int totalParsedEvents = result.getActivitySummary()
                .values()
                .stream()
                .mapToInt(Integer::intValue)
                .sum()
                + result.getUnknownPatterns().size();

        report.append("\nSecurity Overview\n");
        report.append("=================\n");
        report.append("Total Parsed Events: ")
                .append(totalParsedEvents)
                .append("\n");
        report.append("Flagged Events: ")
                .append(result.getFlaggedEntries().size())
                .append("\n");
        report.append("Suspicious IPs: ")
                .append(result.getSuspiciousIps().size())
                .append("\n");
        report.append("Unknown Patterns: ")
                .append(result.getUnknownPatterns().size())
                .append("\n");
        report.append("Malformed Lines: ")
                .append(malformedLines.size())
                .append("\n");

        // Flagged events grouped by rulebook severity
        java.util.Map<Integer, Integer> severityCounts =
                new java.util.TreeMap<>(java.util.Comparator.reverseOrder());

        for (LogEntry entry : result.getFlaggedEntries()) {
            int severity = rulebook.getSeverityScore(entry.getLevel());
            severityCounts.merge(severity, 1, Integer::sum);
        }

        report.append("\nFlagged Events by Severity\n");
        report.append("--------------------------\n");

        if (severityCounts.isEmpty()) {
            report.append("None found.\n");
        } else {
            for (java.util.Map.Entry<Integer, Integer> entry :
                    severityCounts.entrySet()) {
                int count = entry.getValue();

                report.append("Severity ")
                        .append(entry.getKey())
                        .append(": ")
                        .append(count)
                        .append(count == 1 ? " event\n" : " events\n");
            }
        }

        // Top five suspicious IPs by total log entries
        report.append("\nTop 5 Suspicious IPs\n");
        report.append("--------------------\n");

        if (result.getSuspiciousIps().isEmpty()) {
            report.append("None found.\n");
        } else {
            result.getSuspiciousIps().entrySet()
                    .stream()
                    .sorted(
                            Map.Entry.<String, Integer>comparingByValue()
                                    .reversed()
                                    .thenComparing(Map.Entry.comparingByKey())
                    )
                    .limit(5)
                    .forEach(entry ->
                            report.append(entry.getKey())
                                    .append(": ")
                                    .append(entry.getValue())
                                    .append(" total log entries\n")
                    );
        }

        // Activity Summary
        report.append("\nActivity Summary\n");
        report.append("================\n");

        for (Map.Entry<String, Integer> rule :
                rulebook.getRules().entrySet()) {

            String level = rule.getKey();
            int count = result.getActivitySummary()
                    .getOrDefault(level, 0);

            report.append(level)
                    .append(": ")
                    .append(count)
                    .append("\n");
        }

        if (rulebook.getRules().isEmpty()) {
            report.append("None found.\n");
        }

        // Flagged Entries
        report.append("\nFlagged Entries\n");
        report.append("===============\n");

        if (result.getFlaggedEntries().isEmpty()) {
            report.append("None found.\n");
        } else {
            for (LogEntry entry : result.getFlaggedEntries()) {
                report.append("Line ")
                        .append(entry.getLineNumber())
                        .append(": ")
                        .append(entry.getRawContent())
                        .append("\n");
            }
        }

        // Suspicious Activity by IP
        report.append("\nSuspicious Activity by IP\n");
        report.append("=========================\n");

        if (result.getSuspiciousIps().isEmpty()) {
            report.append("None found.\n");
        } else {
            for (Map.Entry<String, Integer> entry :
                    result.getSuspiciousIps().entrySet()) {

                report.append(entry.getKey())
                        .append(": ")
                        .append(entry.getValue())
                        .append(" total log entries")
                        .append("\n");
            }
        }

        // Suspicious IPs ranked by severity-weighted threat score
        report.append("\nSuspicious IP Threat Scores\n");
        report.append("===========================\n");

        if (result.getThreatScores().isEmpty()) {
            report.append("None found.\n");
        } else {
            result.getThreatScores().entrySet()
                    .stream()
                    .sorted(
                            Map.Entry.<String, Integer>comparingByValue()
                                    .reversed()
                                    .thenComparing(Map.Entry.comparingByKey())
                    )
                    .forEach(entry ->
                            report.append(entry.getKey())
                                    .append(": ")
                                    .append(entry.getValue())
                                    .append("\n")
                    );
        }

        // Unknown Patterns
        report.append("\nUnknown Patterns\n");
        report.append("================\n");

        if (result.getUnknownPatterns().isEmpty()) {
            report.append("None found.\n");
        } else {
            for (LogEntry entry : result.getUnknownPatterns()) {
                report.append("Line ")
                        .append(entry.getLineNumber())
                        .append(": ")
                        .append(entry.getRawContent())
                        .append("\n");
            }
        }

        // Malformed Lines
        report.append("\nMalformed Lines\n");
        report.append("===============\n");

        if (malformedLines.isEmpty()) {
            report.append("None found.\n");
        } else {
            for (MalformedLine line : malformedLines) {
                report.append("Line ")
                        .append(line.getLineNumber())
                        .append(": ")
                        .append(line.getRawContent())
                        .append("\n");
            }
        }

        Files.writeString(outputPath, report.toString());
    }
}
