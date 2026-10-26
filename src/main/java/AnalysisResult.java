import java.util.List;
import java.util.Map;

public class AnalysisResult {

    private final Map<String, Integer> activitySummary;
    private final List<LogEntry> flaggedEntries;
    private final Map<String, Integer> suspiciousIps;
    private final Map<String, Integer> threatScores;
    private final List<LogEntry> unknownPatterns;

    public AnalysisResult(
            Map<String, Integer> activitySummary,
            List<LogEntry> flaggedEntries,
            Map<String, Integer> suspiciousIps,
            List<LogEntry> unknownPatterns) {

        this(activitySummary, flaggedEntries, suspiciousIps,
                unknownPatterns, java.util.Map.of());
    }

    public AnalysisResult(
            Map<String, Integer> activitySummary,
            List<LogEntry> flaggedEntries,
            Map<String, Integer> suspiciousIps,
            List<LogEntry> unknownPatterns,
            Map<String, Integer> threatScores) {

        this.activitySummary = activitySummary;
        this.flaggedEntries = flaggedEntries;
        this.suspiciousIps = suspiciousIps;
        this.threatScores = threatScores;
        this.unknownPatterns = unknownPatterns;
    }

    public Map<String, Integer> getActivitySummary() {
        return activitySummary;
    }

    public List<LogEntry> getFlaggedEntries() {
        return flaggedEntries;
    }

    public Map<String, Integer> getSuspiciousIps() {
        return suspiciousIps;
    }

    public Map<String, Integer> getThreatScores() {
        return threatScores;
    }

    public List<LogEntry> getUnknownPatterns() {
        return unknownPatterns;
    }
}