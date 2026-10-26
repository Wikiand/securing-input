public final class RiskThresholds {

    private final int medium;
    private final int high;

    public RiskThresholds(int medium, int high) {
        if (medium <= 0 || high <= medium) {
            throw new IllegalArgumentException(
                    "Risk thresholds must satisfy 0 < medium < high"
            );
        }

        this.medium = medium;
        this.high = high;
    }

    public String classify(int score) {
        if (score >= high) {
            return "HIGH";
        }
        if (score >= medium) {
            return "MEDIUM";
        }
        return "LOW";
    }
}
