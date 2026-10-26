import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class RiskThresholdsTest {

    @Test
    void defaultThresholdsClassifyCorrectly() {
        RiskThresholds thresholds = new RiskThresholds(5, 10);

        assertEquals("LOW", thresholds.classify(4));
        assertEquals("MEDIUM", thresholds.classify(5));
        assertEquals("MEDIUM", thresholds.classify(9));
        assertEquals("HIGH", thresholds.classify(10));
    }

    @Test
    void customThresholdsClassifyCorrectly() {
        RiskThresholds thresholds = new RiskThresholds(8, 15);

        assertEquals("LOW", thresholds.classify(7));
        assertEquals("MEDIUM", thresholds.classify(8));
        assertEquals("MEDIUM", thresholds.classify(14));
        assertEquals("HIGH", thresholds.classify(15));
    }

    @Test
    void rejectsInvalidThresholds() {
        assertThrows(IllegalArgumentException.class,
                () -> new RiskThresholds(0, 10));

        assertThrows(IllegalArgumentException.class,
                () -> new RiskThresholds(-1, 10));

        assertThrows(IllegalArgumentException.class,
                () -> new RiskThresholds(10, 10));

        assertThrows(IllegalArgumentException.class,
                () -> new RiskThresholds(15, 10));
    }
}
