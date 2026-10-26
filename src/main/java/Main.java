import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

public class Main {

    public static void main(String[] args) {
        int exitCode;

        try {
            exitCode = run(args);
        } catch (TraceFinderArgumentException
                 | TraceFinderFileException
                 | RulebookException e) {

            System.err.println("Error: " + e.getMessage());
            exitCode = 1;
        }

        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int run(String[] args)
            throws TraceFinderArgumentException,
                   TraceFinderFileException,
                   RulebookException {

        if (args.length != 3 && args.length != 5) {
            throw new TraceFinderArgumentException(
                    "Usage: java Main logs.txt rules.csv report.txt "
                            + "[start timestamp end timestamp | "
                            + "--risk-medium=N --risk-high=N]"
            );
        }

        Path logPath = Path.of(args[0]);
        Path rulebookPath = Path.of(args[1]);
        Path reportPath = Path.of(args[2]);

        LocalDateTime start = null;
        LocalDateTime end = null;
        RiskThresholds riskThresholds = new RiskThresholds(5, 10);
        boolean hasTimeWindow = false;

        if (args.length == 5) {
            boolean hasRiskOptions =
                    args[3].startsWith("--risk-")
                            || args[4].startsWith("--risk-");

            if (hasRiskOptions) {
                if (!args[3].startsWith("--risk-medium=")
                        || !args[4].startsWith("--risk-high=")) {
                    throw new TraceFinderArgumentException(
                            "Expected --risk-medium=N --risk-high=N"
                    );
                }

                try {
                    int medium = Integer.parseInt(
                            args[3].substring("--risk-medium=".length())
                    );
                    int high = Integer.parseInt(
                            args[4].substring("--risk-high=".length())
                    );
                    riskThresholds = new RiskThresholds(medium, high);
                } catch (IllegalArgumentException e) {
                    throw new TraceFinderArgumentException(
                            "Invalid risk thresholds: "
                                    + e.getMessage(),
                            e
                    );
                }
            } else {
                DateTimeFormatter formatter =
                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

                try {
                    start = LocalDateTime.parse(args[3], formatter);
                    end = LocalDateTime.parse(args[4], formatter);
                } catch (DateTimeParseException e) {
                    throw new TraceFinderArgumentException(
                            "Timestamps must use format yyyy-MM-dd HH:mm:ss",
                            e
                    );
                }

                if (start.isAfter(end)) {
                    throw new TraceFinderArgumentException(
                            "Start timestamp must not be after end timestamp"
                    );
                }

                hasTimeWindow = true;
            }
        }

        RulebookReader rulebookReader = new RulebookReader();
        Rulebook rulebook = rulebookReader.read(rulebookPath);

        LogReader logReader = new LogReader(new Parser());
        LogReadResult logResult = logReader.read(logPath);

        Analyzer analyzer = new Analyzer();
        AnalysisResult analysisResult;

        if (hasTimeWindow) {
            analysisResult = analyzer.analyze(
                    logResult.getEntries(),
                    rulebook,
                    start,
                    end
            );
        } else {
            analysisResult = analyzer.analyze(
                    logResult.getEntries(),
                    rulebook
            );
        }

        ReportWriter reportWriter = new ReportWriter(riskThresholds);

        try {
            reportWriter.write(
                    reportPath,
                    analysisResult,
                    rulebook,
                    logResult.getMalformedLines(),
                    start,
                    end
            );
        } catch (java.io.IOException e) {
            throw new TraceFinderFileException(
                    "Could not write report file '"
                            + reportPath
                            + "': "
                            + e.getMessage(),
                    e
            );
        }

        return 0;
    }
}