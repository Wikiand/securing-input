import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class TraceFinderAnalyzeHandler implements HttpHandler {

    private static final int MAX_REQUEST_BYTES = 12 * 1024 * 1024;
    private static final ObjectMapper MAPPER =
            new ObjectMapper().registerModule(new JavaTimeModule());

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "POST");
                send(exchange, 405, Map.of("error", "Method not allowed"));
                return;
            }

            String contentType = exchange.getRequestHeaders()
                    .getFirst("Content-Type");

            if (contentType == null
                    || !contentType.split(";", 2)[0].trim()
                            .equalsIgnoreCase("application/json")) {
                send(exchange, 415, Map.of("error", "Expected application/json"));
                return;
            }

            byte[] requestBytes;
            try {
                requestBytes = exchange.getRequestBody()
                        .readNBytes(MAX_REQUEST_BYTES + 1);
            } catch (IOException e) {
                send(exchange, 400, Map.of("error", "Could not read request"));
                return;
            }

            if (requestBytes.length > MAX_REQUEST_BYTES) {
                send(exchange, 413, Map.of("error", "Request too large"));
                return;
            }

            JsonNode input;
            try {
                input = MAPPER.readTree(requestBytes);
            } catch (IOException e) {
                send(exchange, 400, Map.of("error", "Invalid JSON"));
                return;
            }

            if (input == null
                    || !input.isObject()
                    || !input.path("logs").isTextual()
                    || !input.path("rulebook").isTextual()) {
                send(exchange, 400, Map.of(
                        "error", "logs and rulebook must be strings"));
                return;
            }

            byte[] logs = input.get("logs").asText()
                    .getBytes(StandardCharsets.UTF_8);
            byte[] rules = input.get("rulebook").asText()
                    .getBytes(StandardCharsets.UTF_8);

            if (logs.length > InputLimits.MAX_LOG_FILE_BYTES
                    || rules.length > InputLimits.MAX_RULEBOOK_FILE_BYTES) {
                send(exchange, 413, Map.of("error", "Input file too large"));
                return;
            }

            Path logFile = null;
            Path ruleFile = null;

            try {
                logFile = Files.createTempFile("tracefinder-log-", ".txt");
                ruleFile = Files.createTempFile("tracefinder-rules-", ".csv");

                Files.write(logFile, logs);
                Files.write(ruleFile, rules);

                Rulebook rulebook = new RulebookReader().read(ruleFile);
                LogReadResult logResult =
                        new LogReader(new Parser()).read(logFile);

                AnalysisResult result = new Analyzer().analyze(
                        logResult.getEntries(), rulebook);

                RiskThresholds thresholds = new RiskThresholds(5, 10);
                Map<String, String> riskLevels = new LinkedHashMap<>();

                result.getThreatScores().forEach((ip, score) ->
                        riskLevels.put(ip, thresholds.classify(score)));

                Map<String, Object> response = new LinkedHashMap<>();
                response.put("activitySummary", result.getActivitySummary());
                response.put("flaggedEntries", result.getFlaggedEntries());
                response.put("suspiciousIps", result.getSuspiciousIps());
                response.put("threatScores", result.getThreatScores());
                response.put("riskLevels", riskLevels);
                response.put("unknownPatterns", result.getUnknownPatterns());
                response.put("malformedLines", logResult.getMalformedLines());

                send(exchange, 200, response);

            } catch (TraceFinderFileException | RulebookException e) {
                send(exchange, 400, Map.of("error", e.getMessage()));
            } finally {
                if (logFile != null) {
                    Files.deleteIfExists(logFile);
                }
                if (ruleFile != null) {
                    Files.deleteIfExists(ruleFile);
                }
            }
        } finally {
            exchange.close();
        }
    }

    private static void send(
            HttpExchange exchange,
            int status,
            Object value) throws IOException {

        byte[] body = MAPPER.writeValueAsBytes(value);

        exchange.getResponseHeaders().set(
                "Content-Type", "application/json; charset=UTF-8");

        exchange.sendResponseHeaders(status, body.length);

        try (var output = exchange.getResponseBody()) {
            output.write(body);
        }
    }
}
