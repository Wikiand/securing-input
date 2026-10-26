import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

class TraceFinderServerTest {

    private HttpServer server;
    private HttpClient client;
    private String baseUrl;

    @BeforeEach
    void setUp() throws Exception {
        server = TraceFinderServer.createServer(0);
        server.start();

        int port = server.getAddress().getPort();
        baseUrl = "http://127.0.0.1:" + port;
        client = HttpClient.newHttpClient();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void healthEndpointReturnsOk() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/health"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(200, response.statusCode());
        assertEquals(
                "{\"status\":\"ok\",\"service\":\"TraceFinder API\"}",
                response.body()
        );
        assertEquals(
                "application/json; charset=UTF-8",
                response.headers()
                        .firstValue("Content-Type")
                        .orElse("")
        );
    }

    @Test
    void analyzeEndpointReturnsThreatScores() throws Exception {
        String requestBody = """
                {
                  "logs": "2024-03-15 01:00:00 | ERROR | 192.168.1.10 | /admin | denied",
                  "rulebook": "level,severity_score\\nERROR,5\\n"
                }
                """;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/analyze"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = client.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(200, response.statusCode());

        com.fasterxml.jackson.databind.JsonNode json =
                new com.fasterxml.jackson.databind.ObjectMapper()
                        .readTree(response.body());

        assertEquals(
                5,
                json.get("threatScores").get("192.168.1.10").asInt()
        );
        assertEquals(
                "MEDIUM",
                json.get("riskLevels").get("192.168.1.10").asText()
        );
        assertEquals(1, json.get("flaggedEntries").size());
    }

    @Test
    void analyzeEndpointRejectsInvalidJson() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/analyze"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{invalid"))
                .build();

        HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(400, response.statusCode());
    }

    @Test
    void analyzeEndpointRejectsMissingFields() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/analyze"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        """
                        {"logs":"example"}
                        """
                ))
                .build();

        HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(400, response.statusCode());
    }

    @Test
    void analyzeEndpointRejectsUnsupportedContentType() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/analyze"))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("hello"))
                .build();

        HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(415, response.statusCode());
    }

    @Test
    void analyzeEndpointRejectsOversizedLogs() throws Exception {
        String oversizedLogs = "A".repeat(
                (int) InputLimits.MAX_LOG_FILE_BYTES + 1
        );

        String requestBody = new com.fasterxml.jackson.databind.ObjectMapper()
                .createObjectNode()
                .put("logs", oversizedLogs)
                .put("rulebook", "level,severity_score\\nERROR,5\\n")
                .toString();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/analyze"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = client.send(
                request, HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(413, response.statusCode());
    }

    @Test
    void healthEndpointRejectsPost() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/health"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> response = client.send(
                request,
                HttpResponse.BodyHandlers.ofString()
        );

        assertEquals(405, response.statusCode());
        assertEquals(
                "GET",
                response.headers()
                        .firstValue("Allow")
                        .orElse("")
        );
    }
}
