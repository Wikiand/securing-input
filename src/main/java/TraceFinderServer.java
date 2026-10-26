import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public final class TraceFinderServer {

    private TraceFinderServer() {
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = createServer(8080);
        server.start();

        System.out.println(
                "TraceFinder API running at http://127.0.0.1:8080"
        );
    }

    static HttpServer createServer(int port) throws IOException {
        HttpServer server = HttpServer.create(
                new InetSocketAddress("127.0.0.1", port),
                0
        );

        server.createContext("/api/health", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.getResponseHeaders().set(
                            "Allow", "GET"
                    );
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                byte[] response = (
                        "{\"status\":\"ok\","
                                + "\"service\":\"TraceFinder API\"}"
                ).getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set(
                        "Content-Type",
                        "application/json; charset=UTF-8"
                );

                exchange.sendResponseHeaders(200, response.length);

                try (var output = exchange.getResponseBody()) {
                    output.write(response);
                }
            } finally {
                exchange.close();
            }
        });

        server.createContext(
                "/api/analyze",
                new TraceFinderAnalyzeHandler()
        );

        server.createContext(
                "/",
                new TraceFinderStaticHandler()
        );

        return server;
    }
}
