import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class TraceFinderStaticHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().set("Allow", "GET");
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String path = exchange.getRequestURI().getPath();
            String resource;
            String contentType;

            switch (path) {
                case "/", "/index.html" -> {
                    resource = "/web/index.html";
                    contentType = "text/html; charset=UTF-8";
                }
                case "/styles.css" -> {
                    resource = "/web/styles.css";
                    contentType = "text/css; charset=UTF-8";
                }
                case "/app.js" -> {
                    resource = "/web/app.js";
                    contentType = "text/javascript; charset=UTF-8";
                }
                default -> {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
            }

            try (InputStream input =
                    TraceFinderStaticHandler.class
                            .getResourceAsStream(resource)) {

                if (input == null) {
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }

                byte[] content = input.readAllBytes();

                exchange.getResponseHeaders().set(
                        "Content-Type", contentType
                );
                exchange.getResponseHeaders().set(
                        "X-Content-Type-Options", "nosniff"
                );

                exchange.sendResponseHeaders(200, content.length);

                try (OutputStream output =
                        exchange.getResponseBody()) {
                    output.write(content);
                }
            }
        } finally {
            exchange.close();
        }
    }
}
