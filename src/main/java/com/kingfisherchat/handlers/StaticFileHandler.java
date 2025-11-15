package com.kingfisherchat.handlers;

import com.kingfisherchat.utils.HttpUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.File;
import java.nio.file.Files;

/**
 * Handles serving static files.
 */
public class StaticFileHandler {
    
    /**
     * Serves a static file.
     */
    public static void serveFile(HttpExchange exchange, String filePath, String contentType) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        File file = new File(filePath);
        if (!file.exists()) {
            System.out.println("File not found: " + filePath);
            exchange.sendResponseHeaders(404, -1);
            return;
        }

        exchange.getResponseHeaders().add("Content-Type", contentType);
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        exchange.sendResponseHeaders(200, fileBytes.length);
        exchange.getResponseBody().write(fileBytes);
        exchange.getResponseBody().close();
    }
    
    /**
     * Handles the root context (index.html).
     */
    public static void handleRoot(HttpExchange exchange) throws Exception {
        serveFile(exchange, "src/main/resources/index.html", "text/html");
    }
    
    /**
     * Handles chat.html.
     */
    public static void handleChatHtml(HttpExchange exchange) throws Exception {
        serveFile(exchange, "src/main/resources/chat.html", "text/html");
    }
    
    /**
     * Handles register.html.
     */
    public static void handleRegisterHtml(HttpExchange exchange) throws Exception {
        serveFile(exchange, "src/main/resources/register.html", "text/html");
    }
    
    /**
     * Handles config.json.
     */
    public static void handleConfigJson(HttpExchange exchange) throws Exception {
        serveFile(exchange, "src/main/resources/config.json", "application/json");
    }
    
    /**
     * Handles static file requests.
     */
    public static void handleStaticFiles(HttpExchange exchange) throws Exception {
        try {
            String path = exchange.getRequestURI().getPath().replaceFirst("/static", "");
            System.out.println("Requested Static File Path: " + path);
    
            File file;
    
            if (path.startsWith("/avatars")) {
                file = new File("avatars" + path.replaceFirst("/avatars", ""));
            } else if (path.startsWith("/uploads")) {
                file = new File("uploads" + path.replaceFirst("/uploads", ""));
            } else {
                file = new File("src/main/resources" + path);
            }
    
            if (!file.exists() || file.isDirectory()) {
                System.out.println("File not found: " + file.getAbsolutePath());
                exchange.sendResponseHeaders(404, -1);
                return;
            }
    
            String mimeType = HttpUtils.getMimeType(path);
            exchange.getResponseHeaders().add("Content-Type", mimeType);
    
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            exchange.sendResponseHeaders(200, fileBytes.length);
            exchange.getResponseBody().write(fileBytes);
            exchange.getResponseBody().close();
        } catch (Exception e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
        }
    }
}

