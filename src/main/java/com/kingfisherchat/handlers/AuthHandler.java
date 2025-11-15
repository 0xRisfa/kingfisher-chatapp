package com.kingfisherchat.handlers;

import com.kingfisherchat.SessionManager;
import com.kingfisherchat.UserAuthentication;
import com.kingfisherchat.utils.HttpUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

/**
 * Handles authentication-related HTTP endpoints.
 */
public class AuthHandler {
    
    /**
     * Handles login requests.
     */
    public static void handleLogin(HttpExchange exchange) throws Exception {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()))) {
            StringBuilder requestBody = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }

            System.out.println("Raw received data: " + requestBody.toString());

            Map<String, String> requestData = HttpUtils.parseJson(requestBody.toString());
            String username = requestData.get("username");
            String password = requestData.get("password");
            String sessionId = requestData.get("sessionId");
            
            System.out.println("Parsed Username: " + username);
            System.out.println("Parsed Password: " + password);

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

            if (UserAuthentication.login(username, password)) {
                SessionManager.authenticateSession(sessionId, username);
                String response = "{\"success\": true}";
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                System.out.println("Login SUCCESS for user: " + username + " with session ID: " + sessionId);
            } else {
                String response = "{\"success\": false, \"error\": \"Invalid credentials\"}";
                exchange.sendResponseHeaders(401, response.length());
                exchange.getResponseBody().write(response.getBytes());
                System.out.println("Login FAILED for user: " + username);
            }

            exchange.getResponseBody().close();
        }
    }
    
    /**
     * Handles registration requests.
     */
    public static void handleRegister(HttpExchange exchange) throws Exception {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()))) {
            StringBuilder requestBody = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                requestBody.append(line);
            }

            System.out.println("Raw received data: " + requestBody.toString());

            Map<String, String> requestData = HttpUtils.parseJson(requestBody.toString());
            String username = requestData.get("username");
            String password = requestData.get("password");

            System.out.println("Parsed Username: " + username);
            System.out.println("Parsed Password: " + password);

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

            if (UserAuthentication.registerUser(username, password)) {
                String response = "{\"success\": true}";
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                System.out.println("Registration SUCCESS for user: " + username);
            } else {
                String response = "{\"success\": false, \"error\": \"Registration failed\"}";
                exchange.sendResponseHeaders(400, response.length());
                exchange.getResponseBody().write(response.getBytes());
                System.out.println("Registration FAILED for user: " + username);
            }

            exchange.getResponseBody().close();
        }
    }
}

