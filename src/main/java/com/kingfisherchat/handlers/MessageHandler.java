package com.kingfisherchat.handlers;

import com.google.gson.Gson;
import com.kingfisherchat.MySqlConnection;
import com.kingfisherchat.utils.DatabaseUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

/**
 * Handles message-related HTTP endpoints.
 */
public class MessageHandler {
    
    /**
     * Handles loading messages for a direct chat.
     */
    public static void handleLoadMessages(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        int chatId = 0;
        int limit = 20;
        int offset = 0;

        if (query != null) {
            for (String param : query.split("&")) {
                String[] keyValue = param.split("=");
                if ("chatId".equals(keyValue[0])) {
                    chatId = Integer.parseInt(keyValue[1]);
                } else if ("limit".equals(keyValue[0])) {
                    limit = Integer.parseInt(keyValue[1]);
                } else if ("offset".equals(keyValue[0])) {
                    offset = Integer.parseInt(keyValue[1]);
                }
            }
        }

        String sql = "SELECT ZAK_MESSAGES.ID AS MESSAGE_ID, ZAK_USERS.USERNAME, ZAK_USERS.PROFILE_PICTURE, " +
                     "ZAK_MESSAGES.MESSAGE, ZAK_MESSAGES.MESSAGE_TYPE, ZAK_MESSAGES.TIMESTAMP " +
                     "FROM ZAK_MESSAGES " +
                     "INNER JOIN ZAK_USERS ON ZAK_MESSAGES.USER_ID = ZAK_USERS.ID " +
                     "WHERE ZAK_MESSAGES.CHAT_ID = ? " +
                     "ORDER BY ZAK_MESSAGES.TIMESTAMP DESC " +
                     "LIMIT ? OFFSET ?";
        List<Map<String, Object>> messages = new ArrayList<>();

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            stmt.setInt(1, chatId);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                String profilePicture = rs.getString("PROFILE_PICTURE");
                if (profilePicture == null || !new File("avatars" + profilePicture).exists()) {
                    profilePicture = "/static/avatars/default-avatar.png";
                }
        
                Map<String, Object> message = new HashMap<>();
                message.put("messageId", rs.getInt("MESSAGE_ID"));
                message.put("username", rs.getString("USERNAME"));
                message.put("profilePicture", profilePicture);
                message.put("message", rs.getString("MESSAGE"));
                message.put("messageType", rs.getString("MESSAGE_TYPE"));
                message.put("timestamp", rs.getTimestamp("TIMESTAMP").toString());
                messages.add(message);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
            return;
        }

        Gson gson = new Gson();
        String jsonResponse = gson.toJson(messages);

        exchange.getResponseHeaders().add("Content-Encoding", "gzip");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);

        try (OutputStream os = new java.util.zip.GZIPOutputStream(exchange.getResponseBody());
            Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
            writer.write(jsonResponse);
            writer.flush();
        }
    }
    
    /**
     * Handles loading messages for a group chat.
     */
    public static void handleLoadGroupMessages(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        int groupId = 0;
        int limit = 20;
        int offset = 0;

        if (query != null) {
            for (String param : query.split("&")) {
                String[] keyValue = param.split("=");
                if ("groupId".equals(keyValue[0])) {
                    groupId = Integer.parseInt(keyValue[1]);
                } else if ("limit".equals(keyValue[0])) {
                    limit = Integer.parseInt(keyValue[1]);
                } else if ("offset".equals(keyValue[0])) {
                    offset = Integer.parseInt(keyValue[1]);
                }
            }
        }

        String sql = "SELECT ZAK_MESSAGES.ID AS MESSAGE_ID, ZAK_USERS.USERNAME, ZAK_USERS.PROFILE_PICTURE, " +
                     "ZAK_MESSAGES.MESSAGE, ZAK_MESSAGES.MESSAGE_TYPE, ZAK_MESSAGES.TIMESTAMP " +
                     "FROM ZAK_MESSAGES " +
                     "INNER JOIN ZAK_USERS ON ZAK_MESSAGES.USER_ID = ZAK_USERS.ID " +
                     "WHERE ZAK_MESSAGES.GROUP_ID = ? " +
                     "ORDER BY ZAK_MESSAGES.TIMESTAMP DESC " +
                     "LIMIT ? OFFSET ?";
        List<Map<String, Object>> messages = new ArrayList<>();

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            stmt.setInt(1, groupId);
            stmt.setInt(2, limit);
            stmt.setInt(3, offset);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                String profilePicture = rs.getString("PROFILE_PICTURE");
                if (profilePicture == null || !new File("avatars" + profilePicture).exists()) {
                    profilePicture = "/static/avatars/default-avatar.png";
                }

                Map<String, Object> message = new HashMap<>();
                message.put("messageId", rs.getInt("MESSAGE_ID"));
                message.put("username", rs.getString("USERNAME"));
                message.put("profilePicture", profilePicture);
                message.put("message", rs.getString("MESSAGE"));
                message.put("messageType", rs.getString("MESSAGE_TYPE"));
                message.put("timestamp", rs.getTimestamp("TIMESTAMP").toString());
                messages.add(message);
            }
        }

        Gson gson = new Gson();
        String jsonResponse = gson.toJson(messages);

        exchange.getResponseHeaders().add("Content-Encoding", "gzip");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);

        try (OutputStream os = new java.util.zip.GZIPOutputStream(exchange.getResponseBody());
            Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
            writer.write(jsonResponse);
            writer.flush();
        }
    }
    
    /**
     * Handles deleting a message.
     */
    public static void handleDeleteMessage(HttpExchange exchange) throws Exception {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
        StringBuilder requestBody = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            requestBody.append(line);
        }

        System.out.println("Received deleteMessage request: " + requestBody);

        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);

        if (!requestData.containsKey("messageId") || requestData.get("messageId") == null) {
            System.out.println("Missing or null messageId in request: " + requestBody);
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        int messageId;
        try {
            messageId = ((Double) requestData.get("messageId")).intValue();
        } catch (ClassCastException | NullPointerException e) {
            System.out.println("Invalid messageId format in request: " + requestBody);
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        String deleteMessageSql = "DELETE FROM ZAK_MESSAGES WHERE ID = ?";
        try (Connection connection = MySqlConnection.getConnection();
            PreparedStatement stmt = connection.prepareStatement(deleteMessageSql)) {

            stmt.setInt(1, messageId);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                exchange.sendResponseHeaders(200, -1);
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
        }
    }
    
    /**
     * Handles marking messages as read.
     */
    public static void handleMarkMessagesAsRead(HttpExchange exchange) throws Exception {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
        StringBuilder requestBody = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            requestBody.append(line);
            System.out.println("Reading line: " + line);
        }

        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
        int id = ((Double) requestData.get("id")).intValue();
        Boolean isGroupBoolean = (Boolean) requestData.get("isGroup");
        boolean isGroup = Optional.ofNullable(isGroupBoolean).orElse(false);

        int userId = getUserIdFromSession(exchange);

        String sql = isGroup
            ? "INSERT IGNORE INTO ZAK_MESSAGE_READ (MESSAGE_ID, USER_ID) SELECT ID, ? FROM ZAK_MESSAGES WHERE GROUP_ID = ?"
            : "INSERT IGNORE INTO ZAK_MESSAGE_READ (MESSAGE_ID, USER_ID) SELECT ID, ? FROM ZAK_MESSAGES WHERE CHAT_ID = ?";

        try (Connection connection = MySqlConnection.getConnection();
            PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        }

        exchange.sendResponseHeaders(200, -1);
    }
    
    private static int getUserIdFromSession(HttpExchange exchange) throws SQLException {
        String sessionId = exchange.getRequestHeaders().getFirst("Session-Id");
        System.out.println("Received Session-Id: " + sessionId);

        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("Session ID is missing in the request headers");
        }

        String username = com.kingfisherchat.SessionManager.getUsername(sessionId);
        if (username == null) {
            throw new IllegalArgumentException("Invalid session ID or user not authenticated");
        }

        return DatabaseUtils.getIdFromUsername(username);
    }
}

