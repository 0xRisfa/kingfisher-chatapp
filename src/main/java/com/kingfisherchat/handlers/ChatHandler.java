package com.kingfisherchat.handlers;

import com.google.gson.Gson;
import com.kingfisherchat.MySqlConnection;
import com.kingfisherchat.utils.DatabaseUtils;
import com.kingfisherchat.utils.HttpUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.*;
import java.util.*;

/**
 * Handles chat-related HTTP endpoints.
 */
public class ChatHandler {
    
    /**
     * Handles loading all chats (DMs and groups) for a user.
     */
    public static void handleLoadChats(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String username = exchange.getRequestHeaders().getFirst("Username");
        if (username == null || username.isEmpty()) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        int userId = DatabaseUtils.getIdFromUsername(username);

        String dmSql = "SELECT dm.chat_id AS id, " +
                    "CASE WHEN dm.user1_id = ? THEN u2.USERNAME ELSE u1.USERNAME END AS name, " +
                    "(SELECT MAX(m.TIMESTAMP) FROM ZAK_MESSAGES m WHERE m.CHAT_ID = dm.chat_id) AS last_message_time, " +
                    "(SELECT COUNT(*) FROM ZAK_MESSAGES m " +
                    "WHERE m.CHAT_ID = dm.chat_id AND m.USER_ID != ? " +
                    "AND NOT EXISTS (SELECT 1 FROM ZAK_MESSAGE_READ r WHERE r.MESSAGE_ID = m.ID AND r.USER_ID = ?)) AS unread_count," +
                    "'dm' AS type " +
                    "FROM ZAK_DIRECT_MESSAGES dm " +
                    "INNER JOIN ZAK_USERS u1 ON dm.user1_id = u1.ID " +
                    "INNER JOIN ZAK_USERS u2 ON dm.user2_id = u2.ID " +
                    "WHERE dm.user1_id = ? OR dm.user2_id = ?";

        String groupSql = "SELECT gc.ID AS id, gc.NAME AS name, " +
                        "(SELECT MAX(m.TIMESTAMP) FROM ZAK_MESSAGES m WHERE m.GROUP_ID = gc.ID) AS last_message_time, " +
                        "(SELECT COUNT(*) FROM ZAK_MESSAGES m " +
                        "WHERE m.GROUP_ID = gc.ID AND m.USER_ID != ? " +
                        "AND NOT EXISTS (SELECT 1 FROM ZAK_MESSAGE_READ r WHERE r.MESSAGE_ID = m.ID AND r.USER_ID = ?)) AS unread_count," +
                        "'group' AS type " +
                        "FROM ZAK_GROUP_CHATS gc " +
                        "INNER JOIN ZAK_GROUP_MEMBERS gm ON gc.ID = gm.GROUP_ID " +
                        "WHERE gm.USER_ID = ?";

        List<Map<String, Object>> chats = new ArrayList<>();

        try (Connection connection = MySqlConnection.getConnection()) {
            // Fetch DMs
            try (PreparedStatement stmt = connection.prepareStatement(dmSql)) {
                stmt.setInt(1, userId);
                stmt.setInt(2, userId);
                stmt.setInt(3, userId);
                stmt.setInt(4, userId);
                stmt.setInt(5, userId);
                ResultSet rs = stmt.executeQuery();

                while (rs.next()) {
                    Map<String, Object> chat = new HashMap<>();
                    chat.put("id", rs.getInt("id"));
                    chat.put("name", rs.getString("name"));
                    chat.put("lastMessageTime", rs.getTimestamp("last_message_time") != null ? rs.getTimestamp("last_message_time").toString() : null);
                    chat.put("unreadCount", rs.getInt("unread_count"));
                    chat.put("type", rs.getString("type"));
                    chats.add(chat);
                }
            }

            // Fetch group chats
            try (PreparedStatement stmt = connection.prepareStatement(groupSql)) {
                stmt.setInt(1, userId);
                stmt.setInt(2, userId);
                stmt.setInt(3, userId);
                ResultSet rs = stmt.executeQuery();

                while (rs.next()) {
                    Map<String, Object> chat = new HashMap<>();
                    chat.put("id", rs.getInt("id"));
                    chat.put("name", rs.getString("name"));
                    chat.put("lastMessageTime", rs.getTimestamp("last_message_time") != null ? rs.getTimestamp("last_message_time").toString() : null);
                    chat.put("unreadCount", rs.getInt("unread_count"));
                    chat.put("type", rs.getString("type"));
                    chats.add(chat);
                }
            }
        }

        // Sort by lastMessageTime in descending order
        chats.sort((c1, c2) -> {
            String time1 = (String) c1.get("lastMessageTime");
            String time2 = (String) c2.get("lastMessageTime");
            if (time1 == null && time2 == null) return 0;
            if (time1 == null) return 1;
            if (time2 == null) return -1;
            return time2.compareTo(time1);
        });

        Gson gson = new Gson();
        String jsonResponse = gson.toJson(chats);

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.getResponseHeaders().add("Content-Encoding", "gzip");
        exchange.sendResponseHeaders(200, 0);

        try (java.io.OutputStream os = new java.util.zip.GZIPOutputStream(exchange.getResponseBody());
            java.io.Writer writer = new java.io.OutputStreamWriter(os, java.nio.charset.StandardCharsets.UTF_8)) {
            writer.write(jsonResponse);
            writer.flush();
        }
    }
    
    /**
     * Handles starting a new chat with another user.
     */
    public static void handleStartChat(HttpExchange exchange) throws Exception {
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
    
            Map<String, String> requestData = HttpUtils.parseJson(requestBody.toString());
            String username = requestData.get("username");
            String otherUsername = requestData.get("otherUsername");
    
            if (username == null || otherUsername == null) {
                exchange.sendResponseHeaders(400, -1);
                return;
            }
    
            int userId = -1, otherUserId = -1;
            String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
            try (Connection connection = MySqlConnection.getConnection();
                 PreparedStatement stmt = connection.prepareStatement(getUserIdSql)) {
    
                stmt.setString(1, username);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) userId = rs.getInt("ID");
    
                stmt.setString(1, otherUsername);
                rs = stmt.executeQuery();
                if (rs.next()) otherUserId = rs.getInt("ID");
            }
    
            if (userId == -1 || otherUserId == -1) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
    
            // Check if chat already exists
            String checkChatSql = "SELECT chat_id FROM ZAK_DIRECT_MESSAGES WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)";
            int chatId = -1;
            try (Connection connection = MySqlConnection.getConnection();
                 PreparedStatement stmt = connection.prepareStatement(checkChatSql)) {
    
                stmt.setInt(1, userId);
                stmt.setInt(2, otherUserId);
                stmt.setInt(3, otherUserId);
                stmt.setInt(4, userId);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) chatId = rs.getInt("chat_id");
            }
    
            // Create a new chat if it doesn't exist
            if (chatId == -1) {
                String createChatSql = "INSERT INTO ZAK_DIRECT_MESSAGES (user1_id, user2_id) VALUES (?, ?)";
                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(createChatSql, PreparedStatement.RETURN_GENERATED_KEYS)) {
    
                    stmt.setInt(1, userId);
                    stmt.setInt(2, otherUserId);
                    stmt.executeUpdate();
                    ResultSet rs = stmt.getGeneratedKeys();
                    if (rs.next()) chatId = rs.getInt(1);
                }
            }
    
            String response = String.format("{\"chatId\": %d}", chatId);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        }
    }
}

