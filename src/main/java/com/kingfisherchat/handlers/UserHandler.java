package com.kingfisherchat.handlers;

import com.google.gson.Gson;
import com.kingfisherchat.MySqlConnection;
import com.sun.net.httpserver.HttpExchange;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

/**
 * Handles user-related HTTP endpoints.
 */
public class UserHandler {
    
    /**
     * Handles searching for users.
     */
    public static void handleSearchUsers(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String searchTerm = "";

        if (query != null) {
            for (String param : query.split("&")) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2 && "q".equals(keyValue[0])) {
                    searchTerm = keyValue[1];
                }
            }
        }

        String sql = "SELECT ID, USERNAME FROM ZAK_USERS WHERE USERNAME LIKE ? LIMIT 10";
        List<Map<String, Object>> users = new ArrayList<>();

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            stmt.setString(1, "%" + searchTerm + "%");
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", rs.getInt("ID"));
                user.put("username", rs.getString("USERNAME"));
                users.add(user);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            exchange.sendResponseHeaders(500, -1);
            return;
        }

        Gson gson = new Gson();
        String jsonResponse = gson.toJson(users);

        exchange.getResponseHeaders().add("Content-Encoding", "gzip");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, 0);

        try (OutputStream os = new java.util.zip.GZIPOutputStream(exchange.getResponseBody());
            Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
            writer.write(jsonResponse);
            writer.flush();
        }
    }
}

