package com.kingfisherchat.handlers;

import com.google.gson.Gson;
import com.kingfisherchat.MySqlConnection;
import com.kingfisherchat.utils.DatabaseUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.*;
import java.util.*;

/**
 * Handles group chat-related HTTP endpoints.
 */
public class GroupHandler {
    
    /**
     * Handles creating a new group chat.
     */
    public static void handleCreateGroupChat(HttpExchange exchange) throws Exception {
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

        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
        String groupName = (String) requestData.get("name");
        List<?> rawMemberUsernames = (List<?>) requestData.get("members");
        int createdBy = getUserIdFromSession(exchange);

        System.out.println("Group Name: " + groupName);
        System.out.println("Raw Member Usernames: " + rawMemberUsernames);

        if (groupName == null || rawMemberUsernames == null || rawMemberUsernames.isEmpty()) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        List<Integer> memberIds = new ArrayList<>();
        for (Object rawUsername : rawMemberUsernames) {
            try {
                int userId = DatabaseUtils.getIdFromUsername(rawUsername.toString());
                if (userId != -1) {
                    memberIds.add(userId);
                } else {
                    System.out.println("Invalid username: " + rawUsername);
                }
            } catch (Exception e) {
                System.out.println("Error parsing username: " + rawUsername);
                e.printStackTrace();
            }
        }

        if (!memberIds.contains(createdBy)) {
            memberIds.add(createdBy);
        }

        System.out.println("Final Member IDs: " + memberIds);

        String insertGroupSql = "INSERT INTO ZAK_GROUP_CHATS (NAME, CREATED_BY) VALUES (?, ?)";
        int groupId;
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(insertGroupSql, PreparedStatement.RETURN_GENERATED_KEYS)) {

            stmt.setString(1, groupName);
            stmt.setInt(2, createdBy);
            stmt.executeUpdate();

            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) {
                groupId = rs.getInt(1);
            } else {
                exchange.sendResponseHeaders(500, -1);
                return;
            }
        }

        String insertMembersSql = "INSERT INTO ZAK_GROUP_MEMBERS (GROUP_ID, USER_ID) VALUES (?, ?)";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(insertMembersSql)) {

            for (Integer memberId : memberIds) {
                stmt.setInt(1, groupId);
                stmt.setInt(2, memberId);
                stmt.addBatch();
            }
            stmt.executeBatch();
        }

        String response = String.format("{\"groupId\": %d}", groupId);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length());
        exchange.getResponseBody().write(response.getBytes());
        exchange.getResponseBody().close();
    }
    
    /**
     * Handles getting group information.
     */
    public static void handleGetGroupInfo(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }
        String query = exchange.getRequestURI().getQuery();
        int groupId = -1;
        if (query != null) {
            for (String param : query.split("&")) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2 && "groupId".equals(keyValue[0])) {
                    groupId = Integer.parseInt(keyValue[1]);
                }
            }
        }
        if (groupId == -1) {
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        String groupSql = "SELECT NAME, CREATED_BY FROM ZAK_GROUP_CHATS WHERE ID = ?";
        String groupName = null;
        int ownerId = -1;
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(groupSql)) {
            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                groupName = rs.getString("NAME");
                ownerId = rs.getInt("CREATED_BY");
            }
        }
        if (groupName == null) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }

        String ownerUsername = null;
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement("SELECT USERNAME FROM ZAK_USERS WHERE ID = ?")) {
            stmt.setInt(1, ownerId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                ownerUsername = rs.getString("USERNAME");
            }
        }

        String membersSql = "SELECT U.USERNAME FROM ZAK_GROUP_MEMBERS GM INNER JOIN ZAK_USERS U ON GM.USER_ID = U.ID WHERE GM.GROUP_ID = ?";
        List<Map<String, String>> members = new ArrayList<>();
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(membersSql)) {
            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Map<String, String> member = new HashMap<>();
                member.put("username", rs.getString("USERNAME"));
                members.add(member);
            }
        }

        Map<String, Object> response = new HashMap<>();
        response.put("name", groupName);
        response.put("owner", ownerUsername);
        response.put("members", members);

        String json = new Gson().toJson(response);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, json.getBytes().length);
        exchange.getResponseBody().write(json.getBytes());
        exchange.getResponseBody().close();
    }
    
    /**
     * Handles adding a member to a group.
     */
    public static void handleAddGroupMember(HttpExchange exchange) throws Exception {
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
        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
        int groupId = ((Double) requestData.get("groupId")).intValue();
        String username = (String) requestData.get("username");

        int sessionUserId = getUserIdFromSession(exchange);

        String ownerSql = "SELECT CREATED_BY FROM ZAK_GROUP_CHATS WHERE ID = ?";
        int ownerId = -1;
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(ownerSql)) {
            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) ownerId = rs.getInt("CREATED_BY");
        }
        if (sessionUserId != ownerId) {
            exchange.sendResponseHeaders(403, -1);
            return;
        }

        int userId = DatabaseUtils.getIdFromUsername(username);
        if (userId == -1) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        String addSql = "INSERT IGNORE INTO ZAK_GROUP_MEMBERS (GROUP_ID, USER_ID) VALUES (?, ?)";
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(addSql)) {
            stmt.setInt(1, groupId);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
        exchange.sendResponseHeaders(200, -1);
    }
    
    /**
     * Handles removing a member from a group.
     */
    public static void handleRemoveGroupMember(HttpExchange exchange) throws Exception {
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
        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
        int groupId = ((Double) requestData.get("groupId")).intValue();
        String username = (String) requestData.get("username");

        int sessionUserId = getUserIdFromSession(exchange);
        int userId = DatabaseUtils.getIdFromUsername(username);

        String ownerSql = "SELECT CREATED_BY FROM ZAK_GROUP_CHATS WHERE ID = ?";
        int ownerId = -1;
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(ownerSql)) {
            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) ownerId = rs.getInt("CREATED_BY");
        }
        if (sessionUserId != ownerId && sessionUserId != userId) {
            exchange.sendResponseHeaders(403, -1);
            return;
        }

        if (userId == -1) {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        String removeSql = "DELETE FROM ZAK_GROUP_MEMBERS WHERE GROUP_ID = ? AND USER_ID = ?";
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(removeSql)) {
            stmt.setInt(1, groupId);
            stmt.setInt(2, userId);
            stmt.executeUpdate();
        }
        exchange.sendResponseHeaders(200, -1);
    }
    
    /**
     * Handles renaming a group.
     */
    public static void handleRenameGroup(HttpExchange exchange) throws Exception {
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
        Gson gson = new Gson();
        Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
        int groupId = ((Double) requestData.get("groupId")).intValue();
        String newName = (String) requestData.get("newName");

        int sessionUserId = getUserIdFromSession(exchange);
        String ownerSql = "SELECT CREATED_BY FROM ZAK_GROUP_CHATS WHERE ID = ?";
        int ownerId = -1;
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(ownerSql)) {
            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) ownerId = rs.getInt("CREATED_BY");
        }
        if (sessionUserId != ownerId) {
            exchange.sendResponseHeaders(403, -1);
            return;
        }

        String updateSql = "UPDATE ZAK_GROUP_CHATS SET NAME = ? WHERE ID = ?";
        try (Connection conn = MySqlConnection.getConnection();
            PreparedStatement stmt = conn.prepareStatement(updateSql)) {
            stmt.setString(1, newName);
            stmt.setInt(2, groupId);
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

