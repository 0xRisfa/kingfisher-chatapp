package com.kingfisherchat.handlers;

import com.kingfisherchat.MySqlConnection;
import com.kingfisherchat.SessionManager;
import com.kingfisherchat.UserAuthentication;
import com.kingfisherchat.utils.DatabaseUtils;
import com.kingfisherchat.utils.MultipartUtils;
import com.sun.net.httpserver.HttpExchange;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;

/**
 * Handles file upload and profile-related HTTP endpoints.
 */
public class FileHandler {
    
    /**
     * Handles file uploads.
     */
    public static void handleUpload(HttpExchange exchange) throws Exception {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.startsWith("multipart/form-data")) {
            System.out.println("Unsupported Content-Type: " + contentType);
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        try (InputStream inputStream = exchange.getRequestBody()) {
            String boundary = contentType.split("boundary=")[1];
            if (boundary == null) {
                System.out.println("Boundary not found in Content-Type");
                exchange.sendResponseHeaders(400, -1);
                return;
            }
            boundary = "--" + boundary;

            byte[] body = inputStream.readAllBytes();
            int boundaryLength = boundary.getBytes(StandardCharsets.UTF_8).length;
            int currentIndex = 0;

            while (currentIndex < body.length) {
                int nextBoundaryIndex = MultipartUtils.locateBoundary(body, currentIndex, boundary);
                if (nextBoundaryIndex == -1) break;

                byte[] part = Arrays.copyOfRange(body, currentIndex, nextBoundaryIndex);
                currentIndex = nextBoundaryIndex + boundaryLength;

                String partHeaders = MultipartUtils.extractHeaders(part);
                if (partHeaders.contains("Content-Disposition") && partHeaders.contains("filename=\"")) {
                    String fileName = UUID.randomUUID().toString();
                    String fileExtension = "";

                    if (partHeaders.contains("filename=\"")) {
                        String originalFileName = partHeaders.split("filename=\"")[1].split("\"")[0];
                        if (originalFileName.contains(".")) {
                            fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
                        }
                    }

                    byte[] fileContent = MultipartUtils.extractFileContent(part);

                    File file = new File("uploads/" + fileName + fileExtension);
                    file.getParentFile().mkdirs();
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        outputStream.write(fileContent);
                    }

                    System.out.println("File saved: " + file.getAbsolutePath() + " (" + file.length() + " bytes)");

                    String fileUrl = "/static/uploads/" + fileName + fileExtension;
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    String response = "{\"success\": true, \"fileUrl\": \"" + fileUrl + "\"}";
                    exchange.sendResponseHeaders(200, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.getResponseBody().close();
                    return;
                }
            }

            System.out.println("No file uploaded");
            exchange.sendResponseHeaders(400, -1);
        }
    }
    
    /**
     * Handles profile picture retrieval.
     */
    public static void handleGetProfilePicture(HttpExchange exchange) throws Exception {
        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String username = null;
        if (query != null) {
            for (String param : query.split("&")) {
                String[] keyValue = param.split("=");
                if ("username".equals(keyValue[0])) {
                    username = keyValue[1];
                }
            }
        }

        if (username == null || username.isEmpty()) {
            System.out.println("Username is missing in the request.");
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        String sql = "SELECT PROFILE_PICTURE FROM ZAK_USERS WHERE USERNAME = ?";
        String profilePicture = null;

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                profilePicture = rs.getString("PROFILE_PICTURE");
                System.out.println("Fetched profile picture for " + username + ": " + profilePicture);
            }
        }

        if (profilePicture == null || profilePicture.isEmpty()) {
            profilePicture = "/static/avatars/default-avatar.png";
            System.out.println("Using default avatar for " + username);
        }

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        String response = String.format("{\"profilePicture\": \"%s\"}", profilePicture);
        exchange.sendResponseHeaders(200, response.length());
        exchange.getResponseBody().write(response.getBytes());
        exchange.getResponseBody().close();
    }
    
    /**
     * Handles profile updates.
     */
    public static void handleUpdateProfile(HttpExchange exchange) throws Exception {
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.startsWith("multipart/form-data")) {
            System.out.println("Unsupported Content-Type: " + contentType);
            exchange.sendResponseHeaders(400, -1);
            return;
        }

        InputStream inputStream = exchange.getRequestBody();
        String boundary = contentType.split("boundary=")[1];
        if (boundary == null) {
            System.out.println("Boundary not found in Content-Type");
            exchange.sendResponseHeaders(400, -1);
            return;
        }
        boundary = "--" + boundary;

        byte[] body = inputStream.readAllBytes();
        int boundaryLength = boundary.getBytes(StandardCharsets.UTF_8).length;
        int currentIndex = 0;

        String username = null;
        String oldPassword = null;
        String newPassword = null;
        String profilePicPath = null;
        boolean removeProfilePic = false;

        while (currentIndex < body.length) {
            int nextBoundaryIndex = MultipartUtils.locateBoundary(body, currentIndex, boundary);
            if (nextBoundaryIndex == -1) break;

            byte[] part = Arrays.copyOfRange(body, currentIndex, nextBoundaryIndex);
            currentIndex = nextBoundaryIndex + boundaryLength;

            String partHeaders = MultipartUtils.extractHeaders(part);
            if (partHeaders.contains("Content-Disposition")) {
                if (partHeaders.contains("name=\"username\"")) {
                    username = new String(MultipartUtils.extractFileContent(part), StandardCharsets.UTF_8).trim();
                } else if (partHeaders.contains("name=\"oldPassword\"")) {
                    oldPassword = new String(MultipartUtils.extractFileContent(part), StandardCharsets.UTF_8).trim();
                } else if (partHeaders.contains("name=\"newPassword\"")) {
                    newPassword = new String(MultipartUtils.extractFileContent(part), StandardCharsets.UTF_8).trim();
                } else if (partHeaders.contains("name=\"profilePic\"") && partHeaders.contains("filename=\"")) {
                    String fileName = UUID.randomUUID().toString();
                    String fileExtension = "";

                    if (partHeaders.contains("filename=\"")) {
                        String originalFileName = partHeaders.split("filename=\"")[1].split("\"")[0];
                        if (originalFileName.contains(".")) {
                            fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
                        }
                    }

                    byte[] fileContent = MultipartUtils.extractFileContent(part);
                    File file = new File("avatars/" + fileName + fileExtension);
                    file.getParentFile().mkdirs();
                    try (FileOutputStream outputStream = new FileOutputStream(file)) {
                        outputStream.write(fileContent);
                    }

                    profilePicPath = "/static/avatars/" + fileName + fileExtension;
                } else if (partHeaders.contains("name=\"removeProfilePic\"")) {
                    removeProfilePic = Boolean.parseBoolean(new String(MultipartUtils.extractFileContent(part), StandardCharsets.UTF_8).trim());
                }
            }
        }

        // Validate old password if a new password is provided
        if (newPassword != null) {
            if (!UserAuthentication.isPasswordStrong(newPassword)) {
                exchange.sendResponseHeaders(400, -1);
                System.out.println("New password does not meet strength requirements.");
                return;
            }

            String sql = "SELECT PASSWORD FROM ZAK_USERS WHERE ID = ?";
            try (Connection connection = MySqlConnection.getConnection();
                 PreparedStatement stmt = connection.prepareStatement(sql)) {

                stmt.setInt(1, getUserIdFromSession(exchange));
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    String storedPassword = rs.getString("PASSWORD");
                    if (!UserAuthentication.encoder.matches(oldPassword, storedPassword)) {
                        exchange.sendResponseHeaders(400, -1);
                        System.out.println("Old password is incorrect.");
                        return;
                    }
                }
            }

            newPassword = UserAuthentication.encoder.encode(newPassword);
        }

        // Update the user's profile in the database
        String updateSql = "UPDATE ZAK_USERS SET ";
        List<String> updates = new ArrayList<>();
        if (username != null) updates.add("USERNAME = ?");
        if (newPassword != null) updates.add("PASSWORD = ?");
        if (profilePicPath != null) updates.add("PROFILE_PICTURE = ?");
        if (removeProfilePic) updates.add("PROFILE_PICTURE = NULL");
        updateSql += String.join(", ", updates) + " WHERE ID = ?";

        if (updates.isEmpty()) {
            exchange.sendResponseHeaders(400, -1);
            System.out.println("No fields to update in the profile.");
            return;
        }

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(updateSql)) {
            int index = 1;
            if (username != null) stmt.setString(index++, username);
            if (newPassword != null) stmt.setString(index++, newPassword);
            if (profilePicPath != null) stmt.setString(index++, profilePicPath);
            stmt.setInt(index, getUserIdFromSession(exchange));
            stmt.executeUpdate();
        }

        exchange.getResponseHeaders().add("Content-Type", "application/json");
        String response = "{\"success\": true}";
        exchange.sendResponseHeaders(200, response.length());
        exchange.getResponseBody().write(response.getBytes());
        exchange.getResponseBody().close();
    }
    
    private static int getUserIdFromSession(HttpExchange exchange) throws SQLException {
        String sessionId = exchange.getRequestHeaders().getFirst("Session-Id");
        System.out.println("Received Session-Id: " + sessionId);

        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("Session ID is missing in the request headers");
        }

        String username = SessionManager.getUsername(sessionId);
        if (username == null) {
            throw new IllegalArgumentException("Invalid session ID or user not authenticated");
        }

        return DatabaseUtils.getIdFromUsername(username);
    }
}

