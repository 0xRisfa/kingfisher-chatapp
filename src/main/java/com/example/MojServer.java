package com.example;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;

import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
//import org.java_websocket.server.DefaultSSLWebSocketServerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.KeyStore;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.zip.GZIPOutputStream;

public class MojServer extends WebSocketServer {
    private static final Set<WebSocket> connections = new HashSet<>();
    private static final Map<String, String> authenticatedSessions = new HashMap<>(); // Map of sessionId -> username
    private static final Map<String, Map<String, WebSocket>> chatConnections = new HashMap<>();

    public static void main(String[] args) throws Exception {
        MojServer server = new MojServer(8081);

        server.start(); // Start the WebSocket server
        System.out.println("WebSocket server started");
        startHttpsServer(); // Start the HTTPS server
    }

    public MojServer(int port) {
        super(new InetSocketAddress(port));
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection attempt: " + conn.getRemoteSocketAddress());
        connections.add(conn); // Add new connection
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            MessageData messageData = MessageData.fromJson(message);
    
            if ("authenticate".equals(messageData.getType())) {
                String username = messageData.getUsername();
                String sessionId = messageData.getSessionId();
    
                if (username == null || sessionId == null) {
                    conn.send("{\"type\": \"authenticate\", \"success\": false, \"error\": \"Missing username or sessionId\"}");
                    return;
                }
    
                authenticatedSessions.put(sessionId, username);
                conn.send("{\"type\": \"authenticate\", \"success\": true}");
                System.out.println("User authenticated: " + username);
    
            }else if ("selectChat".equals(messageData.getType())) {
                Integer chatId = messageData.getChatId(); // Can be null for group chats
                Integer groupId = messageData.getGroupId(); // Can be null for DMs
                String sessionId = messageData.getSessionId();
                
                System.out.println("groupId: " + groupId);
                System.out.println("chatId: " + chatId);

                synchronized (chatConnections) {
                    // Remove the WebSocket connection for the previous chat
                    Map<String, WebSocket> userChats = chatConnections.get(sessionId);
                    if (userChats != null) {
                        userChats.values().removeIf(existingConn -> existingConn.equals(conn));
                    }
            
                    // Add the WebSocket connection for the new chat
                    if (chatId != null && chatId != 0) {
                        String key = "chat-" + chatId;
                        chatConnections.computeIfAbsent(sessionId, k -> new HashMap<>()).put(key, conn);
                        System.out.println("WebSocket associated with session ID: " + sessionId + " and chat ID: " + chatId);
                    } else if (groupId != null && groupId != 0) {
                        String key = "group-" + groupId;
                        chatConnections.computeIfAbsent(sessionId, k -> new HashMap<>()).put(key, conn);
                        System.out.println("WebSocket associated with session ID: " + sessionId + " and group ID: " + groupId);
                    } else {
                        System.out.println("Invalid selectChat request: both chatId and groupId are null.");
                        conn.send("{\"type\": \"error\", \"message\": \"Invalid selectChat request.\"}");
                        return;
                    }
                }
            
                System.out.println("Current chatConnections state: " + chatConnections);
            
            } else if ("message".equals(messageData.getType())) {
                String username = messageData.getUsername();
                String sessionId = messageData.getSessionId();
                Integer chatId = messageData.getChatId(); // Get the chat ID from the message
                Integer groupId = messageData.getGroupId(); // Get the group ID from the message
                
                // Debug log for the received message
                System.out.println("Received message for session ID: " + sessionId + " and chat ID: " + chatId + " and group ID: " + groupId);
                System.out.println("Message content: " + messageData.getMessage());
                System.out.println("Current chatConnections state: " + chatConnections);
                
                // Check if the session is authenticated
                if (!authenticatedSessions.containsKey(sessionId) || !authenticatedSessions.get(sessionId).equals(username)) {
                    conn.send("{\"type\": \"error\", \"message\": \"Unauthorized user.\"}");
                    return;
                }


                System.out.println("groupId: " + groupId);
                System.out.println("chatId: " + chatId);
                

                // ------------------Handle direct messages-----------------
                if(chatId != 0 && groupId == 0) {
                    // Check if the user is part of the chat
                    String checkChatSql = "SELECT COUNT(*) FROM ZAK_DIRECT_MESSAGES " +
                                        "WHERE chat_id = ? AND (user1_id = ? OR user2_id = ?)";
                    int userId = -1;
                    
                    
                    // Get the user ID from the ZAK_USERS table
                    String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
                    try (Connection connection = MySqlConnection.getConnection();
                        PreparedStatement getUserIdStmt = connection.prepareStatement(getUserIdSql)) {

                        getUserIdStmt.setString(1, username.trim());
                        ResultSet rs = getUserIdStmt.executeQuery();
                        if (rs.next()) {
                            userId = rs.getInt("ID");
                        } else {
                            conn.send("{\"type\": \"error\", \"message\": \"User not found.\"}");
                            return;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
                        return;
                    }

                    // Verify that the user is part of the chat
                    try (Connection connection = MySqlConnection.getConnection();
                        PreparedStatement checkChatStmt = connection.prepareStatement(checkChatSql)) {

                        checkChatStmt.setInt(1, chatId);
                        checkChatStmt.setInt(2, userId);
                        checkChatStmt.setInt(3, userId);

                        ResultSet rs = checkChatStmt.executeQuery();
                        if (rs.next() && rs.getInt(1) == 0) {
                            conn.send("{\"type\": \"error\", \"message\": \"User is not part of the chat.\"}");
                            return;
                        }
                    }catch (Exception e) {
                        e.printStackTrace();
                        conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
                        return;
                    }

                    // Save the message to the database
                    saveMessageToDatabase(messageData, chatId);

                    // Broadcast the message to all participants in the chat
                    String key = "chat-" + chatId;
                    synchronized (chatConnections) {
                        for (Map.Entry<String, Map<String, WebSocket>> entry : chatConnections.entrySet()) {
                            String targetSessionId = entry.getKey();
                            Map<String, WebSocket> userChats = entry.getValue();

                            if (userChats != null) {
                                WebSocket targetConn = userChats.get(key);
                                if (targetConn != null) {
                                    targetConn.send(message);
                                    System.out.println("Message sent to session ID: " + targetSessionId + " for chat ID: " + chatId);
                                }
                            }
                        }
                    }
                } else if (groupId != 0 && chatId == 0) {
                    // ------------------Handle group messages-----------------

                    // Check if the user is part of the group
                    String checkGroupSql = "SELECT COUNT(*) FROM ZAK_GROUP_MEMBERS WHERE GROUP_ID = ? AND USER_ID = ?";
                    int userId = -1;
                
                    // Get the user ID from the ZAK_USERS table
                    String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
                    try (Connection connection = MySqlConnection.getConnection();
                         PreparedStatement getUserIdStmt = connection.prepareStatement(getUserIdSql)) {
                
                        getUserIdStmt.setString(1, username.trim());
                        ResultSet rs = getUserIdStmt.executeQuery();
                        if (rs.next()) {
                            userId = rs.getInt("ID");
                        } else {
                            conn.send("{\"type\": \"error\", \"message\": \"User not found.\"}");
                            return;
                        }
                    }
                
                    // Verify that the user is part of the group
                    try (Connection connection = MySqlConnection.getConnection();
                         PreparedStatement checkGroupStmt = connection.prepareStatement(checkGroupSql)) {
                
                        checkGroupStmt.setInt(1, groupId);
                        checkGroupStmt.setInt(2, userId);
                        ResultSet rs = checkGroupStmt.executeQuery();
                        if (rs.next() && rs.getInt(1) == 0) {
                            conn.send("{\"type\": \"error\", \"message\": \"User is not part of the group.\"}");
                            return;
                        }
                    }
                
                    // Save the group message to the database
                    saveGroupMessageToDatabase(messageData, groupId);
                
                    // Broadcast the message to all group members
                    String key = "group-" + groupId;
                    synchronized (chatConnections) {
                        String getGroupMembersSql = "SELECT USER_ID FROM ZAK_GROUP_MEMBERS WHERE GROUP_ID = ?";
                        try (Connection connection = MySqlConnection.getConnection();
                            PreparedStatement stmt = connection.prepareStatement(getGroupMembersSql)) {

                            stmt.setInt(1, groupId);
                            ResultSet rs = stmt.executeQuery();

                            while (rs.next()) {
                                int memberId = rs.getInt("USER_ID");

                                // Find the session ID for the user
                                String targetSessionId = null;
                                for (Map.Entry<String, String> entry : authenticatedSessions.entrySet()) {
                                    if (getIdfromUsername(entry.getValue()) == memberId) { // Match USER_ID with username
                                        targetSessionId = entry.getKey();
                                        break;
                                    }
                                }

                                if (targetSessionId == null) {
                                    System.out.println("No session ID found for user ID: " + memberId);
                                    continue;
                                }

                                // Send the message to all WebSocket connections for the session ID
                                Map<String, WebSocket> userChats = chatConnections.get(targetSessionId);
                                if (userChats != null) {
                                    WebSocket targetConn = userChats.get(key);
                                    if (targetConn != null) {
                                        targetConn.send(message);
                                        System.out.println("Message sent to session ID: " + targetSessionId + " for group ID: " + groupId);
                                    }
                                }
                            }
                        } catch (SQLException e) {
                            e.printStackTrace();
                            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
                        }
                    }
                } else {
                    conn.send("{\"type\": \"error\", \"message\": \"Invalid message type.\"}");
                }


            }
        } catch (Exception e) {
            e.printStackTrace();
            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
        }
    }

    private void saveMessageToDatabase(MessageData messageData, int chatId) {
        System.out.println("Saving message to database...");
        System.out.println("Message: " + messageData.getMessage());
        System.out.println("Chat ID: " + chatId);
        System.out.println("Username: " + messageData.getUsername());
    
        // Get the user ID from the ZAK_USERS table
        int userId =getIdfromUsername(messageData.getUsername());
        if(userId == -1) {
            System.out.println("User not found: " + messageData.getUsername());
            return;
        }
    
        // Insert the message into the ZAK_MESSAGES table
        String sql = "INSERT INTO ZAK_MESSAGES (USER_ID, MESSAGE, CHAT_ID, MESSAGE_TYPE) VALUES (?, ?, ?, ?)";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            stmt.setString(2, messageData.getMessage());
            stmt.setInt(3, chatId);
            stmt.setString(4, messageData.getMessageType());
            stmt.executeUpdate();
            System.out.println("Message saved to database: " + messageData.getMessage());
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void saveGroupMessageToDatabase(MessageData messageData, int groupId) {
        System.out.println("Saving message to database...");
        System.out.println("Message: " + messageData.getMessage());
        System.out.println("Group ID: " + groupId);
        System.out.println("Username: " + messageData.getUsername());
        
        // Get the user ID from the ZAK_USERS table
        int userId =getIdfromUsername(messageData.getUsername());
        if(userId == -1) {
            System.out.println("User not found: " + messageData.getUsername());
            return;
        }
        
        // Insert the message into the ZAK_MESSAGES table
        String sql = "INSERT INTO ZAK_MESSAGES (USER_ID, MESSAGE, GROUP_ID, MESSAGE_TYPE) VALUES (?, ?, ?, ?)";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {
    
            stmt.setInt(1, getIdfromUsername(messageData.getUsername())); // Assuming userId is part of messageData
            stmt.setString(2, messageData.getMessage());
            stmt.setInt(3, groupId);
            stmt.setString(4, messageData.getMessageType());
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private int getIdfromUsername(String username){
        int userId = -1;
        String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement getUserIdStmt = connection.prepareStatement(getUserIdSql)) {
    
            getUserIdStmt.setString(1, username.trim());
            ResultSet rs = getUserIdStmt.executeQuery();
            if (rs.next()) {
                userId = rs.getInt("ID");
                System.out.println("User ID: " + userId);
            } else {
                System.out.println("User not found: " + username);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userId;
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        connections.remove(conn);
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress());
    
        synchronized (chatConnections) {
            // Iterate through all session entries
            for (Map<String, WebSocket> userChats : chatConnections.values()) {
                // Remove the WebSocket connection if it matches the closed connection
                userChats.values().removeIf(existingConn -> existingConn.equals(conn));
            }
    
            // Remove any session entries that no longer have active connections
            chatConnections.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        }
    
        System.out.println("Updated chatConnections state after close: " + chatConnections);
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        System.out.println("WebSocket error: " + ex.getMessage());
        ex.printStackTrace();
    }

    @Override
    public void onStart() {
        System.out.println("WebSocket Server started.");
    }

    // Start the HTTPS server
    private static void startHttpsServer() throws Exception {
        // Load the keystore
        char[] keystorePassword = Config.get("keystore.password").toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(Config.get("keystore.path")), keystorePassword);

        // Set up the key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, keystorePassword);

        // Set up the trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Initialize the SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Create the HTTPS server
        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(8443), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));

        // Serve the root context (/) with index.html
        httpsServer.createContext("/", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                File file = new File("src/main/resources/index.html");
                if (!file.exists()) {
                    System.out.println("File not found: index.html"); // Debug log
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }

                exchange.getResponseHeaders().add("Content-Type", "text/html");
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                exchange.sendResponseHeaders(200, fileBytes.length);
                exchange.getResponseBody().write(fileBytes);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Serve chat.html
        httpsServer.createContext("/chat.html", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                File file = new File("src/main/resources/chat.html");
                if (!file.exists()) {
                    System.out.println("File not found: chat.html"); // Debug log
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }

                exchange.getResponseHeaders().add("Content-Type", "text/html");
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                exchange.sendResponseHeaders(200, fileBytes.length);
                exchange.getResponseBody().write(fileBytes);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Serve register.html
        httpsServer.createContext("/register.html", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                File file = new File("src/main/resources/register.html");
                if (!file.exists()) {
                    System.out.println("File not found: register.html"); // Debug log
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }

                exchange.getResponseHeaders().add("Content-Type", "text/html");
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                exchange.sendResponseHeaders(200, fileBytes.length);
                exchange.getResponseBody().write(fileBytes);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Serve static files
        httpsServer.createContext("/static", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath().replaceFirst("/static", "");
                System.out.println("Requested Static File Path: " + path); // Debug log
        
                File file;
        
                // Check if the file is in the "avatars" directory
                if (path.startsWith("/avatars")) {
                    file = new File("avatars" + path.replaceFirst("/avatars", ""));
                } else if (path.startsWith("/uploads")) {
                    // Check if the file is in the "uploads" directory
                    file = new File("uploads" + path.replaceFirst("/uploads", ""));
                } else {
                    // Serve files directly from "src/main/resources"
                    file = new File("src/main/resources" + path);
                }
        
                if (!file.exists() || file.isDirectory()) {
                    System.out.println("File not found: " + file.getAbsolutePath()); // Debug log
                    exchange.sendResponseHeaders(404, -1);
                    return;
                }
        
                // Determine the MIME type
                exchange.getResponseHeaders().add("Content-Type", getMimeType(path));
        
                // Read and send the file content
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                exchange.sendResponseHeaders(200, fileBytes.length);
                exchange.getResponseBody().write(fileBytes);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Handle login requests
        httpsServer.createContext("/login", exchange -> {
            try {
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

                    System.out.println("Raw received data: " + requestBody.toString()); // Debug log

                    // Parse JSON
                    Map<String, String> requestData = parseJson(requestBody.toString());
                    String username = requestData.get("username");
                    String password = requestData.get("password");
                    String sessionId = requestData.get("sessionId");
                    
                    System.out.println("Parsed Username: " + username); // Debug log
                    System.out.println("Parsed Password: " + password); // Debug log

                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");

                    if (UserAuthentication.login(username, password)) {
                        // Add session ID to authenticatedSessions
                        authenticatedSessions.put(sessionId, username);

                        // Respond with success
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
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Handle registration requests
        httpsServer.createContext("/register", exchange -> {
            try {
                if ("OPTIONS".equals(exchange.getRequestMethod())) {
                    exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
                    exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
                    exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
                    exchange.sendResponseHeaders(204, -1); // No content for preflight
                    return;
                }

                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()))) {
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        requestBody.append(line);
                    }

                    System.out.println("Raw received data: " + requestBody.toString()); // Debug log

                    // Parse JSON
                    Map<String, String> requestData = parseJson(requestBody.toString());
                    String username = requestData.get("username");
                    String password = requestData.get("password");

                    System.out.println("Parsed Username: " + username); // Debug log
                    System.out.println("Parsed Password: " + password); // Debug log

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
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Handle loadMessages requests
        httpsServer.createContext("/loadMessages", exchange -> {
        try {
            if (!"GET".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                return;
            }

            String query = exchange.getRequestURI().getQuery();
            int chatId = 0; // Default chat ID
            int limit = 20; // Default limit
            int offset = 0; // Default offset

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

            String sql = "SELECT ZAK_USERS.USERNAME, ZAK_USERS.PROFILE_PICTURE, ZAK_MESSAGES.MESSAGE, ZAK_MESSAGES.MESSAGE_TYPE, ZAK_MESSAGES.TIMESTAMP " +
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
                        profilePicture = "/static/avatars/default-avatar.png"; // Fallback to default avatar
                    }
            
                    Map<String, Object> message = new HashMap<>();
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

            // Use Gson to serialize the messages list to JSON
            Gson gson = new Gson();
            String jsonResponse = gson.toJson(messages);

            exchange.getResponseHeaders().add("Content-Encoding", "gzip");
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);

            try (OutputStream os = new GZIPOutputStream(exchange.getResponseBody());
                Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
                writer.write(jsonResponse);
                writer.flush();
            }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        // Handle loadDirectMessages requests
        httpsServer.createContext("/loadDirectMessages", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                // Retrieve the username from the session or headers
                String username = exchange.getRequestHeaders().getFirst("Username");
                if (username == null || username.isEmpty()) {
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }

                // Get the user ID from the database
                int userId = -1;
                String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(getUserIdSql)) {

                    stmt.setString(1, username);
                    long startTime = System.currentTimeMillis();
                    ResultSet rs = stmt.executeQuery();
                    long endTime = System.currentTimeMillis();
                    System.out.println("Query execution time: " + (endTime - startTime) + "ms");
                    if (rs.next()) {
                        userId = rs.getInt("ID");
                    } else {
                        exchange.sendResponseHeaders(404, -1); // User not found
                        return;
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                    return;
                }

                // Fetch direct messages for the user
                String sql = "SELECT chat_id, " +
                             "CASE WHEN user1_id = ? THEN u2.USERNAME ELSE u1.USERNAME END AS other_user " +
                             "FROM ZAK_DIRECT_MESSAGES " +
                             "INNER JOIN ZAK_USERS AS u1 ON ZAK_DIRECT_MESSAGES.user1_id = u1.ID " +
                             "INNER JOIN ZAK_USERS AS u2 ON ZAK_DIRECT_MESSAGES.user2_id = u2.ID " +
                             "WHERE user1_id = ? OR user2_id = ?";
                StringBuilder response = new StringBuilder("[");

                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(sql)) {

                    stmt.setInt(1, userId);
                    stmt.setInt(2, userId);
                    stmt.setInt(3, userId);
                    long startTime = System.currentTimeMillis();
                    ResultSet rs = stmt.executeQuery();
                    long endTime = System.currentTimeMillis();
                    System.out.println("Query execution time: " + (endTime - startTime) + "ms");

                    while (rs.next()) {
                        if (response.length() > 1) response.append(",");
                        response.append(String.format(
                            "{\"chatId\": %d, \"username\": \"%s\"}",
                            rs.getInt("chat_id"),
                            rs.getString("other_user")
                        ));
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                    return;
                }

                response.append("]");
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.toString().getBytes());
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/loadGroupMessages", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
        
                // Parse query parameters directly
                String query = exchange.getRequestURI().getQuery();
                int groupId = 0; // Default group ID
                int limit = 20; // Default limit
                int offset = 0; // Default offset

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

                System.out.println("Tralalero tralala, if this has loaded. it tried loading group messages"); // Debug log
                // Fetch messages for the group
                String sql = "SELECT ZAK_USERS.USERNAME, ZAK_USERS.PROFILE_PICTURE, ZAK_MESSAGES.MESSAGE, ZAK_MESSAGES.MESSAGE_TYPE, ZAK_MESSAGES.TIMESTAMP " +
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
                            profilePicture = "/static/avatars/default-avatar.png"; // Fallback to default avatar
                        }

                        Map<String, Object> message = new HashMap<>();
                        message.put("username", rs.getString("USERNAME"));
                        message.put("profilePicture", profilePicture);
                        message.put("message", rs.getString("MESSAGE"));
                        message.put("messageType", rs.getString("MESSAGE_TYPE"));
                        message.put("timestamp", rs.getTimestamp("TIMESTAMP").toString());
                        messages.add(message);
                    }
                }
        
            // Use Gson to serialize the messages list to JSON
            Gson gson = new Gson();
            String jsonResponse = gson.toJson(messages);

            exchange.getResponseHeaders().add("Content-Encoding", "gzip");
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, 0);

            try (OutputStream os = new GZIPOutputStream(exchange.getResponseBody());
                Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
                writer.write(jsonResponse);
                writer.flush();
            }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/loadGroupChats", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                // Retrieve the username from the session or headers
                String username = exchange.getRequestHeaders().getFirst("Username");
                if (username == null || username.isEmpty()) {
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }

                // Get the user ID from the database
                int userId = -1;
                String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(getUserIdSql)) {

                    stmt.setString(1, username);
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        userId = rs.getInt("ID");
                    } else {
                        exchange.sendResponseHeaders(404, -1); // User not found
                        return;
                    }
                }

                // Fetch group chats for the user
                String sql = "SELECT GROUP_ID, NAME FROM ZAK_GROUP_CHATS " +
                             "INNER JOIN ZAK_GROUP_MEMBERS ON ZAK_GROUP_CHATS.ID = ZAK_GROUP_MEMBERS.GROUP_ID " +
                             "WHERE ZAK_GROUP_MEMBERS.USER_ID = ?";
                StringBuilder response = new StringBuilder("[");

                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(sql)) {

                    stmt.setInt(1, userId);
                    ResultSet rs = stmt.executeQuery();

                    while (rs.next()) {
                        if (response.length() > 1) response.append(",");
                        response.append(String.format(
                            "{\"groupId\": %d, \"name\": \"%s\"}",
                            rs.getInt("GROUP_ID"),
                            rs.getString("NAME")
                        ));
                    }
                }

                response.append("]");
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.toString().getBytes());
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/upload", exchange -> {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                    System.out.println("Unsupported Content-Type: " + contentType);
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }

                try (InputStream inputStream = exchange.getRequestBody()) {
                    // Extract the boundary from the Content-Type header
                    String boundary = contentType.split("boundary=")[1];
                    if (boundary == null) {
                        System.out.println("Boundary not found in Content-Type");
                        exchange.sendResponseHeaders(400, -1); // Bad Request
                        return;
                    }
                    boundary = "--" + boundary;

                    // Read the request body
                    byte[] body = inputStream.readAllBytes();

                    // Split the body into parts using the boundary
                    int boundaryLength = boundary.getBytes("UTF-8").length;
                    int currentIndex = 0;

                    while (currentIndex < body.length) {
                        // Locate the next boundary
                        int nextBoundaryIndex = locateBoundary(body, currentIndex, boundary);
                        if (nextBoundaryIndex == -1) break;

                        // Extract the part
                        byte[] part = Arrays.copyOfRange(body, currentIndex, nextBoundaryIndex);
                        currentIndex = nextBoundaryIndex + boundaryLength;

                        // Process the part
                        String partHeaders = extractHeaders(part);
                        if (partHeaders.contains("Content-Disposition") && partHeaders.contains("filename=\"")) {
                            // Extract the filename
                            String fileName = UUID.randomUUID().toString();
                            String fileExtension = "";

                            if (partHeaders.contains("filename=\"")) {
                                String originalFileName = partHeaders.split("filename=\"")[1].split("\"")[0];
                                if (originalFileName.contains(".")) {
                                    fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
                                }
                            }

                            // Extract the file content
                            byte[] fileContent = extractFileContent(part);

                            // Save the file
                            File file = new File("uploads/" + fileName + fileExtension);
                            file.getParentFile().mkdirs();
                            try (FileOutputStream outputStream = new FileOutputStream(file)) {
                                outputStream.write(fileContent);
                            }

                            // Debug: Log the file size and path
                            System.out.println("File saved: " + file.getAbsolutePath() + " (" + file.length() + " bytes)");

                            // Respond with the file URL
                            String fileUrl = "/static/uploads/" + fileName + fileExtension;
                            exchange.getResponseHeaders().add("Content-Type", "application/json");
                            String response = "{\"success\": true, \"fileUrl\": \"" + fileUrl + "\"}";
                            exchange.sendResponseHeaders(200, response.length());
                            exchange.getResponseBody().write(response.getBytes());
                            exchange.getResponseBody().close();
                            return;
                        }
                    }

                    // If no file was uploaded
                    System.out.println("No file uploaded");
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/searchUsers", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
        
                String query = exchange.getRequestURI().getQuery();
                String searchTerm = "";
        
                if (query != null) {
                    for (String param : query.split("&")) {
                        String[] keyValue = param.split("=");
                        if (keyValue.length == 2 && "q".equals(keyValue[0])) { // Ensure keyValue has both key and value
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
                        user.put("id", rs.getInt("ID")); // Include the user ID
                        user.put("username", rs.getString("USERNAME"));
                        users.add(user);
                    }
                } catch (SQLException e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                    return;
                }
        
                // Use Gson to serialize the user list to JSON
                Gson gson = new Gson();
                String jsonResponse = gson.toJson(users);

                exchange.getResponseHeaders().add("Content-Encoding", "gzip");
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, 0);

                try (OutputStream os = new GZIPOutputStream(exchange.getResponseBody());
                    Writer writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
                    writer.write(jsonResponse);
                    writer.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/startChat", exchange -> {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
            
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()))) {
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        requestBody.append(line);
                    }
            
                    Map<String, String> requestData = parseJson(requestBody.toString());
                    String username = requestData.get("username");
                    String otherUsername = requestData.get("otherUsername");
            
                    if (username == null || otherUsername == null) {
                        exchange.sendResponseHeaders(400, -1); // Bad Request
                        return;
                    }
            
                    // Get user IDs
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
                        exchange.sendResponseHeaders(404, -1); // User not found
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
                        if (rs.next()) chatId = rs.getInt("ID");
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
            
                    // Respond with the chat ID
                    String response = String.format("{\"chatId\": %d}", chatId);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    exchange.getResponseBody().close();
                } catch (Exception e) {
                    e.printStackTrace();
                    exchange.sendResponseHeaders(500, -1); // Internal Server Error
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/updateProfile", exchange -> {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
        
                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType == null || !contentType.startsWith("multipart/form-data")) {
                    System.out.println("Unsupported Content-Type: " + contentType);
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }
        
                InputStream inputStream = exchange.getRequestBody();
                String boundary = contentType.split("boundary=")[1];
                if (boundary == null) {
                    System.out.println("Boundary not found in Content-Type");
                    exchange.sendResponseHeaders(400, -1); // Bad Request
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
                    int nextBoundaryIndex = locateBoundary(body, currentIndex, boundary);
                    if (nextBoundaryIndex == -1) break;
        
                    byte[] part = Arrays.copyOfRange(body, currentIndex, nextBoundaryIndex);
                    currentIndex = nextBoundaryIndex + boundaryLength;
        
                    String partHeaders = extractHeaders(part);
                    if (partHeaders.contains("Content-Disposition")) {
                        if (partHeaders.contains("name=\"username\"")) {
                            username = new String(extractFileContent(part), StandardCharsets.UTF_8).trim();
                        } else if (partHeaders.contains("name=\"oldPassword\"")) {
                            oldPassword = new String(extractFileContent(part), StandardCharsets.UTF_8).trim();
                        } else if (partHeaders.contains("name=\"newPassword\"")) {
                            newPassword = new String(extractFileContent(part), StandardCharsets.UTF_8).trim();
                        } else if (partHeaders.contains("name=\"profilePic\"") && partHeaders.contains("filename=\"")) {
                            String fileName = UUID.randomUUID().toString();
                            String fileExtension = "";
        
                            if (partHeaders.contains("filename=\"")) {
                                String originalFileName = partHeaders.split("filename=\"")[1].split("\"")[0];
                                if (originalFileName.contains(".")) {
                                    fileExtension = originalFileName.substring(originalFileName.lastIndexOf("."));
                                }
                            }
        
                            byte[] fileContent = extractFileContent(part);
                            File file = new File("avatars/" + fileName + fileExtension);
                            file.getParentFile().mkdirs();
                            try (FileOutputStream outputStream = new FileOutputStream(file)) {
                                outputStream.write(fileContent);
                            }
        
                            profilePicPath = "/static/avatars/" + fileName + fileExtension;
                        } else if (partHeaders.contains("name=\"removeProfilePic\"")) {
                            removeProfilePic = Boolean.parseBoolean(new String(extractFileContent(part), StandardCharsets.UTF_8).trim());
                        }
                    }
                }
        
                // Validate old password if a new password is provided
                if (newPassword != null) {
                    String sql = "SELECT PASSWORD FROM ZAK_USERS WHERE ID = ?";
                    try (Connection connection = MySqlConnection.getConnection();
                         PreparedStatement stmt = connection.prepareStatement(sql)) {
        
                        stmt.setInt(1, getUserIdFromSession(exchange));
                        ResultSet rs = stmt.executeQuery();
                        if (rs.next()) {
                            String storedPassword = rs.getString("PASSWORD");
                            if (!UserAuthentication.encoder.matches(oldPassword, storedPassword)) { // Compare hashed passwords
                                exchange.sendResponseHeaders(400, -1); // Bad Request
                                System.out.println("Old password is incorrect.");
                                return;
                            }
                        }
                    }
        
                    // Hash the new password before storing it
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
                    exchange.sendResponseHeaders(400, -1); // Bad Request
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
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/getProfilePicture", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }

                // Parse the username from the query parameters
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
                    System.out.println("Username is missing in the request."); // Debug log
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }

                // Fetch the profile picture path from the database
                String sql = "SELECT PROFILE_PICTURE FROM ZAK_USERS WHERE USERNAME = ?";
                String profilePicture = null;

                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(sql)) {

                    stmt.setString(1, username);
                    ResultSet rs = stmt.executeQuery();
                    if (rs.next()) {
                        profilePicture = rs.getString("PROFILE_PICTURE");
                        System.out.println("Fetched profile picture for " + username + ": " + profilePicture); // Debug log
                    }
                }

                // If no profile picture is found, use the default avatar
                if (profilePicture == null || profilePicture.isEmpty()) {
                    profilePicture = "/static/avatars/default-avatar.png";
                    System.out.println("Using default avatar for " + username); // Debug log
                }

                // Respond with the profile picture URL
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                String response = String.format("{\"profilePicture\": \"%s\"}", profilePicture);
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/createGroupChat", exchange -> {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
        
                BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                StringBuilder requestBody = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    requestBody.append(line);
                }
        
                // Parse the request body
                Gson gson = new Gson();
                Map<String, Object> requestData = gson.fromJson(requestBody.toString(), Map.class);
                String groupName = (String) requestData.get("name");
                List<Double> memberIds = (List<Double>) requestData.get("members"); // Gson parses numbers as Double
                int createdBy = getUserIdFromSession(exchange);
        
                if (groupName == null || memberIds == null || memberIds.isEmpty()) {
                    exchange.sendResponseHeaders(400, -1); // Bad Request
                    return;
                }
        
                // Insert the group chat into the database
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
                        exchange.sendResponseHeaders(500, -1); // Internal Server Error
                        return;
                    }
                }
        
                // Add members to the group
                String insertMembersSql = "INSERT INTO ZAK_GROUP_MEMBERS (GROUP_ID, USER_ID) VALUES (?, ?)";
                try (Connection connection = MySqlConnection.getConnection();
                     PreparedStatement stmt = connection.prepareStatement(insertMembersSql)) {
        
                    for (Double memberId : memberIds) {
                        stmt.setInt(1, groupId);
                        stmt.setInt(2, memberId.intValue()); // Convert Double to Integer
                        stmt.addBatch();
                    }
                    stmt.executeBatch();
                }
        
                // Respond with the group ID
                String response = String.format("{\"groupId\": %d}", groupId);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, response.length());
                exchange.getResponseBody().write(response.getBytes());
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.createContext("/config.json", exchange -> {
            try {
                if (!"GET".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1); // Method Not Allowed
                    return;
                }
        
                File file = new File("src/main/resources/config.json");
                if (!file.exists()) {
                    System.out.println("File not found: config.json"); // Debug log
                    exchange.sendResponseHeaders(404, -1); // Not Found
                    return;
                }
        
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                exchange.sendResponseHeaders(200, fileBytes.length);
                exchange.getResponseBody().write(fileBytes);
                exchange.getResponseBody().close();
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1); // Internal Server Error
            }
        });

        httpsServer.setExecutor(Executors.newFixedThreadPool(10)); // Adjust the thread pool size as needed
        httpsServer.start();
        System.out.println("HTTPS Server started at https://localhost:8443");
    }

    // parse JSON string into a Map
    private static Map<String, String> parseJson(String json) {
        Map<String, String> map = new HashMap<>();
        json = json.replaceAll("[{}\"]", ""); // Remove brackets and quotes
        String[] keyValuePairs = json.split(",");
    
        for (String pair : keyValuePairs) {
            String[] entry = pair.split(":");
            if (entry.length == 2) {
                String key = entry[0].trim();
                String value = entry[1].trim();
                map.put(key, value);
            }
        }
    
        return map;
    }

    private static String getMimeType(String path) {
        if (path.endsWith(".html")) return "text/html";
        if (path.endsWith(".css")) return "text/css";
        if (path.endsWith(".js")) return "application/javascript";
        if (path.endsWith(".png")) return "image/png";
        if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
        if (path.endsWith(".gif")) return "image/gif";
        return "application/octet-stream";
    }  

    private static int locateBoundary(byte[] body, int startIndex, String boundary) {
        byte[] boundaryBytes = boundary.getBytes();
        for (int i = startIndex; i <= body.length - boundaryBytes.length; i++) {
            boolean match = true;
            for (int j = 0; j < boundaryBytes.length; j++) {
                if (body[i + j] != boundaryBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private static String extractHeaders(byte[] part) {
        int headerEndIndex = -1;
        for (int i = 0; i < part.length - 3; i++) {
            if (part[i] == '\r' && part[i + 1] == '\n' && part[i + 2] == '\r' && part[i + 3] == '\n') {
                headerEndIndex = i;
                break;
            }
        }
        if (headerEndIndex == -1) return "";
        return new String(Arrays.copyOfRange(part, 0, headerEndIndex), StandardCharsets.UTF_8);
    }

    private static byte[] extractFileContent(byte[] part) {
        int headerEndIndex = -1;
        for (int i = 0; i < part.length - 3; i++) {
            if (part[i] == '\r' && part[i + 1] == '\n' && part[i + 2] == '\r' && part[i + 3] == '\n') {
                headerEndIndex = i + 4;
                break;
            }
        }
        if (headerEndIndex == -1) return new byte[0];
        return Arrays.copyOfRange(part, headerEndIndex, part.length);
    }

    private static int getUserIdFromSession(HttpExchange exchange) throws SQLException {
        String sessionId = exchange.getRequestHeaders().getFirst("Session-Id");
        System.out.println("Received Session-Id: " + sessionId); // Debug log

        if (sessionId == null || sessionId.isEmpty()) {
            throw new IllegalArgumentException("Session ID is missing in the request headers");
        }

        String username = authenticatedSessions.get(sessionId);
        if (username == null) {
            throw new IllegalArgumentException("Invalid session ID or user not authenticated");
        }

        // Retrieve the user ID from the database
        String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(getUserIdSql)) {

            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("ID");
            } else {
                throw new IllegalArgumentException("User not found for the given session ID");
            }
        }
    }
}
