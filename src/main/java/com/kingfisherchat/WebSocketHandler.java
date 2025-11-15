package com.kingfisherchat;

import com.kingfisherchat.utils.DatabaseUtils;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import java.net.InetSocketAddress;
import java.sql.*;
import java.util.Map;

/**
 * Handles WebSocket connections and message routing.
 */
public class WebSocketHandler extends WebSocketServer {
    
    public WebSocketHandler(int port) {
        super(new InetSocketAddress(port));
    }
    
    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        System.out.println("New connection attempt: " + conn.getRemoteSocketAddress());
    }
    
    @Override
    public void onMessage(WebSocket conn, String message) {
        try {
            MessageData messageData = MessageData.fromJson(message);
    
            if ("authenticate".equals(messageData.getType())) {
                handleAuthenticate(conn, messageData);
            } else if ("selectChat".equals(messageData.getType())) {
                handleSelectChat(conn, messageData);
            } else if ("message".equals(messageData.getType())) {
                handleMessage(conn, messageData, message);
            }
        } catch (Exception e) {
            e.printStackTrace();
            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
        }
    }
    
    private void handleAuthenticate(WebSocket conn, MessageData messageData) {
        String username = messageData.getUsername();
        String sessionId = messageData.getSessionId();
    
        if (username == null || sessionId == null) {
            conn.send("{\"type\": \"authenticate\", \"success\": false, \"error\": \"Missing username or sessionId\"}");
            return;
        }
    
        SessionManager.authenticateSession(sessionId, username);
        conn.send("{\"type\": \"authenticate\", \"success\": true}");
        System.out.println("User authenticated: " + username);
    }
    
    private void handleSelectChat(WebSocket conn, MessageData messageData) {
        Integer chatId = messageData.getChatId();
        Integer groupId = messageData.getGroupId();
        String sessionId = messageData.getSessionId();
        
        System.out.println("groupId: " + groupId);
        System.out.println("chatId: " + chatId);

        String key = null;
        if (chatId != null && chatId != 0) {
            key = "chat-" + chatId;
            SessionManager.associateChatConnection(sessionId, key, conn);
            System.out.println("WebSocket associated with session ID: " + sessionId + " and chat ID: " + chatId);
        } else if (groupId != null && groupId != 0) {
            key = "group-" + groupId;
            SessionManager.associateChatConnection(sessionId, key, conn);
            System.out.println("WebSocket associated with session ID: " + sessionId + " and group ID: " + groupId);
        } else {
            System.out.println("Invalid selectChat request: both chatId and groupId are null.");
            conn.send("{\"type\": \"error\", \"message\": \"Invalid selectChat request.\"}");
            return;
        }
        
        System.out.println("Current chatConnections state: " + SessionManager.getAllChatConnections());
    }
    
    private void handleMessage(WebSocket conn, MessageData messageData, String rawMessage) {
        String username = messageData.getUsername();
        String sessionId = messageData.getSessionId();
        Integer chatId = messageData.getChatId();
        Integer groupId = messageData.getGroupId();
        
        System.out.println("Received message for session ID: " + sessionId + " and chat ID: " + chatId + " and group ID: " + groupId);
        System.out.println("Message content: " + messageData.getMessage());
        
        // Check if the session is authenticated
        if (!SessionManager.isAuthenticated(sessionId) || !SessionManager.getUsername(sessionId).equals(username)) {
            conn.send("{\"type\": \"error\", \"message\": \"Unauthorized user.\"}");
            return;
        }

        System.out.println("groupId: " + groupId);
        System.out.println("chatId: " + chatId);

        // Handle direct messages
        if (chatId != 0 && groupId == 0) {
            handleDirectMessage(conn, messageData, rawMessage, chatId, username);
        } else if (groupId != 0 && chatId == 0) {
            handleGroupMessage(conn, messageData, rawMessage, groupId, username);
        } else {
            conn.send("{\"type\": \"error\", \"message\": \"Invalid message type.\"}");
        }
    }
    
    private void handleDirectMessage(WebSocket conn, MessageData messageData, String rawMessage, int chatId, String username) {
        // Check if the user is part of the chat
        String checkChatSql = "SELECT COUNT(*) FROM ZAK_DIRECT_MESSAGES " +
                            "WHERE chat_id = ? AND (user1_id = ? OR user2_id = ?)";
        int userId = DatabaseUtils.getIdFromUsername(username);
        
        if (userId == -1) {
            conn.send("{\"type\": \"error\", \"message\": \"User not found.\"}");
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
        } catch (Exception e) {
            e.printStackTrace();
            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
            return;
        }

        // Save the message to the database
        saveMessageToDatabase(messageData, chatId);

        // Broadcast the message to all participants in the chat
        String key = "chat-" + chatId;
        java.util.Map<String, java.util.Map<String, WebSocket>> allConnections = SessionManager.getAllChatConnections();
        for (Map.Entry<String, java.util.Map<String, WebSocket>> entry : allConnections.entrySet()) {
            String targetSessionId = entry.getKey();
            java.util.Map<String, WebSocket> userChats = entry.getValue();

            if (userChats != null) {
                WebSocket targetConn = userChats.get(key);
                if (targetConn != null) {
                    targetConn.send(rawMessage);
                    System.out.println("Message sent to session ID: " + targetSessionId + " for chat ID: " + chatId);
                }
            }
        }
    }
    
    private void handleGroupMessage(WebSocket conn, MessageData messageData, String rawMessage, int groupId, String username) {
        // Check if the user is part of the group
        String checkGroupSql = "SELECT COUNT(*) FROM ZAK_GROUP_MEMBERS WHERE GROUP_ID = ? AND USER_ID = ?";
        int userId = DatabaseUtils.getIdFromUsername(username);
    
        if (userId == -1) {
            conn.send("{\"type\": \"error\", \"message\": \"User not found.\"}");
            return;
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
        } catch (Exception e) {
            e.printStackTrace();
            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
            return;
        }
    
        // Save the group message to the database
        saveGroupMessageToDatabase(messageData, groupId);
    
        // Broadcast the message to all group members
        String key = "group-" + groupId;
        String getGroupMembersSql = "SELECT USER_ID FROM ZAK_GROUP_MEMBERS WHERE GROUP_ID = ?";
        try (Connection connection = MySqlConnection.getConnection();
            PreparedStatement stmt = connection.prepareStatement(getGroupMembersSql)) {

            stmt.setInt(1, groupId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                int memberId = rs.getInt("USER_ID");

                // Find the session ID for the user
                String targetSessionId = null;
                java.util.Map<String, String> authenticatedSessions = SessionManager.getAllAuthenticatedSessions();
                for (Map.Entry<String, String> entry : authenticatedSessions.entrySet()) {
                    if (DatabaseUtils.getIdFromUsername(entry.getValue()) == memberId) {
                        targetSessionId = entry.getKey();
                        break;
                    }
                }

                if (targetSessionId == null) {
                    System.out.println("No session ID found for user ID: " + memberId);
                    continue;
                }

                // Send the message to all WebSocket connections for the session ID
                java.util.Map<String, WebSocket> userChats = SessionManager.getChatConnections(targetSessionId);
                if (userChats != null) {
                    WebSocket targetConn = userChats.get(key);
                    if (targetConn != null) {
                        targetConn.send(rawMessage);
                        System.out.println("Message sent to session ID: " + targetSessionId + " for group ID: " + groupId);
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            conn.send("{\"type\": \"error\", \"message\": \"Internal server error.\"}");
        }
    }
    
    private void saveMessageToDatabase(MessageData messageData, int chatId) {
        System.out.println("Saving message to database...");
        System.out.println("Message: " + messageData.getMessage());
        System.out.println("Chat ID: " + chatId);
        System.out.println("Username: " + messageData.getUsername());
    
        int userId = DatabaseUtils.getIdFromUsername(messageData.getUsername());
        if (userId == -1) {
            System.out.println("User not found: " + messageData.getUsername());
            return;
        }
    
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
        
        int userId = DatabaseUtils.getIdFromUsername(messageData.getUsername());
        if (userId == -1) {
            System.out.println("User not found: " + messageData.getUsername());
            return;
        }
        
        String sql = "INSERT INTO ZAK_MESSAGES (USER_ID, MESSAGE, GROUP_ID, MESSAGE_TYPE) VALUES (?, ?, ?, ?)";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {
    
            stmt.setInt(1, userId);
            stmt.setString(2, messageData.getMessage());
            stmt.setInt(3, groupId);
            stmt.setString(4, messageData.getMessageType());
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        System.out.println("Connection closed: " + conn.getRemoteSocketAddress());
        SessionManager.removeConnection(conn);
        System.out.println("Updated chatConnections state after close: " + SessionManager.getAllChatConnections());
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
}

