package com.kingfisherchat;

import org.java_websocket.WebSocket;
import java.util.*;

/**
 * Manages authenticated sessions and WebSocket connections for chats.
 */
public class SessionManager {
    private static final Map<String, String> authenticatedSessions = new HashMap<>(); // sessionId -> username
    private static final Map<String, Map<String, WebSocket>> chatConnections = new HashMap<>(); // sessionId -> (chatKey -> WebSocket)
    
    /**
     * Authenticates a session with a username.
     */
    public static void authenticateSession(String sessionId, String username) {
        authenticatedSessions.put(sessionId, username);
    }
    
    /**
     * Checks if a session is authenticated.
     */
    public static boolean isAuthenticated(String sessionId) {
        return authenticatedSessions.containsKey(sessionId);
    }
    
    /**
     * Gets the username for a session.
     */
    public static String getUsername(String sessionId) {
        return authenticatedSessions.get(sessionId);
    }
    
    /**
     * Associates a WebSocket connection with a chat for a session.
     */
    public static void associateChatConnection(String sessionId, String chatKey, WebSocket conn) {
        synchronized (chatConnections) {
            // Remove the WebSocket connection for the previous chat
            Map<String, WebSocket> userChats = chatConnections.get(sessionId);
            if (userChats != null) {
                userChats.values().removeIf(existingConn -> existingConn.equals(conn));
            }
            
            // Add the WebSocket connection for the new chat
            chatConnections.computeIfAbsent(sessionId, k -> new HashMap<>()).put(chatKey, conn);
        }
    }
    
    /**
     * Gets the WebSocket connection for a specific chat.
     */
    public static WebSocket getChatConnection(String sessionId, String chatKey) {
        synchronized (chatConnections) {
            Map<String, WebSocket> userChats = chatConnections.get(sessionId);
            if (userChats != null) {
                return userChats.get(chatKey);
            }
            return null;
        }
    }
    
    /**
     * Gets all chat connections for a session.
     */
    public static Map<String, WebSocket> getChatConnections(String sessionId) {
        synchronized (chatConnections) {
            return chatConnections.getOrDefault(sessionId, new HashMap<>());
        }
    }
    
    /**
     * Gets all chat connections across all sessions.
     */
    public static Map<String, Map<String, WebSocket>> getAllChatConnections() {
        synchronized (chatConnections) {
            return new HashMap<>(chatConnections);
        }
    }
    
    /**
     * Removes a WebSocket connection when it closes.
     */
    public static void removeConnection(WebSocket conn) {
        synchronized (chatConnections) {
            // Iterate through all session entries
            for (Map<String, WebSocket> userChats : chatConnections.values()) {
                // Remove the WebSocket connection if it matches the closed connection
                userChats.values().removeIf(existingConn -> existingConn.equals(conn));
            }
            
            // Remove any session entries that no longer have active connections
            chatConnections.entrySet().removeIf(entry -> entry.getValue().isEmpty());
        }
    }
    
    /**
     * Removes a session.
     */
    public static void removeSession(String sessionId) {
        authenticatedSessions.remove(sessionId);
        synchronized (chatConnections) {
            chatConnections.remove(sessionId);
        }
    }
    
    /**
     * Gets all authenticated sessions.
     */
    public static Map<String, String> getAllAuthenticatedSessions() {
        return new HashMap<>(authenticatedSessions);
    }
}

