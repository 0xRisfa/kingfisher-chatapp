package com.example;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

public class MessageData {
    private String type;        // "authenticate" or "message"
    private String sessionId;   // Session ID for each tab
    private String username;    // Username of the sender
    private String message;     // Chat message content
    private int chatId;         // Chat ID
    private String messageType; // "text" or "file"
    private int groupId;        // Group ID

    // Constructor for message data
    public MessageData(String type, String sessionId, String username, String message, String messageType) {
        this.type = type;
        this.sessionId = sessionId;
        this.username = username;
        this.message = message;
        this.messageType = messageType;
    }

    // Constructor for authentication data (used only for type "authenticate")
    public MessageData(String type, String username) {
        this.type = type;
        this.username = username;
    }

    // Default constructor
    public MessageData() {
    }

    // Getters and setters
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getChatId() {
        return chatId;
    }

    public void setChatId(int chatId) {
        this.chatId = chatId;
    }

    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }

    public int getGroupId() {
        return groupId;
    }

    public void setGroupId(int groupId) {
        this.groupId = groupId;
    }

    // Method to convert a MessageData object into a JSON string
    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }

    // Static method to create a MessageData object from a JSON string
    public static MessageData fromJson(String json) {
        Gson gson = new Gson();
        try {
            return gson.fromJson(json, MessageData.class);
        } catch (JsonSyntaxException e) {
            e.printStackTrace();
            return null; // Return null if parsing fails
        }
    }
}
