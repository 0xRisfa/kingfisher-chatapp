package com.kingfisherchat;

/**
 * Main server class that starts the WebSocket and HTTPS servers.
 * This class has been refactored to use modular components:
 * - WebSocketHandler: Handles WebSocket connections and message routing
 * - HttpServerManager: Manages HTTPS server and all HTTP endpoints
 * - SessionManager: Manages authenticated sessions and chat connections
 * - Various handlers in the handlers package for different endpoint groups
 */
public class MojServer {

    public static void main(String[] args) throws Exception {
        // Start the WebSocket server
        WebSocketHandler webSocketServer = new WebSocketHandler(8081);
        webSocketServer.start();
        System.out.println("WebSocket server started on port 8081");

        // Start the HTTPS server
        HttpServerManager.startHttpsServer();
    }
}
