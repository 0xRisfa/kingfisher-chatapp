package com.kingfisherchat;

import com.sun.net.httpserver.HttpsServer;
import javax.net.ssl.SSLContext;

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
        // Initialize the HTTPS server and get the SSLContext
        HttpsServer httpsServer = HttpServerManager.initializeHttpsServerAndGetSslContext();
        SSLContext sslContext = HttpServerManager.getSslContext();

        // Start the WebSocket server with SSLContext
        WebSocketHandler webSocketServer = new WebSocketHandler(8081, sslContext);
        webSocketServer.start();
        System.out.println("WebSocket server started on port 8081 with WSS");

        // Start the HTTPS server
        HttpServerManager.startHttpsServer();
    }
}

