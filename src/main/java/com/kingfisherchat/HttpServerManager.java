package com.kingfisherchat;

import com.kingfisherchat.handlers.*;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.concurrent.Executors;

/**
 * Manages the HTTPS server and all HTTP endpoints.
 */
public class HttpServerManager {

    private static SSLContext sslContext;
    private static HttpsServer httpsServer;

    /**
     * Initializes the HTTPS server and returns the SSLContext.
     * This method should be called once to set up the server and get the SSLContext for WebSockets.
     * @return The initialized SSLContext.
     * @throws Exception if initialization fails.
     */
    public static HttpsServer initializeHttpsServerAndGetSslContext() throws Exception {
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
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Create the HTTPS server
        httpsServer = HttpsServer.create(new InetSocketAddress(8443), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext));

        // Register all endpoints
        registerEndpoints(httpsServer);
        
        httpsServer.setExecutor(Executors.newFixedThreadPool(20));
        System.out.println("HTTPS Server initialized on port 8443");
        return httpsServer;
    }

    /**
     * Starts the previously initialized HTTPS server.
     */
    public static void startHttpsServer() {
        if (httpsServer != null) {
            httpsServer.start();
            System.out.println("HTTPS Server started at https://localhost:8443");
        } else {
            System.err.println("HTTPS Server not initialized. Call initializeHttpsServerAndGetSslContext() first.");
        }
    }

    /**
     * Returns the initialized SSLContext.
     * @return The SSLContext.
     */
    public static SSLContext getSslContext() {
        return sslContext;
    }
    
    /**
     * Registers all HTTP endpoints with the server.
     */
    private static void registerEndpoints(HttpsServer httpsServer) {
        // Static file endpoints
        httpsServer.createContext("/", exchange -> {
            try {
                StaticFileHandler.handleRoot(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/chat.html", exchange -> {
            try {
                StaticFileHandler.handleChatHtml(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/register.html", exchange -> {
            try {
                StaticFileHandler.handleRegisterHtml(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/static", exchange -> {
            try {
                StaticFileHandler.handleStaticFiles(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/config.json", exchange -> {
            try {
                StaticFileHandler.handleConfigJson(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Authentication endpoints
        httpsServer.createContext("/login", exchange -> {
            try {
                AuthHandler.handleLogin(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/register", exchange -> {
            try {
                AuthHandler.handleRegister(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Message endpoints
        httpsServer.createContext("/loadMessages", exchange -> {
            try {
                MessageHandler.handleLoadMessages(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/loadGroupMessages", exchange -> {
            try {
                MessageHandler.handleLoadGroupMessages(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/deleteMessage", exchange -> {
            try {
                MessageHandler.handleDeleteMessage(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/markMessagesAsRead", exchange -> {
            try {
                MessageHandler.handleMarkMessagesAsRead(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Chat endpoints
        httpsServer.createContext("/loadChats", exchange -> {
            try {
                ChatHandler.handleLoadChats(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/startChat", exchange -> {
            try {
                ChatHandler.handleStartChat(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // Group endpoints
        httpsServer.createContext("/createGroupChat", exchange -> {
            try {
                GroupHandler.handleCreateGroupChat(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/getGroupInfo", exchange -> {
            try {
                GroupHandler.handleGetGroupInfo(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/addGroupMember", exchange -> {
            try {
                GroupHandler.handleAddGroupMember(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/removeGroupMember", exchange -> {
            try {
                GroupHandler.handleRemoveGroupMember(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/renameGroup", exchange -> {
            try {
                GroupHandler.handleRenameGroup(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // File endpoints
        httpsServer.createContext("/upload", exchange -> {
            try {
                FileHandler.handleUpload(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/getProfilePicture", exchange -> {
            try {
                FileHandler.handleGetProfilePicture(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        httpsServer.createContext("/updateProfile", exchange -> {
            try {
                FileHandler.handleUpdateProfile(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        
        // User endpoints
        httpsServer.createContext("/searchUsers", exchange -> {
            try {
                UserHandler.handleSearchUsers(exchange);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
}

