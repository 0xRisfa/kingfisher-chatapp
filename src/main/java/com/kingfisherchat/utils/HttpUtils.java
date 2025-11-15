package com.kingfisherchat.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for HTTP-related operations.
 */
public class HttpUtils {
    
    /**
     * Parses a simple JSON string into a Map.
     * Note: This is a simple parser for basic JSON. For complex JSON, use Gson.
     */
    public static Map<String, String> parseJson(String json) {
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
    
    /**
     * Gets the MIME type for a file path.
     */
    public static String getMimeType(String path) {
        if (path.endsWith(".html")) return "text/html";
        if (path.endsWith(".css")) return "text/css";
        if (path.endsWith(".js")) return "application/javascript";
        if (path.endsWith(".png")) return "image/png";
        if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
        if (path.endsWith(".gif")) return "image/gif";
        if (path.endsWith(".json")) return "application/json";
        return "application/octet-stream";
    }
}

