package com.kingfisherchat.utils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Utility class for parsing multipart/form-data.
 */
public class MultipartUtils {
    
    /**
     * Locates the next boundary in the multipart body.
     */
    public static int locateBoundary(byte[] body, int startIndex, String boundary) {
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
    
    /**
     * Extracts headers from a multipart part.
     */
    public static String extractHeaders(byte[] part) {
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
    
    /**
     * Extracts file content from a multipart part.
     */
    public static byte[] extractFileContent(byte[] part) {
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
}

