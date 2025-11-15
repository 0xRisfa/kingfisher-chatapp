package com.kingfisherchat.utils;

import com.kingfisherchat.MySqlConnection;
import java.sql.*;

/**
 * Utility class for common database operations.
 */
public class DatabaseUtils {
    
    /**
     * Gets the user ID from a username.
     */
    public static int getIdFromUsername(String username) {
        int userId = -1;
        String getUserIdSql = "SELECT ID FROM ZAK_USERS WHERE USERNAME = ?";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement getUserIdStmt = connection.prepareStatement(getUserIdSql)) {
    
            getUserIdStmt.setString(1, username.trim());
            ResultSet rs = getUserIdStmt.executeQuery();
            if (rs.next()) {
                userId = rs.getInt("ID");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userId;
    }
    
    /**
     * Gets the username from a user ID.
     */
    public static String getUsernameFromId(int userId) {
        String username = null;
        String sql = "SELECT USERNAME FROM ZAK_USERS WHERE ID = ?";
        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                username = rs.getString("USERNAME");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return username;
    }
}

