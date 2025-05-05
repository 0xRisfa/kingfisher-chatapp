package com.kingfisherchat;

import java.sql.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class UserAuthentication {

    public static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

// User login method
public static boolean login(String username, String password) {
    String sqlQuery = "SELECT PASSWORD FROM ZAK_USERS WHERE USERNAME = ?";

    try (Connection connection = MySqlConnection.getConnection();
         PreparedStatement stmt = connection.prepareStatement(sqlQuery)) {

        stmt.setString(1, username);
        System.out.println("Executing query for username: " + username); // DEBUG LOG

        ResultSet rs = stmt.executeQuery();

        if (rs.next()) {
            String storedHash = rs.getString("PASSWORD");
            System.out.println("Retrieved password hash from DB: " + storedHash); // DEBUG LOG

            System.out.println(encoder.encode(password));

            boolean isMatch = encoder.matches(password, storedHash);
            System.out.println("Password match result: " + isMatch); // DEBUG LOG
            
            return isMatch;
        } else {
            System.out.println("User not found: " + username); // DEBUG LOG
        }

    } catch (SQLException e) {
        e.printStackTrace();
        System.out.println("SQL Exception: " + e.getMessage()); // DEBUG LOG
    }

    return false; // User not found or incorrect password
}

    // User registration method
    public static boolean registerUser(String username, String password) {
        String hashedPassword = encoder.encode(password); // Hash the password before storing
        String sql = "INSERT INTO ZAK_USERS (USERNAME, PASSWORD) VALUES (?, ?)";

        try (Connection connection = MySqlConnection.getConnection();
             PreparedStatement stmt = connection.prepareStatement(sql)) {

            stmt.setString(1, username);
            stmt.setString(2, hashedPassword);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;// Registration failed due to SQL error or duplicate username
        }
    }
}
