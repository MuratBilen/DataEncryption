package com.muratbilen;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class Database
{
	private static Connection connect()
	{
		// SQLite connection string
		String url = "jdbc:sqlite:C:\\Users\\MONSTER\\MuratSQL.db";
		Connection conn = null;
		try {
			conn = DriverManager.getConnection(url);
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		return conn;
	}

	protected void insert(String name, String secretpassword, String salt)
	{
		String sql = "INSERT INTO login(username,password,salt) VALUES(?,?,?)";

		try (Connection conn = this.connect();
			 PreparedStatement pstmt = conn.prepareStatement(sql)) {
			pstmt.setString(1, name);
			pstmt.setString(2, secretpassword);
			pstmt.setString(3, salt);
			pstmt.executeUpdate();
			System.out.println("Successful");
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
	}

	protected void insert(String name, String secretpassword)
	{
		String sql = "INSERT INTO login(username,password,salt) VALUES(?,?,?)";

		try (Connection conn = this.connect();
			 PreparedStatement pstmt = conn.prepareStatement(sql)) {
			pstmt.setString(1, name);
			pstmt.setString(2, secretpassword);
			pstmt.setString(3, null);
			pstmt.executeUpdate();
			System.out.println("Successful");
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
	}
}
