package com.muratbilen;

import java.sql.*;

public class Database
{
	private static Connection connect()
	{
		String url = "jdbc:sqlite:C:\\Users\\MONSTER\\MuratSQL.db";
		Connection conn = null;
		try {
			conn = DriverManager.getConnection(url);
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
		return conn;
	}

	protected void insert(String name, String secretpassword, String salt, String type)
	{
		String sql = "INSERT INTO login(username,password,salt,type) VALUES(?,?,?,?)";

		try (Connection conn = this.connect();
			 PreparedStatement pstmt = conn.prepareStatement(sql)) {
			pstmt.setString(1, name);
			pstmt.setString(2, secretpassword);
			pstmt.setString(3, salt);
			pstmt.setString(4, type);
			pstmt.executeUpdate();
			System.out.println("Successful");
		} catch (SQLException e) {
			System.out.println(e.getMessage());
		}
	}

	protected boolean query(String name, String hashedloginpassword, String salt)
	{
		String queryString;


		try (Connection conn = this.connect();
			 PreparedStatement ps = conn.prepareStatement("SELECT password FROM login where username=?;")) {
			ps.setString(1, name);
			//set this values using PreparedStatement
			ResultSet results = ps.executeQuery();
			return results.getString("password").equals(hashedloginpassword);

		} catch (SQLException sql) {

			System.out.println(sql);
		}
		return false;
	}

	protected String getSalt(String name)
	{
		try (Connection conn = this.connect();
			 PreparedStatement ps = conn.prepareStatement("SELECT salt FROM login where username=?;")) {
			ps.setString(1, name);
			ResultSet results = ps.executeQuery();
			return results.getString("salt");
		} catch (SQLException sql) {
			System.out.println(sql);
		}
		return null;
	}


}
