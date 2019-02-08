package com.muratbilen;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.Base64;
import java.util.Scanner;

public class Main
{
	private static final String initVector = "RandomInitVector";
	private static final String pepper = "$eBGAea6N#7b9z$@8X``5[k49TDV[.";


	public static void main(String[] args) throws NoSuchAlgorithmException
	{
		Database db=new Database();
		Scanner sc = new Scanner(System.in);
		Scanner scint = new Scanner(System.in);
		System.out.print("Please enter your name: ");
		String name = sc.nextLine();
		System.out.print("Please enter your password: ");
		String password = sc.nextLine();
		System.out.println("Please select the necessary option to proceed: ");
		System.out.println("1-AES password encryption");
		System.out.println("2-SHA-256 password hashing");
		System.out.println("3-SHA-512 password hashing");
		System.out.println("4-MD5 password hashing");
		System.out.println("5-PBKDF2WithHmacSHA1 hashing");
		System.out.println("6-Exit from the console");
		int algorithmselection = sc.nextInt();
		switch (algorithmselection) {
			case 1:
				// TODO: 8.02.2019 Fix AES key size
				encryptAES(initVector, password);
				break;
			case 2:
				if (checkSaltOption()) {
					String salt = bytesToHex(getSalt());
					System.out.println(getSha256(password, salt));
					db.insert(name, getSha256(password, salt), salt);
					break;
				}
				System.out.println(getSha256(password));
				db.insert(name,getSha256(password));
				break;
			case 3:
				if (checkSaltOption()) {
					String salt = bytesToHex(getSalt());
					System.out.println(getSha512(password, salt));
					db.insert(name, getSha512(password,salt),salt);
					break;
				}
				System.out.println(getSha512(password));
				db.insert(name, getSha512(password));
				break;
			case 4:
				if (checkSaltOption()) {
					String salt = bytesToHex(getSalt());
					System.out.println(getMd5(password, salt));
					db.insert(name,getMd5(password,salt),salt);
					break;
				}
				System.out.println(getMd5(password));
				db.insert(name,password);
				break;
			case 5:
				try {
					System.out.println(getPBKDF2WithHmacSHA1(password));
				} catch (InvalidKeySpecException e) {
					e.printStackTrace();
				}
				break;
			case 6:
				break;
			default:
				System.out.println("You have typed in the wrong number. Please try again!");
		}
	}



	private static boolean checkSaltOption()
	{
		System.out.println("Do you want salt to be added in your password? Press 1 for yes");
		Scanner scString = new Scanner(System.in);
		if (scString.nextInt() == 1) {
			return true;
		}
		return false;
	}

	private static byte[] getSalt() throws NoSuchAlgorithmException
	{
		//Always use a SecureRandom generator
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt;
	}

	private static String encryptAES(String initVector, String value)
	{
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(16);
			String secretKey = keyGen.generateKey().toString();
			SecretKeySpec skeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			byte[] encrypted = cipher.doFinal(value.getBytes());
			System.out.println("encrypted string: "
					+ new String(Base64.getEncoder().encode(encrypted)));

			return new String(Base64.getEncoder().encode(encrypted));
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}



	private static String decryptAES(String key, String initVector, String encrypted)
	{
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

			byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	private static String getSha256(String passwordToHash, String salt)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(salt.getBytes((StandardCharsets.UTF_8)));
			byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
			return bytesToHex(bytes);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String getSha256(String passwordToHash)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(passwordToHash.getBytes());
			return bytesToHex(md.digest());
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static String getSha512(String passwordToHash)
	{
		String generatedPassword = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;

	}

	private static String getSha512(String passwordToHash, String salt)
	{
		String generatedPassword = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(salt.getBytes(StandardCharsets.UTF_8));
			byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword;
	}

	private static String bytesToHex(byte[] bytes)
	{
		StringBuffer result = new StringBuffer();
		for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
		return result.toString();
	}

	private static String getMd5(String password)
	{
		try {
			// Static getInstance method is called with hashing MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			// digest() method is called to calculate message digest
			//  of an input digest() return array of byte
			byte[] messageDigest = md.digest(password.getBytes());
			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);
			// Convert message digest into hex value
			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}

	}

	private static String getMd5(String password, String salt)
	{
		try {
			// Static getInstance method is called with hashing MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(salt.getBytes(StandardCharsets.UTF_8));
			// digest() method is called to calculate message digest
			//  of an input digest() return array of byte
			byte[] messageDigest = md.digest(password.getBytes());
			// Convert byte array into signum representation
			BigInteger no = new BigInteger(1, messageDigest);
			// Convert message digest into hex value
			String hashtext = no.toString(16);
			while (hashtext.length() < 32) {
				hashtext = "0" + hashtext;
			}
			return hashtext;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	private static String getPBKDF2WithHmacSHA1(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		int iterations = 1000;
		char[] chars = password.toCharArray();
		byte[] salt = getSalt();

		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return iterations + ":" + bytesToHex(salt) + ":" + bytesToHex(hash);

	}

}
