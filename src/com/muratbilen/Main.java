package com.muratbilen;
import javax.crypto.Cipher;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Main
{
	private static final String initVector = "RandomInitVector";


	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		Database db = new Database();
		Scanner sc = new Scanner(System.in);
		Scanner scint = new Scanner(System.in);
		System.out.println("For login press 1, for signup press any key");
		if (scint.nextInt() == 1) {
			System.out.print("Please enter your name: ");
			String name = sc.nextLine();
			System.out.print("Please enter your password: ");
			String password = sc.nextLine();
			System.out.println("Please put the type of encryption in numbers");
			int type = sc.nextInt();
			String salt = db.getSalt(name);
			switch (type) {
				case 1:
					if (db.query(name, encryptAES("Bar12345Bar12345", initVector, password), null)) {
						System.out.println("You have logged in succesfully");
						break;
					} else {
						System.out.println("You have entered wrong");
						break;
					}

				case 2:
					if (db.query(name, getSha256(password, salt), salt)) {
						System.out.println("You have logged in successfully");
						break;
					}
					System.out.println("You have entered wrong please try again!");
					break;
				case 3:
					if (db.query(name, getSha512(password, salt), salt)) {
						System.out.println("You have logged in successfully");
						break;
					}
					System.out.println("Please try again!");
					break;
				case 4:
					if (db.query(name, getMd5(password, salt), salt)) {
						System.out.println("You have logged in successfully");
						break;
					}
					System.out.println("Please try again!");
					break;
				case 5:
					String salt1 = db.getSalt(name);
					if (db.query(name, Arrays.toString(getPBKDF2WithHmacSHA1(password, salt1)), salt1)) {
						System.out.println("You have logged in");
						break;
					} else {
						System.out.println("Please try again!");
						break;
					}
				case 6:
					break;
				default:
					System.out.println("You have typed the wrong number. Please try again!");
			}
		} else {
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
			String salt = bytesToHex(generateSalt());
			switch (algorithmselection) {
				case 1:
					db.insert(name, encryptAES("Bar12345Bar12345", initVector, password), null, "1");
					break;
				case 2:
					System.out.println(getSha256(password, salt));
					db.insert(name, getSha256(password, salt), salt, "2");
					break;

				case 3:
					System.out.println(getSha512(password, salt));
					db.insert(name, getSha512(password, salt), salt, "3");
					break;
				case 4:
					System.out.println(getMd5(password, salt));
					db.insert(name, getMd5(password, salt), salt, "4");
					break;

				case 5:
					try {
						db.insert(name, Arrays.toString(getPBKDF2WithHmacSHA1(password, salt)), salt, "5");
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
	}

	private static byte[] generateSalt() throws NoSuchAlgorithmException
	{
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		//Create array for salt
		byte[] salt = new byte[16];
		//Get a random salt
		sr.nextBytes(salt);
		//return salt
		return salt;
	}

	private static String encryptAES(String key, String initVector, String value)
	{
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

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

	private static String getSha256(String passwordToHash, String salt)
	{
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			if (!salt.isEmpty()) {
				md.update(salt.getBytes((StandardCharsets.UTF_8)));
			}
			byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
			return bytesToHex(bytes);
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}

	}

	private static String getSha512(String passwordToHash, String salt)
	{
		String generatedPassword = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			if (!salt.isEmpty()) {
				md.update(salt.getBytes(StandardCharsets.UTF_8));
			}
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

	private static String getMd5(String password, String salt)
	{
		try {
			// Static getInstance method is called with hashing MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			if (!salt.isEmpty()) {
				md.update(salt.getBytes(StandardCharsets.UTF_8));
			}
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

	protected static byte[] getPBKDF2WithHmacSHA1(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		int iterations = 1000;
		char[] chars = password.toCharArray();
		PBEKeySpec spec = new PBEKeySpec(chars, salt.getBytes(), iterations, 64 * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] hash = skf.generateSecret(spec).getEncoded();
		return hash;
	}

}
