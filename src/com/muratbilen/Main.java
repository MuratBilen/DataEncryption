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
import java.util.Base64;
import java.util.Scanner;

public class Main {

    private static final String key = "Bar12345Bar12345";
    private static final String initVector = "RandomInitVector";
    private static final String pepper="$eBGAea6N#7b9z$@8X``5[k49TDV[.";
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println(pepper);
        System.out.println("Do you want salt and pepper to be added in your password? Press 1 for yes");
        Scanner scString = new Scanner(System.in);
        Scanner scint=new Scanner(System.in);
        int methodselection=scint.nextInt();
        if (methodselection==1)
        {
            System.out.println("Please select the necessary option to proceed: ");
            System.out.println("1-AES password encryption");
            System.out.println("2-SHA-256 password hashing");
            System.out.println("3-SHA-512 password hashing");
            System.out.println("4-MD5 password hashing");
            System.out.println("5-PBKDF2WithHmacSHA1 hashing");
            System.out.println("6-Exit from the console");
            int algorithmselection = scint.nextInt();
            switch (algorithmselection)
            {
                case 1:

                    System.out.print("Please enter your name: ");
                    String name = scString.nextLine();

                    System.out.print("Please enter your password: ");
                    String result=encryptAES(key,initVector,scString.nextLine());
                    System.out.println(result);
                    break;
                case 2:
                    System.out.print("Please enter your name: ");
                     name = scString.nextLine();
                    System.out.print("Please enter your password: ");
                     result=getSha256(scString.nextLine());
                    System.out.println(result);
                     break;
                case 3:
                    System.out.print("Please enter your name: ");
                    name = scString.nextLine();
                    System.out.print("Please enter your password: ");
                    result=getSha512(scString.nextLine(), bytesToHex(getSalt()));
                    System.out.println(result);
                    break;
                case 4:
                    System.out.print("Please enter your name: ");
                    name = scString.nextLine();
                    System.out.print("Please enter your password: ");
                    result=getMd5(scString.nextLine());
                    System.out.println(result);
                    break;
                case 5:
                    System.out.print("Please enter your name: ");
                    name = scString.nextLine();
                    System.out.print("Please enter your password: ");
                    try {
                        result=getPBKDF2WithHmacSHA1(scString.nextLine());
                        System.out.println(result);
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
        else
        {



        }
    }
    private static byte[]  getSalt() throws NoSuchAlgorithmException
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

    public static String encryptAES(String key, String initVector, String value)
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
    public static String decryptAES(String key, String initVector, String encrypted) {
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
    public static String getSha256(String value)
    {
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(value.getBytes());
            return bytesToHex(md.digest());
        } catch(Exception ex){
            throw new RuntimeException(ex);
        }

    }
    public static String getSha512(String passwordToHash, String salt){
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            byte[] bytes = md.digest(passwordToHash.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++){
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        }
        catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return generatedPassword;
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
    public static String getMd5(String input)
    {
        try {
            // Static getInstance method is called with hashing MD5
            MessageDigest md = MessageDigest.getInstance("MD5");
            // digest() method is called to calculate message digest
            //  of an input digest() return array of byte
            byte[] messageDigest = md.digest(input.getBytes());
            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);
            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
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
