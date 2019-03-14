/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.rcibanque.common.util;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.lang3.CharEncoding;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

public class HashPassword {
	private static final String CLASS_NAME = HashPassword.class.getName();
	private static Logger log = Logger.getLogger(CLASS_NAME);

	public static final int METHODE_HASH_SHA_256 = 0;
	public static final int METHODE_PBKDF2WithHmacSHA1 = 1;
	private static final int DEFAULT_SIZE = 32;

	public static final String SHA256_ALGORITHM = "SHA-256";
	public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";

	private static final SecureRandom RANDOM = new SecureRandom();

	public static final int SALT_BYTE_SIZE = 24;
	public static final int HASH_BYTE_SIZE = 24;
	public static int ITERATIONS = 1000;

	private static int METHOD_HASH;
	
	
	public static String getSaltHexa() {
		return toHex(getSalt(DEFAULT_SIZE));
	}

	public static byte[] getSalt(int size) {
		final byte[] salt;
		if (size < 32) {
			System.err.println("salt is set to defaut value : " + DEFAULT_SIZE);
			salt = new byte[DEFAULT_SIZE];
		} else {
			salt = new byte[size];
		}
		RANDOM.nextBytes(salt);
		return salt;
	}

	public static byte[] hashPBKDF2WithHmacSHA1(String password, String salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
		return hashPBKDF2WithHmacSHA1(password.toCharArray(),
				salt.getBytes(CharEncoding.UTF_8));
	}

	public static byte[] hashPBKDF2WithHmacSHA1(char[] password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		// Hash the password
		byte[] hash = pbkdf2(password, salt, ITERATIONS, HASH_BYTE_SIZE);
		// format iterations:salt:hash
		// return ITERATIONS + ":" + toHex(salt) + ":" + toHex(hash);
		return hash;
	}

	private static byte[] fromHex(String hex) {
		byte[] binary = new byte[hex.length() / 2];
		for (int i = 0; i < binary.length; i++) {
			binary[i] = (byte) Integer.parseInt(
					hex.substring(2 * i, 2 * i + 2), 16);
		}
		return binary;
	}

	private static String toHex(byte[] array) {
		BigInteger bi = new BigInteger(1, array);
		String hex = bi.toString(16);
		int paddingLength = (array.length * 2) - hex.length();
		if (paddingLength > 0)
			return String.format("%0" + paddingLength + "d", 0) + hex;
		else
			return hex;
	}

	private static byte[] pbkdf2(char[] password, byte[] salt, int iterations,
			int bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
		SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
		return skf.generateSecret(spec).getEncoded();
	}

	public static String hash(final String password, final String saltHexa,
			int hashMethod, int iterations){

		byte[] hash = null;
		if (StringUtils.isBlank(password)) {
			log.error("Password must not be null");
			return null;
		}
		if (StringUtils.isBlank(saltHexa)) {
			log.error("Salt must not be null");
			return null;
		}
		if (iterations >= 1000 && iterations <= 10000) {
			ITERATIONS = iterations;
		} else if (iterations > 10000) {
			log.info("iteration set to default value : " + ITERATIONS);
		}
		
		
		try{
			METHOD_HASH = hashMethod;
			
			switch (hashMethod) {
			
				case METHODE_HASH_SHA_256:
					hash = hashSha256(password, new String(fromHex(saltHexa), CharEncoding.UTF_8));
					break;
					
				case METHODE_PBKDF2WithHmacSHA1:
					hash = hashPBKDF2WithHmacSHA1(password, new String(fromHex(saltHexa), CharEncoding.UTF_8));			
					break;
				}
		}catch(Exception e){
			log.error("Exception " + " hash " + e);
		}
		
		return toHex(hash);
	}

	
	
	private static byte[] hashSha256(final String password, final String salt) throws Exception {
		byte[] hash;
		
		MessageDigest md = MessageDigest.getInstance(SHA256_ALGORITHM);
		hash = md.digest((password + salt).getBytes(CharEncoding.UTF_8));

		for (int i = 0; i < ITERATIONS; i++) {
			md.reset();
			hash = md.digest(hash);
		}		
		return hash;
	}
	
	private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
	
	
	public static boolean isCorrectPassword(String password, String storedhashHexa, String salt){				
		boolean res = false;			
		
		try{
			byte[] hash = null;			
			switch (METHOD_HASH) {
			case METHODE_HASH_SHA_256:				
				hash = hashSha256(password, new String(fromHex(salt), CharEncoding.UTF_8));
				break;
			case METHODE_PBKDF2WithHmacSHA1:
				hash = hashPBKDF2WithHmacSHA1(password, new String(fromHex(salt), CharEncoding.UTF_8));				
				break;				
			}
			
			res = slowEquals(fromHex(storedhashHexa), hash);
			
		}catch(Exception e){
			log.error("Exception isCorrectPassword "+e);
		}		
		return res;
	}

}
