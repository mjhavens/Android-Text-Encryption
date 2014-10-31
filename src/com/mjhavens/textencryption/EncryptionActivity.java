/*
 * @author: MJ Havens
 * 
 * This class is mainly used for encrypting purposes.
 * It encrypts, decrypts, encodes, and decodes plaintext and ciphertext.
 */
package com.mjhavens.textencryption;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.util.Log;

public class EncryptionActivity extends Activity
{
	private byte[]	encryptedText	= null;
    private String base64CipherText = null;
    private byte[] textBytes = null;
    private byte[] secretKeyBytes = null;
    private String strdecryptedText;
    private byte[] secretKeyInBytes = null;
    
    /**
     * The default constructor sets all variables to null.
     */
	public EncryptionActivity()
	{
		encryptedText	= null;
	    base64CipherText = null;
	    textBytes = null;
	    secretKeyBytes = null;
	    strdecryptedText = null;
	}
	
	/**
	 * 
	 * @param secretKey the secret key for the encryption.
	 * 
	 * This method generates a key based on the secret key 
	 * and a initialization vector using AES.
	 */
	public void prepareKeyForEncryption(String secretKey) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, IOException
	{
		
		secretKeyBytes = secretKey.getBytes("UTF-8");

		// This generates cryptographically secure random numbers using AES in ECB mode.
		SecureRandom sR = SecureRandom.getInstance("SHA1PRNG");
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		sR.setSeed(secretKeyBytes);
		Log.d("App", "Secret key in bytes: " + secretKeyBytes);
		Log.d("App", "SecureRandom string: " + sR.toString());

		// Initialize the 128 bit key generator using the secret key and AES.
		keyGen.init(128, sR);

		// Generate the actual 128 bit key based on the secret key and AES.
		SecretKey skey = keyGen.generateKey();

		// The bytes for the secret key that was generated.
		secretKeyBytes = skey.getEncoded();

	}

	/**
	 * 
	 * @param encryptedKey the key that was encrypted based on the prepareKeyForEncryption() method.
	 * @param textToEncrypt The plaintext that needs to be encrypted to ciphertext.
	 *
	 * Uses AES/ECB to encrypt the plaintext based on the encrypted secret key.
	 */
	public void encryptWithAES(byte[] encryptedKey, String textToEncrypt)
			throws IllegalBlockSizeException, BadPaddingException,
			NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, UnsupportedEncodingException
	{
		textBytes = textToEncrypt.getBytes("UTF-8");
		Log.d("App", "encrypted key: " + encryptedKey);

		SecretKeySpec sKey = new SecretKeySpec(encryptedKey, "AES");
		Cipher c = Cipher.getInstance("AES/ECB/PKCS7Padding");
		c.init(Cipher.ENCRYPT_MODE, sKey);
		Log.d("App", "encrypted skey: " + sKey);
		encryptedText = c.doFinal(textBytes);
		Log.d("App", "Encrypted bytes: " + encryptedText);
		encodeToBase64(encryptedText);
		

	}

	/**
	 * @param encryptedText The output of the encrypted text in bytes.
	 * 
	 * Uses the bytes of the ciphertext to encode it to base 64.
	 */
	private void encodeToBase64(byte[] encryptedText)
	{
		
		base64CipherText = Base64.encodeBytes(encryptedText);	
		Log.d("App", "Base 64 encrypted text: " + base64CipherText);
	}
	
	/**
	 * 
	 * @param base64CipherText The cipher text encoded with base 64.
	 * @return The bytes of the ciphertext.
	 */
	private byte[] decodeFromBase64(String base64CipherText) throws IOException
	{
		byte[] cipherText = Base64.decode(base64CipherText);
		return cipherText;
		
	}
	
	/**
	 * 
	 * @param encryptedKey The AES encrypted key.
	 * @param base64CipherText The base 64 encoded cipher text.
	 * 
	 * Decrypts the AES base 64 encoded ciphertext into plaintext.
	 */
	public void decryptAES(byte[] encryptedKey, String base64CipherText)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException
	{

		SecretKeySpec sKey = new SecretKeySpec(encryptedKey, "AES");
		Cipher c = Cipher.getInstance("AES");
		c.init(Cipher.DECRYPT_MODE, sKey);
		strdecryptedText = new String(c.doFinal(decodeFromBase64(base64CipherText)));
		Log.d("App", "Plaintext: " + strdecryptedText);
	}
	
	/**
	 * @return The plaintext.
	 */
	public String getDecryptedText()
	{
		return strdecryptedText;
	}
	
	/**
	 * @return The secret key in bytes.
	 */
	public byte[] getSecretKeyBytes()
	{
		return secretKeyBytes;
	}

	/**
	 * @return The ciphertext encoded in base 64.
	 */
	public String getBase64CipherText()
	{
		Log.d("APP", "base64CipherText: " + base64CipherText);
		return base64CipherText;
	}
}
