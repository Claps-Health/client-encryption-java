package claps.health.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class EncryptAES {
	private static final int AES_KEY_SIZE = 256;

	public static SecretKey generateAesKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(AES_KEY_SIZE);
		return keyGenerator.generateKey();
	}

	public static SecretKeySpec getAesSecretKey(byte[] key) throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(AES_KEY_SIZE, new SecureRandom(key));
		SecretKey secretKey = kg.generateKey();
		return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}

	public static final int SIZE_1K = 1024;
	public static Cipher getCipher(int mode, byte[] ivBytes, byte[] keyBytes)
			throws NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException{
		Security.addProvider(new BouncyCastleProvider());

		AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
		//Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		cipher.init(mode, newKey, ivSpec);
		return cipher;

	}
	public static byte[] aes_encrypt(byte[] ivBytes, byte[] keyBytes, byte[] data)
			throws NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			IllegalBlockSizeException,
			BadPaddingException
	{
		return getCipher(Cipher.ENCRYPT_MODE,ivBytes,keyBytes)
				.doFinal(data);
	}
	//will return max 1MB of cipher_text for mac
	public static ByteArrayOutputStream aes_encrypt_file(byte[] ivBytes, byte[] keyBytes, FileInputStream fileInputStream, FileOutputStream fileOutputStream, int maxCipherLengthForMac, ByteArrayOutputStream byteArrayOutputStream)
			throws NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException, IOException{

		Cipher cipher = getCipher(Cipher.ENCRYPT_MODE,ivBytes,keyBytes);
		CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher); // Read in the decrypted bytes and write the cleartext to out
		int numRead = 0;
		byte[] buf = new byte[SIZE_1K];
		while ((numRead = cipherInputStream.read(buf)) != -1) {
			fileOutputStream.write(buf, 0, numRead);
			//mac just need 1MB of cipher_text
			if(byteArrayOutputStream.size() < maxCipherLengthForMac){
				byteArrayOutputStream.write(buf, 0, numRead);
			}
		}
		cipherInputStream.close();
		return byteArrayOutputStream;
	}
	public static void aes_decrypt_file(byte[] ivBytes, byte[] keyBytes, FileInputStream fileInputStream, FileOutputStream fileOutputStream)
			throws NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,IOException
	{
		Cipher cipher = getCipher(Cipher.DECRYPT_MODE,ivBytes,keyBytes);
		CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream,cipher);
		int numRead = 0;
		byte[] buf = new byte[SIZE_1K];
		while ((numRead = fileInputStream.read(buf)) != -1) {
			cipherOutputStream.write(buf, 0, numRead);
		}
		cipherOutputStream.close();
	}

	public static byte[] aes_decrypt(byte[] ivBytes, byte[] keyBytes, byte[] data)
			throws NoSuchAlgorithmException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			IllegalBlockSizeException,
			BadPaddingException
	{
		return  getCipher(Cipher.DECRYPT_MODE,ivBytes,keyBytes)
				.doFinal(data);
	}
}
