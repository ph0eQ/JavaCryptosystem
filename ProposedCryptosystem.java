
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.*;
/**
 * In our proposed cryptosystem we will use AES-128-CTR to provide Confidentiality and HMACSHA256 to provide Authenticity and Integrity.
 * Ideally we would have used AES-256 but the basic installation of Java only allows up 128. We chose CTR mode of AES-128 so we would not
 * have to worry about padding.
 * Sources:
 * https://docs.oracle.com/javase/7/docs/api/javax/crypto
 * www.ietf.org/rfc/rfc2898
 * www.ietf.org/rfc/rfc7366
 * www.gladman.me.uk/cryptography_technolgy/fileencrypt/
 * netnix.org/2015/04/19/aes-encryption-with-hmac-integrity-in-java
 * @author Sean Hoyt, Nina Chepovska, Shelema Bekele
 */
public class ProposedCryptosystem {
	
	public static byte[] getBytesFromFile(String pathname) throws IOException{
		byte[] bytes = Files.readAllBytes(new File(pathname).toPath());
		return bytes;
		
	}
	public static void writeBytesToFile(String pathname, byte[] bytes) throws IOException {
		Files.write(new File(pathname).toPath(), bytes, StandardOpenOption.CREATE);	
	}
	/**This method will take an input byte array and password, from these it will use Secure random to generate salts and IV for AES-128-CTR and HMACSHA256, 
	 * these salts are then used to derive keys for both AES and HMAC256 using PBKDF2WithHmacSHA1. These are later stored in the final output. After keys are calculated,
	 * the byte array input is then encrypted with AES-128-CTR mode, and then a HMACSHA256 on the ciphertext (Encrypt then MAC). A  byte array containing IV || eSalt|| hSalt|| eMessage || hMac is returned.
	 * 
	 * At this point we can
	 * 
	 * @param input Array of bytes
	 * @param password password to derive keys from
	 * @return Returns byte array containing IV || eSalt|| hSalt|| eMessage || hMac
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] encrypt(byte[] input, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		SecureRandom rando = SecureRandom.getInstance("SHA1PRNG");
		//generate IV for AES-CTR mode sets the counter to random value from secure random
		byte[] IV = new byte[16];
		rando.nextBytes(IV);
		
		//generate eSalt for use with password derived key AES, to be used with PBKDF2WithHmacSHA1
		byte[] eSalt = new byte[20];
		rando.nextBytes(eSalt);
		
		//generate hSalt for use with password derived key for HMAC, to be used with PBKDF2WithHmacSHA1
		byte[] hSalt = new byte[20];
		rando.nextBytes(hSalt);
		
		SecretKeyFactory fact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		
		//generate eKey from eSalt and password, key to be used for AES-128-CTR mode, computed with PBKDF2WithHmacSHA1 
		KeySpec eKS = new PBEKeySpec(password.toCharArray(), eSalt, 10000, 128);
		SecretKey eS = fact.generateSecret(eKS);
		Key eK = new SecretKeySpec(eS.getEncoded(), "AES");
		//encrypt plaintext bytes in AES-128-CTR with eKey and IV
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, eK, new IvParameterSpec(IV));
		byte[] eMessage = cipher.doFinal(input); 
		
		// we compute the HMACSHA256 on the ciphertext according to RFC7366 (Encrypt then MAC)
		//generate hKey from hSalt and password, key to be used for HMACSHA256, computed with PBKDF2WithHmacSHA1
		
		KeySpec hKS = new PBEKeySpec(password.toCharArray(), hSalt, 10000, 160);
		SecretKey hS = fact.generateSecret(hKS);
		Key hK = new SecretKeySpec(hS.getEncoded(), "HMACSHA256");
		Mac mac = Mac.getInstance("HMACSHA256");
		mac.init(hK);
		byte[] hMac = mac.doFinal(eMessage);
		
		//now we put all into new byte[] 
		
		byte[] output = new byte[16 + 40 + eMessage.length + 32];
		System.arraycopy(IV, 0, output, 0, 16);
		System.arraycopy(eSalt, 0, output, 16, 20);
		System.arraycopy(hSalt, 0, output, 36, 20);
		System.arraycopy(eMessage, 0, output, 56, eMessage.length);
		System.arraycopy(hMac, 0, output, 56 + eMessage.length, 32);
		
		return output;	
	}
	/**
	 * In this method we will recover our IV eSalt, hSalt, eMessage and hMac from the cipher block input as a byte array.
	 * It will first recompute the HMACSHA256 and compare with the HMACSHA256 sent with message. If 
	 * @param input
	 * @param password
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] decrypt(byte[] input, String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		//recover IV
		byte[] IV = Arrays.copyOfRange(input, 0, 16);
		
		//recover eSalt
		byte[] eSalt = Arrays.copyOfRange(input, 16, 36);
		
		//recover hSalt
		byte[] hSalt = Arrays.copyOfRange(input, 36, 56);
		
		//recover eMessage
		byte[] eMessage = Arrays.copyOfRange(input, 56, input.length - 32);
		
		//recover hmac
		byte[] hMac = Arrays.copyOfRange(input, input.length -32, input.length);
		
		SecretKeyFactory fact = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		
		//first we check to see if the HMAC of the input matches the recomputed HMAC
		KeySpec rhKS = new PBEKeySpec(password.toCharArray(),hSalt, 10000, 160);
		SecretKey rHS = fact.generateSecret(rhKS);
		Key rhK = new SecretKeySpec(rHS.getEncoded(), "HMACSHA256");
		Mac rMac = Mac.getInstance("HMACSHA256");
		rMac.init(rhK);
		byte [] rhMac = rMac.doFinal(eMessage);
		byte [] pMessage = null;
		
		boolean sameHash = true;
		for(int i =0; i < rhMac.length && sameHash == true; i++){
			if(hMac[i] != rhMac[i]){
				sameHash = false;
			}
		}
		if(sameHash == true){
			//generate eKey from eSalt and password, key to be used for AES-128-CTR mode, computed with PBKDF2WithHmacSHA1 
			KeySpec eKS = new PBEKeySpec(password.toCharArray(), eSalt, 10000, 128);
			SecretKey eS = fact.generateSecret(eKS);
			Key eK = new SecretKeySpec(eS.getEncoded(), "AES");
			//decrypt plaintext bytes in AES-128-CTR with eKey and IV
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, eK, new IvParameterSpec(IV));
			pMessage = cipher.doFinal(eMessage);
			return pMessage;
		}else {
			//lame error message but didn't want to write custom errors just yet. 
			System.err.println("Error cannot decrypt, SHA256 of Ciphertext and Recomputed Ciphertext do not match, Data has been modified or wrong password supplied.");
		}
		return pMessage;
		
		
	}
	/**
	 * Main to run a quick test to output
	 * @param args
	 */
	public static void main(String[] args) {
		try{
			byte[] input = getBytesFromFile("/home/ph0e/Documents/TCSS481/TCSS481_Midterm_Implementation/src/Midterm_input_bytes.bin");
			byte[] encrypted = encrypt(input, "hahahahahahahaahahaha");
			//writeBytesToFile("/home/ph0e/Documents/TCSS481/TCSS481_Midterm_Implementation/src/Midterm_input_bytes_encrypted.bin", encrypted);
			byte[] decrypted = decrypt(input, "hahahahahahahaahahaha");
			if(decrypted != null){
			writeBytesToFile("/home/ph0e/Documents/TCSS481/TCSS481_Midterm_Implementation/src/Midterm_input_bytes_decrypted_modified.bin", decrypted);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//String initialFileInput = ""
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	

}
