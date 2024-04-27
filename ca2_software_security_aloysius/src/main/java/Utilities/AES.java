package Utilities;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;


/*
 * encrypts a file using AES encryption
 
 */

public class AES {
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final String salt = "chaosorbs";
    public static boolean encryptFile(String inputFile, String outputFile, String secretKey, boolean displayOutput) {
        try {
            File file = new File(inputFile);
            if (!file.exists()) {
                throw new FileNotFoundException("File not found: " + inputFile);
            }

            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivspec);

            FileInputStream inputStream = new FileInputStream(file);
            byte[] inputBytes = new byte[(int) file.length()];
            inputStream.read(inputBytes);
            inputStream.close();

            byte[] cipherText = cipher.doFinal(inputBytes);
            byte[] encryptedData = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

            // Add file format identifier at the start of the encrypted data so that we can identify the file format when decrypting
            byte[] fileFormatIdent = "ENCRYPTED".getBytes();
            // Adds the rest of the encrypted data to the file format identifier
            byte[] finalEncryptedData = new byte[fileFormatIdent.length + encryptedData.length];

            System.arraycopy(fileFormatIdent, 0, finalEncryptedData, 0, fileFormatIdent.length);
            System.arraycopy(encryptedData, 0, finalEncryptedData, fileFormatIdent.length, encryptedData.length);

            if (displayOutput) {
                System.out.println("Encrypted data: " + Arrays.toString(finalEncryptedData));
            }

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(finalEncryptedData);
            outputStream.close();

            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /*
     * Decrypts a file using AES encryption
     */
    public static boolean decryptFile(String inputFile, String outputFile, String secretKey,boolean displayOutput) {
        try {
            File file = new File(inputFile);
            if (!file.exists()) {
                throw new FileNotFoundException("File" + inputFile + "not found");
            }

            FileInputStream inputStream = new FileInputStream(file);
            byte[] inputBytes = new byte[(int) file.length()];
            inputStream.read(inputBytes);
            inputStream.close();

            byte[] fileFormatIdent = "ENCRYPTED".getBytes();
            if (!beginsWith(inputBytes, fileFormatIdent)) {
                throw new FileFormatNotIdentifiedException("File format not identified");
            }

            byte[] encryptedData = new byte[inputBytes.length - fileFormatIdent.length];
            System.arraycopy(inputBytes, fileFormatIdent.length, encryptedData, 0, encryptedData.length);

            byte[] iv = new byte[16];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), ITERATION_COUNT, KEY_LENGTH);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec);

            byte[] cipherText = new byte[encryptedData.length - iv.length];
            System.arraycopy(encryptedData, iv.length, cipherText, 0, cipherText.length);

            byte[] decryptedText = cipher.doFinal(cipherText);
            String decryptedString = new String(decryptedText);
            
            if (displayOutput) {
                System.out.println();
                System.out.println("Decrypted text : " + decryptedString);
                System.out.println();
            }
            
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(decryptedText);
            outputStream.close();

            return true;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (FileFormatNotIdentifiedException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static boolean beginsWith(byte[] arr, byte[] pref) {
        if (arr.length < pref.length) {
            return false;
        }
        for (int i = 0; i < pref.length; i++) {
            if (arr[i] != pref[i]) {
                return false;
            }
        }
        return true;
    }
    
}




    