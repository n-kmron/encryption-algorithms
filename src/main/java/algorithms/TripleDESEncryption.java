package algorithms;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class TripleDESEncryption {

    // Clé hardcodée (24 octets pour 3DES)
    private static final String keyString = "0123456789abcdef01234567"; // 24 caractères (192 bits)

    /**
     * Encrypts the provided message using 3DES algorithm in ECB mode with PKCS5 padding.
     * The secret key is hardcoded and used to initialize the encryption process.
     * The encrypted result is encoded in Base64 for easy representation.
     *
     * @param message the plaintext message to be encrypted
     * @return the Base64-encoded encrypted message
     */

    public static String encrypt(String message) throws Exception {
        // Convert key into byte array
        byte[] keyBytes = keyString.getBytes();

        // DESede do refer to Triple DES and PCKS5Padding is a padding scheme to ensure the message is a multiple of 8 bytes
        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    /**
     * Decrypts the provided encrypted message using 3DES algorithm in ECB mode with PKCS5 padding.
     * The secret key is hardcoded and used to initialize the decryption process.
     * The encrypted message should be in Base64 format, which will be decoded before decryption.
     *
     * @param encryptedMessage the Base64-encoded encrypted message to be decrypted
     * @return the decrypted plaintext message
     */
    public static String decrypt(String encryptedMessage) throws Exception {
        // Convert key into byte array
        byte[] keyBytes = keyString.getBytes();

        SecretKey secretKey = new SecretKeySpec(keyBytes, "DESede");

        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decodedMessage = Base64.getDecoder().decode(encryptedMessage);

        byte[] decryptedMessage = cipher.doFinal(decodedMessage);

        return new String(decryptedMessage);
    }
}
