package algorithms;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class AESCBCWithDiffieHellman {

    private static SecretKey sharedSecretKey;
    private static byte[] iv = new byte[16]; // Initialization vector for AES


    /**
     * Initializes the Diffie-Hellman parameters and generates the shared secret key.
     */
    public static void generateSharedSecret() throws Exception {
        // Generate Diffie-Hellman key pair
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Generate the shared secret key
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        // Simulate getting the other party's public key
        PublicKey otherPartyPublicKey = keyPair.getPublic(); // Replace this in a real scenario

        // Perform key agreement
        keyAgreement.doPhase(otherPartyPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Create a SecretKey for AES from the shared secret
        sharedSecretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES"); // Use 128 bits for AES
    }

    /**
     * Encrypts the given plaintext message using AES in CBC mode.
     *
     * @param plaintext The plaintext message to encrypt.
     * @return The Base64 encoded ciphertext.
     */
    public static String encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Generate random IV for each encryption
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, sharedSecretKey, ivSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Decrypts the given Base64 encoded ciphertext using AES in CBC mode.
     *
     * @param ciphertext The Base64 encoded ciphertext to decrypt.
     * @return The decrypted plaintext message.
     */
    public static String decrypt(String ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, sharedSecretKey, ivSpec);

        byte[] decodedCiphertext = Base64.getDecoder().decode(ciphertext);
        byte[] plaintext = cipher.doFinal(decodedCiphertext);
        return new String(plaintext);
    }
}
