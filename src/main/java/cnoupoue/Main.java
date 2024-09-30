package cnoupoue;

import algorithms.TripleDESEncryption;

import static algorithms.TripleDESEncryption.decrypt;
import static algorithms.TripleDESEncryption.encrypt;

public class Main {
    public static void main(String[] args) {
        try {
            String message = "Mon message a encrypter";

            // Encryption with 3DES
            String encryptedMessage = encrypt(message);
            System.out.println("Crypted message : " + encryptedMessage);

            // Decryption with 3DES
            String decryptedMessage = decrypt(encryptedMessage);
            System.out.println("Decrypted message : " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}