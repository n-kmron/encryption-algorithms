package cnoupoue;

import algorithms.AESCBCWithDiffieHellman;
import algorithms.TripleDESEncryption;

import static algorithms.TripleDESEncryption.*;
import static algorithms.AESCBCWithDiffieHellman.*;

public class Main {
    public static void main(String[] args) {
        try {
            String message = "Nouveau message";

            // Encryption with 3DES
            String encryptedMessage3DES = TripleDESEncryption.encrypt(message);
            System.out.println("Crypted message with 3DES : " + encryptedMessage3DES);

            // Decryption with 3DES
            String decryptedMessage3DES = TripleDESEncryption.decrypt(encryptedMessage3DES);
            System.out.println("Decrypted message with 3DES: " + decryptedMessage3DES);

        } catch (Exception e) {
            e.printStackTrace();
        }


        try {
            AESCBCWithDiffieHellman.generateSharedSecret(); // Generate the shared secret key

            String message = "Nouveau message";

            String encryptedMessage = AESCBCWithDiffieHellman.encrypt(message);
            System.out.println("Crypted message with AES: " + encryptedMessage);

            String decryptedMessageDH = AESCBCWithDiffieHellman.decrypt(encryptedMessage);
            System.out.println("Decrypted message with AES: " + decryptedMessageDH);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}