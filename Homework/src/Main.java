import crypto.RSA;

public class Main {
    public static void main(String[] args) {
        RSA rsa = new RSA(2048);

        String message = "### Compiles and hot-reloads for development";
        byte[] ciphertext = rsa.encryptText(message);
        String decryptedText = rsa.decryptText(ciphertext);

        System.out.println("Message: " + message);
        System.out.println("Encrypted: " + ciphertext);
        System.out.println("Decrypted: " + decryptedText);
    }
}