package crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public abstract class CryptoAlgorithm {

    public abstract byte[] encrypt(byte[] data);

    public abstract byte[] decrypt(byte[] data);

    public byte[] encryptText(String inputText) {
        byte[] inputData = inputText.getBytes();
        byte[] encryptedData = encrypt(inputData);
        return encryptedData;
    }

    public String decryptText(byte[] encryptedText) {
        byte[] decryptedData = decrypt(encryptedText);
        return new String(decryptedData);
    }

    public void encryptFile(String inputFilePath, String outputFilePath) throws IOException {
        Path inputFile = Paths.get(inputFilePath);
        byte[] inputData = Files.readAllBytes(inputFile);
        byte[] encryptedData = encrypt(inputData);
        Path outputFile = Paths.get(outputFilePath);
        Files.write(outputFile, encryptedData);
    }

    public void decryptFile(String inputFilePath, String outputFilePath) throws IOException {
        Path inputFile = Paths.get(inputFilePath);
        byte[] encryptedData = Files.readAllBytes(inputFile);
        byte[] decryptedData = decrypt(encryptedData);
        Path outputFile = Paths.get(outputFilePath);
        Files.write(outputFile, decryptedData);
    }
}
