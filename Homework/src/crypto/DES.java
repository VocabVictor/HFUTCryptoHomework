package crypto;

import java.util.Arrays;

public class DES extends CryptoAlgorithm {
    private long key;

    public DES(long key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] data) {
        byte[] paddedData = pkcs5Pad(data);
        byte[] encryptedData = new byte[paddedData.length];

        for (int i = 0; i < paddedData.length; i += 8) {
            long block = bytesToLong(paddedData, i);
            long encryptedBlock = encryptBlock(block);
            longToBytes(encryptedBlock, encryptedData, i);
        }
        return encryptedData;
    }

    public byte[] decrypt(byte[] encryptedData) {
        if (encryptedData.length % 8 != 0) {
            throw new IllegalArgumentException("Data length must be a multiple of 8 bytes.");
        }

        byte[] decryptedData = new byte[encryptedData.length];
        for (int i = 0; i < encryptedData.length; i += 8) {
            long block = bytesToLong(encryptedData, i);
            long decryptedBlock = decryptBlock(block);
            longToBytes(decryptedBlock, decryptedData, i);
        }
        return pkcs5Unpad(decryptedData);
    }

    private byte[] pkcs5Pad(byte[] data) {
        int blockSize = 8;
        int paddingSize = blockSize - (data.length % blockSize);
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingSize);
        for (int i = 0; i < paddingSize; i++) {
            paddedData[data.length + i] = (byte) paddingSize;
        }
        return paddedData;
    }

    private byte[] pkcs5Unpad(byte[] paddedData) {
        int paddingSize = paddedData[paddedData.length - 1] & 0xFF;
        return Arrays.copyOf(paddedData, paddedData.length - paddingSize);
    }

    private long encryptBlock(long block) {
        // Implement your custom DES encryption logic here
        return block ^ key; // This is a simplified example and NOT secure
    }

    private long decryptBlock(long encryptedBlock) {
        // Implement your custom DES decryption logic here
        return encryptedBlock ^ key; // This is a simplified example and NOT secure
    }

    private static long bytesToLong(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= ((long) bytes[offset + i] & 0xFF) << (8 * i);
        }
        return value;
    }

    private static void longToBytes(long value, byte[] bytes, int offset) {
        for (int i = 0; i < 8; i++) {
            bytes[offset + i] = (byte) ((value >>> (8 * i)) & 0xFF);
        }
    }
}
