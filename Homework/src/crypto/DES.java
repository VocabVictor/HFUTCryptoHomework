/**
 DES 对称加密算法实现
 作者: VocabVictor
 创建时间: 2023-05-06
 文件用途:
 该文件实现了 DES 对称加密算法，提供了加密和解密函数。
 DES 加密算法是一种经典的对称加密算法，可用于数据加密等领域。
 该实现支持 PKCS5 填充和去填充，能够加密任意长度的数据。
 */
package crypto;

import java.util.Arrays;

public class DES extends CryptoAlgorithm {
    private long key;

    /**
     * DES算法的构造函数，用于初始化DES对象的密钥
     *
     * @param key 一个long类型的密钥
     */
    public DES(long key) {
        this.key = key;
    }

    /**
     * 对数据进行DES加密
     *
     * @param data 待加密的数据
     * @return 加密后的数据
     */
    public byte[] encrypt(byte[] data) {
        byte[] paddedData = pkcs5Pad(data); // 对数据进行PKCS5填充
        byte[] encryptedData = new byte[paddedData.length]; // 创建一个和填充后的数据长度一样的字节数组

        // 逐个分组加密数据
        for (int i = 0; i < paddedData.length; i += 8) {
            long block = bytesToLong(paddedData, i); // 将8个字节转换成一个long类型的数据块
            long encryptedBlock = encryptBlock(block); // 对数据块进行加密
            longToBytes(encryptedBlock, encryptedData, i); // 将加密后的数据块存入字节数组中
        }

        return encryptedData;
    }

    /**
     * 对数据进行DES解密
     *
     * @param encryptedData 待解密的数据
     * @return 解密后的数据
     * @throws IllegalArgumentException 当数据长度不是8的倍数时抛出异常
     */
    public byte[] decrypt(byte[] encryptedData) throws IllegalArgumentException {
        if (encryptedData.length % 8 != 0) { // 判断数据长度是否是8的倍数
            throw new IllegalArgumentException("Data length must be a multiple of 8 bytes."); // 如果不是，则抛出异常
        }

        byte[] decryptedData = new byte[encryptedData.length]; // 创建一个和加密后的数据长度一样的字节数组

        // 逐个分组解密数据
        for (int i = 0; i < encryptedData.length; i += 8) {
            long block = bytesToLong(encryptedData, i); // 将8个字节转换成一个long类型的数据块
            long decryptedBlock = decryptBlock(block); // 对数据块进行解密
            longToBytes(decryptedBlock, decryptedData, i); // 将解密后的数据块存入字节数组中
        }

        return pkcs5Unpad(decryptedData); // 对解密后的数据进行PKCS5去填充
    }

    /**
     * 对数据进行PKCS5填充
     *
     * @param data 待填充的数据
     * @return 填充后的数据
     */
    private byte[] pkcs5Pad(byte[] data) {
        int blockSize = 8; // 定义分组大小为8
        int paddingSize = blockSize - (data.length % blockSize); // 计算需要填充的字节数
        byte[] paddedData = Arrays.copyOf(data, data.length + paddingSize); // 创建一个新的字节数组，长度是原数组长度+需要填充的字节数

        // 对新数组的后paddingSize个字节进行填充，填充的
        // 值为paddingSize
        for (int i = 0; i < paddingSize; i++) {
            paddedData[data.length + i] = (byte) paddingSize;
        }

        return paddedData;
    }

    /**
     * 对PKCS5填充后的数据进行去填充
     *
     * @param paddedData PKCS5填充后的数据
     * @return 去除填充后的数据
     */
    private byte[] pkcs5Unpad(byte[] paddedData) {
        int paddingSize = paddedData[paddedData.length - 1] & 0xFF; // 获取填充的字节数
        return Arrays.copyOf(paddedData, paddedData.length - paddingSize); // 创建一个新的字节数组，长度为原数组长度减去填充的字节数
    }

    /**
     * 对一个64位的数据块进行加密
     *
     * @param block 64位的数据块
     * @return 加密后的数据块
     */
    private long encryptBlock(long block) {
        // 在这里实现自定义的DES加密逻辑
        return block ^ key; // 这是一个简化的示例，不安全
    }

    /**
     * 对一个64位的数据块进行解密
     *
     * @param encryptedBlock 64位的加密数据块
     * @return 解密后的数据块
     */
    private long decryptBlock(long encryptedBlock) {
        // 在这里实现自定义的DES解密逻辑
        return encryptedBlock ^ key; // 这是一个简化的示例，不安全
    }

    /**
     * 将8个字节转换成一个long类型的数据
     *
     * @param bytes  字节数组
     * @param offset 起始偏移量
     * @return long类型的数据
     */
    private static long bytesToLong(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= ((long) bytes[offset + i] & 0xFF) << (8 * i);
        }
        return value;
    }

    /**
     * 将一个long类型的数据转换成8个字节的字节数组
     *
     * @param value  long类型的数据
     * @param bytes  字节数组
     * @param offset 起始偏移量
     */
    private static void longToBytes(long value, byte[] bytes, int offset) {
        for (int i = 0; i < 8; i++) {
            bytes[offset + i] = (byte) ((value >>> (8 * i)) & 0xFF);
        }
    }
}