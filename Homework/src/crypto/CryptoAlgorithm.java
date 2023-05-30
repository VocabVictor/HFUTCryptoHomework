/**
 * 加密算法抽象类
 * 作者: VocabVictor
 * 创建时间: 2023-05-06
 * 文件用途:
 * 该文件定义了加密算法的抽象类 CryptoAlgorithm，提供了加密字符串、解密字节数组为字符串,加密文件、解密文件等等功能、以及加密，解密抽象方法的声明。
 */
package crypto;

// 导入 java io 和 nio 库
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 加密算法抽象类
 */
public abstract class CryptoAlgorithm {

    /**
     * 加密函数抽象方法，留给子类实现
     *
     * @param data 待加密的字节数组
     * @return 加密后的字节数组
     */
    public abstract byte[] encrypt(byte[] data);

    /**
     * 解密函数抽象方法，留给子类实现
     *
     * @param data 待解密的字节数组
     * @return 解密后的字节数组
     */
    public abstract byte[] decrypt(byte[] data);


    /**
     * 加密字符串
     *
     * @param inputText 待加密的字符串
     * @return 加密后的字节数组
     */
    public byte[] encryptText(String inputText) {
        byte[] inputData = inputText.getBytes();
        byte[] encryptedData = encrypt(inputData);
        return encryptedData;
    }

    /**
     * 解密字节数组为字符串
     *
     * @param encryptedText 加密后的字节数组
     * @return 解密后的字符串
     */
    public String decryptText(byte[] encryptedText) {
        byte[] decryptedData = decrypt(encryptedText);
        return new String(decryptedData);
    }

    /**
     * 加密文件
     *
     * @param inputFilePath  待加密的文件路径
     * @param outputFilePath 加密后的文件路径
     * @throws IOException 文件读写错误
     */
    public void encryptFile(String inputFilePath, String outputFilePath) throws IOException {
        // 读取待加密文件的数据
        Path inputFile = Paths.get(inputFilePath);
        byte[] inputData = Files.readAllBytes(inputFile);
        // 对数据进行加密
        byte[] encryptedData = encrypt(inputData);
        // 将加密后的数据写入文件
        Path outputFile = Paths.get(outputFilePath);
        Files.write(outputFile, encryptedData);
    }

    /**
     * 解密文件
     *
     * @param inputFilePath  待解密的文件路径
     * @param outputFilePath 解密后的文件路径
     * @throws IOException 文件读写错误
     */
    public void decryptFile(String inputFilePath, String outputFilePath) throws IOException {
        // 读取待解密文件的数据
        Path inputFile = Paths.get(inputFilePath);
        byte[] encryptedData = Files.readAllBytes(inputFile);
        // 对数据进行解密
        byte[] decryptedData = decrypt(encryptedData);
        // 将解密后的数据写入文件
        Path outputFile = Paths.get(outputFilePath);
        Files.write(outputFile, decryptedData);
    }
}
