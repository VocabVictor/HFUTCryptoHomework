/**
 * RSA 分块加密算法实现
 * 作者: VocabVictor
 * 创建时间: 2023-05-06
 * 文件用途:
 * 该文件实现了 RSA 分块加密算法，提供了加密和解密函数。
 * RSA 加密算法是一种公钥加密算法，可用于数据加密和数字签名等领域。
 * 分块加密可以加密任意长度的数据，且相较于单次加密速度更快。
 */
package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class RSA extends CryptoAlgorithm {

    // 声明 RSA 需要的三个大整数，分别是 n、e 和 d
    private BigInteger n, e, d;

    // 声明分块加密所需的块大小
    private int encryptblockSize, decryptblockSize;

    /**
     * 构造函数，初始化RSA参数。
     *
     * @param bits       RSA密钥的位数
     * @param blockSize  加密和解密时的块大小
     */
    public RSA(int bits, int blockSize) {
        // 创建安全随机数生成器对象
        SecureRandom random = new SecureRandom();

        // 生成两个大素数 p 和 q，每个素数的二进制位数为 bits / 2
        BigInteger p = BigInteger.probablePrime(bits / 2, random);
        BigInteger q = BigInteger.probablePrime(bits / 2, random);

        // 计算 n = p * q
        this.n = p.multiply(q);

        // 计算 m = (p-1) * (q-1)
        BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // 选择一个 e，使得 e 与 m 的最大公约数为 1，即 e 和 m 互质
        this.e = new BigInteger("65537");

        // 计算 d = e^(-1) mod m，即 d 为 e 模 m 的乘法逆元
        this.d = this.e.modInverse(m);

        // 根据块大小和密钥长度的关系，设置块大小
        blockSize = Math.min((bits - 1) / 8, blockSize);

        // 记录块大小
        this.encryptblockSize = blockSize;
        this.decryptblockSize = n.bitLength() / 8 + 1;
    }

    /**
     * RSA加密函数。
     *
     * @param message 要加密的字节数组
     * @return 加密后的字节数组
     */
    public byte[] encrypt(byte[] message) {
        // 计算需要分块的块数
        int numBlocks = (message.length + encryptblockSize - 1) / encryptblockSize;

        // 计算加密后的字节数组的总长度
        byte[] encryptedMessage = new byte[numBlocks * decryptblockSize];

        // 偏移量
        int offset = 0;

        // 对明文分块加密
        for (int i = 0; i < numBlocks; i++) {
            byte[] encryptedBlock = encryptBlock(Arrays.copyOfRange(message, offset, offset + Math.min(encryptblockSize, message.length - offset)));
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * decryptblockSize, decryptblockSize);
            offset += encryptblockSize;
        }

        return encryptedMessage;
    }

    /**
     * 对单个块进行加密
     *
     * @param block 要加密的块的字节数组
     * @return 加密后的字节数组
     */
    private byte[] encryptBlock(byte[] block) {
        BigInteger blockBigInt = new BigInteger(1, block);
        BigInteger encryptedBlockBigInt = blockBigInt.modPow(e, n);
        byte[] encryptedBlock = encryptedBlockBigInt.toByteArray();

        if (encryptedBlock.length < decryptblockSize) {
            byte[] paddedBlock = new byte[decryptblockSize];
            System.arraycopy(encryptedBlock, 0, paddedBlock, decryptblockSize - encryptedBlock.length, encryptedBlock.length);
            encryptedBlock = paddedBlock;
        }

        return encryptedBlock;
    }



    /**
     * RSA解密函数。
     *
     * @param encryptedMessage 要解密的字节数组
     * @return 解密后的字节数组
     */
    public byte[] decrypt(byte[] encryptedMessage) {
        // 计算需要分块的块数
        int numBlocks = encryptedMessage.length / decryptblockSize;

        // 创建解密后的字节数组
        byte[] decryptedMessage = new byte[numBlocks * decryptblockSize];
        int offset = 0;

        // 对密文分块解密
        for (int i = 0; i < numBlocks; i++) {
            byte[] decryptedBlock = decryptBlock(Arrays.copyOfRange(encryptedMessage, i * decryptblockSize, (i + 1) * decryptblockSize));
            int length = Math.min(decryptblockSize, decryptedBlock.length);

            if (decryptedBlock[0] == 0) {
                System.arraycopy(decryptedBlock, 1, decryptedMessage, offset, length - 1);
                offset += length - 1;
            } else {
                System.arraycopy(decryptedBlock, 0, decryptedMessage, offset, length);
                offset += length;
            }
        }

        return Arrays.copyOfRange(decryptedMessage, 0, offset);
    }

    /**
     * 对单个块进行解密
     *
     * @param block 要解密的块的字节数组
     * @return 解密后的字节数组
     */
    private byte[] decryptBlock(byte[] block) {
        BigInteger encryptedBlockBigInt = new BigInteger(1, block);
        BigInteger decryptedBlockBigInt = encryptedBlockBigInt.modPow(d, n);
        byte[] decryptedBlock = decryptedBlockBigInt.toByteArray();
        return decryptedBlock;
    }


}

