/**
 * DES 对称加密算法实现
 * 作者: VocabVictor
 * 创建时间: 2023-05-06
 * 文件用途:
 * 该文件实现了 DES 对称加密算法，提供了加密和解密函数。
 * DES 加密算法是一种经典的对称加密算法，可用于数据加密等领域。
 * 该实现支持 PKCS5 填充和去填充，能够加密任意长度的数据。
 */
package crypto;

import java.util.Arrays;

public class DES extends CryptoAlgorithm {

    // PC-1置换表（密钥调度）
    //静态常量，PC-1置换表用于初始密钥的置换。
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    // PC-2置换表（密钥调度）
    //静态常量，PC-2置换表用于生成子密钥。
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // 移位表
    //静态常量，移位表定义了每个轮次密钥左移的位数。
    private static final int[] SHIFTS = {
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    // 初始置换表
    //静态常量，初始置换表用于数据的初始置换。
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // 反初始置换表
    //静态常量，反初始置换表用于数据的最后置换，恢复到原来的顺序。
    private static final int[] IIP = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    // 扩展表
    //静态常量，扩展表用于将32位数据扩展为48位。
    private static final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    // S盒
    //静态常量，S盒用于数据的非线性变换。
    private static final int[][][] S = {
            {
                    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            {
                    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                    {3, 13, 12, 11, 1, 4, 2, 5, 0, 15, 10, 7, 6, 9, 8, 14},
                    {10, 7, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 11, 4, 2, 8},
                    {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            {
                    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                    {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                    {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                    {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
            },
            {
                    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                    {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                    {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                    {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
            },
            {
                    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            {
                    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 10, 0, 8, 13}
            },
            {
                    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                    {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                    {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                    {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            {
                    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                    {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 10, 14, 9, 2},
                    {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                    {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
    };

    // 置换表
    // 静态常量，置换表用于数据的置换。
    private static final int[] P = {
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
    };

    private long key; // 私有变量，用来保存密钥。

    // 存储子密钥的数组。
    private long[] subKeys = new long[16]; // 私有变量，用于存储生成的16个子密钥。

    /**
     * DES算法的构造函数，用于初始化DES对象的密钥
     *
     * @param key 一个long类型的密钥
     */
    public DES(long key) {
        this.key = key;
        generateSubKeys();
    }

    /**
     * 将8个字节转换成一个long类型的数据
     *
     * @param bytes  字节数组
     * @param offset 起始偏移量
     * @return long类型的数据
     */
    private static long bytesToLong(byte[] bytes, int offset) {
        long value = 0; // 初始化为 0 的 long 型变量，用于存储转换结果

        // 遍历 byte 数组的一个部分（从 offset 开始的 8 个字节）
        for (int i = 0; i < 8; i++) {
            // 每次循环将 byte 转换为 long，然后左移相应的位数，并与 value 进行或操作
            // byte[offset + i] & 0xFF 操作是为了确保 byte 转 long 时，不会因为 byte 是负数而导致高位全部变成 1
            value |= ((long) bytes[offset + i] & 0xFF) << (8 * i);
        }

        return value; // 返回转换结果
    }

    private static long permute(long block, int[] table) {
        long result = 0; // 初始化结果为 0

        // 遍历整个置换表
        for (int i = 0; i < table.length; i++) {
            // 将当前结果左移一位，为下一个位做准备
            result <<= 1;

            // 从 block 中取出位值，这个位值的位置由置换表给出
            // (64 - table[i]) 是因为位操作从右向左（也就是从低位向高位）计算，而置换表中的位序是从左向右（也就是从高位向低位）编号的
            // (block >>> (64 - table[i])) & 1 这部分取出了相应位置的位值，然后与 result 进行或操作
            result |= (block >>> (64 - table[i])) & 1;
        }

        // 返回置换后的结果
        return result;
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
        // 初始置换
        block = initialPermutation(block); // 对输入块执行初始置换

        // 将块拆分成左右两个部分
        int left = (int) (block >>> 32); // 取 block 的高 32 位
        int right = (int) block; // 取 block 的低 32 位

        // 执行 16 轮的 F 函数运算
        for (int i = 0; i < 16; i++) {
            // F 函数包括扩展置换、与子密钥异或、S盒替代、P置换等步骤
            int newRight = left ^ fFunction(right, subKeys[i]); // 用 F 函数处理右半部分，然后与左半部分进行异或
            left = right; // 在下一轮迭代中，当前的右半部分会成为左半部分
            right = newRight; // 在下一轮迭代中，newRight 会成为右半部分
        }

        // 交换左右两个部分
        block = (((long) right) << 32) | (left & 0xFFFFFFFFL); // 在所有轮运算结束后，交换左右两个部分

        // 逆初始置换
        block = inverseInitialPermutation(block); // 执行逆初始置换，得到密文块

        return block; // 返回加密后的块
    }

    public void generateSubKeys() {
        // 对密钥应用 PC-1 置换
        long permutedChoice1 = permute(key, PC1);

        // 将置换后的密钥分为两半，分别为 c 和 d
        int c = (int) (permutedChoice1 >>> 28); // 取 permutedChoice1 的高 28 位
        int d = (int) (permutedChoice1 & 0xFFFFFFF); // 取 permutedChoice1 的低 28 位

        // 进行 16 轮操作，每轮都会生成一个子密钥
        for (int i = 0; i < 16; i++) {
            // 根据移位表进行左移操作
            c = (c << SHIFTS[i]) | (c >>> (28 - SHIFTS[i]));
            d = (d << SHIFTS[i]) | (d >>> (28 - SHIFTS[i]));

            // 对移位后的 c 和 d 应用 PC-2 置换，生成子密钥
            long permutedChoice2 = (((long) c) << 28) | d; // 将 c 和 d 重新组合，准备进行 PC-2 置换
            subKeys[i] = permute(permutedChoice2, PC2); // 生成第 i 轮的子密钥
        }
    }

    private int fFunction(int right, long subKey) {
        // 扩展置换
        long expandedRight = expand(right); // 对右半块进行扩展置换，将其从 32 位扩展到 48 位

        // 与子密钥进行异或
        expandedRight ^= subKey; // 对扩展后的右半块和当前的子密钥进行异或操作

        // S 盒替代
        int output = sBoxSubstitution(expandedRight); // 对异或后的结果进行 S 盒替代，将其从 48 位压缩回 32 位

        // P 置换
        output = pBoxPermutation(output); // 对 S 盒替代后的结果进行 P 置换

        return output; // 返回 F 函数的结果
    }

    /**
     * 对一个64位的数据块进行解密
     *
     * @param encryptedBlock 64位的加密数据块
     * @return 解密后的数据块
     */
    private long decryptBlock(long encryptedBlock) {
        // Perform the initial permutation
        long permutedBlock = initialPermutation(encryptedBlock);

        // Split the block into two halves
        int left = (int) (permutedBlock >>> 32);
        int right = (int) (permutedBlock & 0xFFFFFFFF);

        // 16 rounds of the DES algorithm
        for (int i = 15; i >= 0; i--) {
            int previousRight = right;
            right = left ^ fFunction(right, subKeys[i]);
            left = previousRight;
        }

        // Join the swapped halves together
        long preOutput = ((long) right << 32) | (left & 0xFFFFFFFFL);

        // Perform the inverse initial permutation and return the result
        return inverseInitialPermutation(preOutput);
    }

    // 执行初始置换操作
    private long initialPermutation(long block) {
        // 初始置换是通过调用 permute 函数并传入初始置换表 IP 来实现的
        return permute(block, IP);
    }

    // 执行逆初始置换操作
    private long inverseInitialPermutation(long block) {
        // 逆初始置换是通过调用 permute 函数并传入逆初始置换表 IIP 来实现的
        return permute(block, IIP);
    }

    private long expand(int block) {
        long result = 0;
        for (int i = 0; i < E.length; i++) {
            result <<= 1;
            result |= (block >>> (32 - E[i])) & 1;
        }
        return result;
    }

    private int sBoxSubstitution(long block) {
        int output = 0;
        for (int i = 0; i < 8; i++) {
            int row = (int) ((block >>> (42 - i * 6)) & 0x20 | (block >>> (43 - i * 6)) & 0x1);
            int col = (int) (block >>> (42 - i * 6)) & 0x1E;
            output <<= 4;
            output |= S[i][row][col];
        }
        return output;
    }

    private int pBoxPermutation(int block) {
        int output = 0;
        for (int i = 0; i < P.length; i++) {
            output <<= 1;
            output |= (block >>> (32 - P[i])) & 1;
        }
        return output;
    }
}