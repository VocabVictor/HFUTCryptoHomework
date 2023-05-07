import java.io.IOException;
import crypto.RSA;
import crypto.DES;

public class Main {
    public static void main(String[] args) throws IOException {
        try {
            testencryptText(); // 测试加密解密字符串的方法
            testencryptFile(); // 测试加密解密文件的方法
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 演示 RSA 和 DES 加密解密字符串的方法
     *
     * @throws Exception 当加密解密操作出错时抛出异常
     */
    public static void testencryptText() throws Exception {
        String str = "Hello World!"; // 待加密的字符串
        System.out.println("原文：" + str);
        DES des = new DES(2019216864); // 创建一个DES加密对象，使用指定的密钥
        RSA rsa = new RSA(1024, 512); // 创建一个RSA加密对象，使用指定的密钥长度
        byte[] cipher = rsa.encryptText(str); // 对字符串进行RSA加密
        String plain = rsa.decryptText(cipher); // 对密文进行RSA解密
        System.out.println("RSA加密后：" + cipher); // 打印RSA加密后的密文
        System.out.println("RSA解密后：" + plain); // 打印RSA解密后的明文
        cipher = des.encryptText(str); // 对字符串进行DES加密
        plain = des.decryptText(cipher); // 对密文进行DES解密
        System.out.println("DES加密后：" + cipher); // 打印DES加密后的密文
        System.out.println("DES解密后：" + plain); // 打印DES解密后的明文
    }

    /**
     * 演示 RSA 和 DES 加密解密文件的方法
     *
     * @throws Exception 当加密解密操作出错时抛出异常
     */
    public static void testencryptFile() throws Exception {
        String filename = "README.md"; // 待加密的文件名
        String encryptfilename = "encryptREADME.md"; // 加密后的文件名
        String decryptfilename = "decryptREADME.md"; // 解密后的文件名
        DES des = new DES(2019216864); // 创建一个DES加密对象，使用指定的密钥
        RSA rsa = new RSA(1024, 512); // 创建一个RSA加密对象，使用指定的密钥长度
        des.encryptFile(filename, encryptfilename); // 对文件进行DES加密
        des.decryptFile(encryptfilename, decryptfilename); // 对加密后的文件进行DES解密
        rsa.encryptFile(filename, encryptfilename); // 对文件进行RSA加密
        rsa.decryptFile(encryptfilename, decryptfilename); // 对加密后的文件进行RSA解密
    }
}
