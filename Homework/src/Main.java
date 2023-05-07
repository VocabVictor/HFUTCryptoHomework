import java.io.IOException;
import crypto.RSA;
import crypto.DES;

public class Main {
    public static void main(String[] args) throws IOException {
        try {
            testencryptText();
            testencryptFile();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 演示RSA和AES的加密解密字符串
    public static void testencryptText() throws Exception {
        String str = "Hello World!";
        System.out.println("原文：" + str);
        DES des = new DES(2019216864);
        RSA rsa = new RSA(1024,512);
        byte[] cipher = rsa.encryptText(str);
        String plain = rsa.decryptText(cipher);
        System.out.println("RSA加密后：" + cipher);
        System.out.println("RSA解密后：" + plain);
        cipher = des.encryptText(str);
        plain = des.decryptText(cipher);
        System.out.println("DES加密后：" + cipher);
        System.out.println("DES解密后：" + plain);
    }

    // 演示RSA和AES的加密解密文件
    public static void testencryptFile() throws Exception {
        String filename = "README.md";
        String encryptfilename = "encryptREADME.md";
        String decryptfilename = "decryptREADME.md";
        DES des = new DES(2019216864);
        RSA rsa = new RSA(1024,512);
        des.encryptFile(filename, encryptfilename);
        des.decryptFile(encryptfilename, decryptfilename);
        rsa.encryptFile(filename, encryptfilename);
        rsa.decryptFile(encryptfilename, decryptfilename);
    }
}