package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA extends CryptoAlgorithm {
    private BigInteger n, e, d;

    public RSA(int bits) {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bits / 2, 100, random);
        BigInteger q = new BigInteger(bits / 2, 100, random);
        n = p.multiply(q);

        BigInteger m = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    public byte[] encrypt(byte[] message) {
        BigInteger messageBigInt = new BigInteger(message);
        BigInteger encryptedBigInt = messageBigInt.modPow(e, n);
        return encryptedBigInt.toByteArray();
    }

    public byte[] decrypt(byte[] encryptedMessage) {
        BigInteger encryptedBigInt = new BigInteger(encryptedMessage);
        BigInteger decryptedBigInt = encryptedBigInt.modPow(d, n);
        return decryptedBigInt.toByteArray();
    }
}
