package ru.kpfu.itis.borisgk98.infosecurity.cryptopals;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.BinaryMessage;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.Client;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.Message;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.RSAHelper;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.TextMessage;

import java.math.BigInteger;
import java.util.List;

public class Utils {
    static final int   TIMES = RSAHelper.PUBLIC_EXPONENT.intValue();

    public static BigInteger pow(BigInteger a, Long b) {
        if (b == 0) {
            return BigInteger.ONE;
        }
        if (b == 1) {
            return a;
        }
        BigInteger res = pow(a, b / 2);
        return (b % 2 == 1 ? a : BigInteger.ONE).multiply(res).multiply(res);
    }

    public static Long pow(Long a, Long b) {
        if (b == 0) {
            return 1l;
        }
        if (b == 1) {
            return a;
        }
        Long res = pow(a, b / 2);
        return (b % 2 == 1 ? a : 1l) * res * res;
    }

    public static Long powMod(Long a, Long b, Long p) {
        if (b == 0) {
            return 1l;
        }
        if (b == 1) {
            return a % p;
        }
        Long res = powMod(a, b / 2, p);
        return ((b % 2 == 1 ? a : 1l) * res * res) % p;
    }

    public static BigInteger powMod(BigInteger a, BigInteger b, BigInteger mod) {
        if (b.equals(BigInteger.ZERO)) {
            return BigInteger.ONE;
        }
        if (b.equals(BigInteger.ONE)) {
            return a.mod(mod);
        }
        BigInteger res = powMod(a, b.divide(BigInteger.TWO), mod);
        return (b.mod(BigInteger.TWO).equals(BigInteger.ONE) ? a : BigInteger.ONE).multiply(res).multiply(res).mod(mod);
    }



    public static void processDecMess(Client to, byte[] data, Message message) {
        if (message instanceof TextMessage) {
            to.getReceivedMessages().add(new TextMessage(new String(data)));
        }
        else {
            to.getReceivedMessages().add(new BinaryMessage(data));
        }
    }

        public static BigInteger  ithroot(BigInteger n, int k) {
        final int  k1 = k - 1;
        BigInteger  kBig = BigInteger.valueOf(k),  k1Big = BigInteger.valueOf(k1),  s = n.add(BigInteger.ONE),  u = n;

        while (u.compareTo(s) < 0) {
            s = u;
            u = u.multiply(k1Big).add(n.divide(u.pow(k1))).divide(kBig);
        }
        return s;
    }

    public static boolean  isOdd(BigInteger i) {
        byte[]  repr = i.toByteArray();
        return  (repr[repr.length - 1] & 0x01) != 0;
    }

    private static BigInteger  recoverPlainText(List<BigInteger[]> pairs) {
        if (pairs.size() != TIMES)
            throw  new IllegalArgumentException(TIMES + " { modulus, cipherText} pairs required");
        BigInteger   n012 = BigInteger.ONE,  res = BigInteger.ZERO;
        for (int i=0; i < TIMES; i++) {
            n012 = n012.multiply(pairs.get(i)[0]);
            BigInteger   msi = BigInteger.ONE;
            for (int j = 0; j < TIMES; j++) {
                if (j == i)  continue;
                msi = msi.multiply(pairs.get(j)[0]);
            }
            res = res.add(pairs.get(i)[1].multiply(msi).multiply(msi.modInverse(pairs.get(i)[0])));
        }
        return  ithroot(res.mod(n012), TIMES);
    }

}
