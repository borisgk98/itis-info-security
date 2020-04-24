package ru.kpfu.itis.borisgk98.infosecurity.cryptopals;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.BinaryMessage;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.Client;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.Message;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.TextMessage;

import java.math.BigInteger;

public class Utils {

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

}
