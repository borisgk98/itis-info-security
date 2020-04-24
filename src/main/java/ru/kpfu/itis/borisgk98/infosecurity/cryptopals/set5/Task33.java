package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils.pow;
import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils.powMod;

public class Task33 {
    public static void main(String[] args) {
        String pHex = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
                "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
                "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
                "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
                "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
                "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
                "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
                "fffffffffffff";
        BigInteger p = new BigInteger(pHex, 16), g = BigInteger.TWO;
        BigInteger a = BigInteger.valueOf(23l), b = BigInteger.valueOf(16l);
        BigInteger A = powMod(g, a, p);
        BigInteger B = powMod(g, b, p);
        BigInteger s = powMod(B, a, p), ss = powMod(A, b, p);
        if (!s.equals(ss)) {
            System.out.println("false");
            System.exit(-1);
        }
    }
}
