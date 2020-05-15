package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.dsarsa.DSAHelper;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.RSAHelper;
import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.RSAHelperExt;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Predicate;

import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.dsarsa.DSAHelper.fromHash;

public class Task42and46 {
    static final BigInteger TWO = BigInteger.valueOf(2L);
    static final String   PLAIN_TEXT = "{\n" +
            "  time: 1356304276,\n" +
            "  social: '555-55-5555',\n" +
            "}",
            CHALLENGE_43_TEXT = "For those that envy a MC it can be hazardous to your health\n"
                    + "So be friendly, a matter of life and death, just like a etch-a-sketch\n",
            CHALLANGE_47_PLAINTEXT = "kick it, CC";
    static final BigInteger   CHALLENGE_43_Y = new BigInteger("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
            "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
            "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
            "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
            "bb283e6633451e535c45513b2d33c99ea17", 16),
            CHALLENGE_44_Y = new BigInteger("2d026f4bf30195ede3a088da85e398ef869611d0f68f07" +
                    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" +
                    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" +
                    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" +
                    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" +
                    "2971c3de5084cce04a2e147821", 16);
    static final DSAHelper.Signature   CHALLANGE_43_SIGNATURE = new DSAHelper.Signature(
            new BigInteger("548099063082341131477253921760299949438196259240", 10),
            new BigInteger("857042759984254168557880549501802188789837994940", 10));
    static final byte   CHALLANGE_46_PLAINTEXT[] = DatatypeConverter.parseBase64Binary(
            "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==");
    private static final Random RANDOM = new Random(); // Thread safe

    @SneakyThrows
    static BigInteger  forgeSignature(byte msg[], RSAHelper.PublicKey pk, RSAHelperExt.HashMethod method) {
        final int   MIN_PAD = 4;   // \x00\x01\xff\x00"
        MessageDigest md = MessageDigest.getInstance(method.toString());
        byte[]   hash = md.digest(msg),  paddedMsg;
        int      lenPad = pk.getModulus().bitLength() / 8 - (hash.length + method.getASN1Encoding().length + MIN_PAD + 1);
        paddedMsg = new byte[lenPad + hash.length + method.getASN1Encoding().length + MIN_PAD];
        paddedMsg[1] = 1;     paddedMsg[2] = -1;
        System.arraycopy(method.getASN1Encoding(), 0, paddedMsg, MIN_PAD , method.getASN1Encoding().length);
        System.arraycopy(hash, 0, paddedMsg, MIN_PAD + method.getASN1Encoding().length, hash.length);
        Arrays.fill(paddedMsg, paddedMsg.length - 3, paddedMsg.length, (byte) -1);
        BigInteger  forgedSignature = ithroot(new BigInteger(paddedMsg), 3);
        return  forgedSignature.add(BigInteger.ONE);
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

    @Data
    @Builder
    static class  SignedMessage  {
        final String   msg;
        final BigInteger   m;
        final DSAHelper.Signature   signature;
    }

    static BigInteger  breakChallenge46(BigInteger cipherTxt, RSAHelper.PublicKey pk,
                                        Predicate<BigInteger> oracle) {
        System.out.printf("Ciphertext: %x%n", cipherTxt);
        BigInteger   modulus = pk.getModulus(),  lower = BigInteger.ZERO,  upper = BigInteger.ONE,  denom = BigInteger.ONE,
                     multiplier = TWO.modPow(pk.getE(), modulus),  cur = cipherTxt,  d;
        int   n = modulus.bitLength();
        for (int i=0; i < n; i++) {
            cur = cur.multiply(multiplier);
//            tmp = upper.add(lower).divide(TWO);   // Here upper starts at the modulus. This approach turns out
//                                                     to be numerically unstable and fails to decrypt the least
//                                                     significant byte of the ciphertext. Replaced with an approach
//                                                     below.
            d = upper.subtract(lower);
            upper = upper.multiply(TWO);
            lower = lower.multiply(TWO);
            denom = denom.multiply(TWO);
            if (oracle.test(cur)) { // It didn't wrap the modulus
                upper = upper.subtract(d);
//                upper = tmp; // Not stable, abandoned
            } else {                // It wrapped the modulus
                lower = lower.add(d);
//                lower = tmp; // Not stable, abandoned
            }

            System.out.printf("%4d %s%n", i,        // Hollywood style :-)
                    new String(upper.multiply(modulus).divide(denom).toByteArray()).split("[\\n\\r]")[0]);
        }

        return  upper.multiply(modulus).divide(denom);
    }


    public static void main(String[] args) {

        try {
            RSAHelperExt   rsa = new RSAHelperExt(BigInteger.valueOf(17));

            System.out.println("\nChallenge 42");
            byte   msg[] = "hi mom".getBytes();
            rsa = new RSAHelperExt(BigInteger.valueOf(3));
            BigInteger   signature = rsa.sign(msg, RSAHelperExt.HashMethod.SHA1);
            System.out.println("Valid signature verifies? " + rsa.verify(msg, signature));
            System.out.println("Forged signature verifies? "
                    + rsa.verify(msg, forgeSignature(msg, rsa.getPublicKey(), RSAHelperExt.HashMethod.SHA1)));

            DSAHelper   dsa = new DSAHelper();
            DSAHelper.PublicKey   pk = dsa.getPublicKey();
            DSAHelper.Signature   dsaSignature = dsa.sign(CHALLENGE_43_TEXT.getBytes());
            System.out.println("Signature verifies? " + pk.verifySignature(CHALLENGE_43_TEXT.getBytes(), dsaSignature));

            System.out.println("\nChallenge 46");
            BigInteger cipherTxt = rsa.encrypt(fromHash(CHALLANGE_46_PLAINTEXT));
            BigInteger  plainText = breakChallenge46(cipherTxt, rsa.getPublicKey(), rsa::decryptionOracle);
            msg = plainText.toByteArray();
            System.out.println("Obtained plaintext:\n" + new String(msg));
            assert  Arrays.equals(msg, CHALLANGE_46_PLAINTEXT);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
