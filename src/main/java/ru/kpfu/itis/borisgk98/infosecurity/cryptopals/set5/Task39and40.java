package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

import ru.kpfu.itis.borisgk98.infosecurity.cryptopals.helpers.RSAHelper;

import java.math.BigInteger;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static javax.management.Query.TIMES;
import static ru.kpfu.itis.borisgk98.infosecurity.cryptopals.Utils.ithroot;

public class Task39and40 {

    public static void main(String[] args){
        List<BigInteger[]> stream = IntStream.range(0, TIMES).mapToObj(x -> new RSAHelper()).map(helper ->
            new BigInteger[] { helper.getPublicKey().getModulus(), helper.encrypt(new BigInteger("test".getBytes())) })
                .collect(Collectors.toList());

        BigInteger  res = recoverPlainText(stream);

        System.out.printf("Ciphertext '%d' -> \"%s\"", res, new String(res.toByteArray()));
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
