package ru.kpfu.itis.borisgk98.infosecurity.cryptopals.set5;

public class Task39and40 {

    public static void main(String[] args){
        List<BigInteger[]> stream = IntStream.range(0, TIMES).mapToObj(x -> new RSAHelper()).map(helper ->
            new BigInteger[] { helper.getPublicKey().getModulus(), helper.encrypt(new BigInteger(msg.getBytes())) })
                .collect(Collectors.toList());

        BigInteger  res = recoverPlainText(stream);

        System.out.printf("Ciphertext '%d' -> \"%s\"", res, new String(res.toByteArray()));
    }
}
