import javax.xml.bind.DatatypeConverter;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.stream.Stream;

public class Main {

    private static final byte[] key1 = DatatypeConverter
            .parseHexBinary("123456789abcedf0123456789abcedf0");
    private static final byte[] key2 = DatatypeConverter
                     .parseHexBinary("023456789abced1f123456789abcedf0");

    private static final BlockCryptor KUZ_CRYPTOR = new GostKuzCryptor(key1, key2);
    private static final BlockConnector ECB_BLOCK_CONNECTOR = new ECBBlockConnector();
    private static final BlockConnector PBC_BLOCK_CONNECTOR = new PBCBlockConnector();
    private static final Cryptor ECB_CRYPTOR = new SimpleCryptor(KUZ_CRYPTOR, ECB_BLOCK_CONNECTOR);
    private static final Cryptor PBC_CRYPTOR = new SimpleCryptor(KUZ_CRYPTOR, PBC_BLOCK_CONNECTOR);

    private static final byte[] SINGLE_BLOCK = DatatypeConverter
            .parseHexBinary("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    private static final byte[] LAST_BLOCK = DatatypeConverter
            .parseHexBinary("80000000000000000000000000000000");
    private static final byte[] MANY_BLOCKS = DatatypeConverter
            .parseHexBinary("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb80000000000000000000000000000000");
    private static final byte[] DISBALANCED_BLOCKS = DatatypeConverter
            .parseHexBinary("11aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb80000000000000000000000000000000");

    public static void main(String[] args)
    {
//        Stream.of(SINGLE_BLOCK, LAST_BLOCK, MANY_BLOCKS, DISBALANCED_BLOCKS).forEach(data -> test(data, ECB_CRYPTOR));
        Stream.of(SINGLE_BLOCK, LAST_BLOCK, MANY_BLOCKS, DISBALANCED_BLOCKS).forEach(data -> test(data, PBC_CRYPTOR));
    }

    private static void test(byte[] data, Cryptor cryptor) {
        System.out.printf("data:\t\t%s\n", DatatypeConverter.printHexBinary(data));
        byte[] enrypted = cryptor.encrypt(data);
        System.out.printf("encrypted:\t%s\n", DatatypeConverter.printHexBinary(enrypted));
        System.out.printf("decrypted:\t%s\n", DatatypeConverter.printHexBinary(cryptor.decrypt(enrypted)));
        System.out.println();
    }
}
