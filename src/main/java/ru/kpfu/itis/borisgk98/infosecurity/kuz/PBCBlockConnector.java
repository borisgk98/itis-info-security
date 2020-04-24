package ru.kpfu.itis.borisgk98.infosecurity.kuz;

import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.List;

public class PBCBlockConnector implements BlockConnector {
    private static final byte[] P0 = DatatypeConverter
            .parseHexBinary("00000000000000000000000000000000");

    @Override
    public byte[] encrypt(byte[] data, BlockCryptor cryptor) {
        List<byte[]> splited = Utils.split(data, cryptor.getBlockSize());
        List<byte[]> result = new ArrayList<>();
        byte[] pref = f(P0, splited.get(0), cryptor);
        result.add(pref);
        for (int i = 1; i < splited.size(); i++) {
            pref = f(splited.get(i - 1), splited.get(i), cryptor);
            result.add(pref);
        }
        return Utils.convert2(result);
    }

    @Override
    public byte[] decrypt(byte[] data, BlockCryptor cryptor) {
        if (data.length % cryptor.getBlockSize() != 0) {
            throw new IllegalArgumentException();
        }
        List<byte[]> splited = Utils.split2(data, cryptor.getBlockSize());
        List<byte[]> result = new ArrayList<>();
        byte[] pref = reverseF(P0, splited.get(0), cryptor);
        result.add(pref);
        for (int i = 1; i < splited.size(); i++) {
            pref = reverseF(pref, splited.get(i), cryptor);
            result.add(pref);
        }
        return Utils.unsplit(result);
    }

    private byte[] f(byte[] pref, byte[] block, BlockCryptor cryptor) {
        return Utils.xor(pref, cryptor.encrypt(block));
    }

    private byte[] reverseF(byte[] pref, byte[] block, BlockCryptor cryptor) {
        return cryptor.decrypt(Utils.xor(pref, block));
    }
}
