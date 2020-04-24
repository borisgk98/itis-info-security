package ru.kpfu.itis.borisgk98.infosecurity.kuz;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ECBBlockConnector implements BlockConnector {

    @Override
    public byte[] encrypt(byte[] data, BlockCryptor cryptor) {
        return Utils.split(data, cryptor.getBlockSize())
                .parallelStream()
                .map(cryptor::encrypt)
                .reduce(Utils::mergeArrays)
                .orElseGet(() -> new byte[0]);
    }

    @Override
    public byte[] decrypt(byte[] data, BlockCryptor cryptor) {
        if (data.length % cryptor.getBlockSize() != 0) {
            throw new IllegalArgumentException();
        }
        List<byte[]> decripted = Utils.split2(data, cryptor.getBlockSize())
                .parallelStream()
                .map(cryptor::decrypt).collect(Collectors.toList());
        return Stream.of(Utils.unsplit(decripted))
                .reduce(Utils::mergeArrays)
                .orElseGet(() -> new byte[0]);
    }
}
