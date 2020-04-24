package ru.kpfu.itis.borisgk98.infosecurity.kuz;

public class SimpleCryptor implements Cryptor {

    private final BlockCryptor blockCryptor;
    private final BlockConnector blockConnector;

    public SimpleCryptor(BlockCryptor blockCryptor, BlockConnector blockConnector) {
        this.blockCryptor = blockCryptor;
        this.blockConnector = blockConnector;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return blockConnector.encrypt(data, blockCryptor);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return blockConnector.decrypt(data, blockCryptor);
    }
}
