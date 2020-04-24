package ru.kpfu.itis.borisgk98.infosecurity.kuz;

public class SimpleBlockCryptor implements BlockCryptor {
    @Override
    public int getBlockSize() {
        return 16;
    }

    @Override
    public byte[] encrypt(byte[] block) {
        return block;
    }

    @Override
    public byte[] decrypt(byte[] block) {
        return block;
    }
}
