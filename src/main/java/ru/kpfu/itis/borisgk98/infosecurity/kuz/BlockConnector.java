package ru.kpfu.itis.borisgk98.infosecurity.kuz;

public interface BlockConnector {
    byte[] encrypt(byte[] data, BlockCryptor cryptor);
    byte[] decrypt(byte[] data, BlockCryptor cryptor);
}
