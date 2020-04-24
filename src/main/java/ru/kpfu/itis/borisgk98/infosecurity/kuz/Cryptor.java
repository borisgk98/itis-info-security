package ru.kpfu.itis.borisgk98.infosecurity.kuz;

public interface Cryptor {
    byte[] encrypt(byte[] block);
    byte[] decrypt(byte[] block);
}
