public interface Cryptor {
    byte[] encrypt(byte[] block);
    byte[] decrypt(byte[] block);
}
