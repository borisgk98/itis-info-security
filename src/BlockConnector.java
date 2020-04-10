public interface BlockConnector {
    byte[] encrypt(byte[] data, BlockCryptor cryptor);
    byte[] decrypt(byte[] data, BlockCryptor cryptor);
}
