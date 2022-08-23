package ciphers;

public interface Cipher {
    byte[] encrypt(byte[] text);

    byte[] decrypt(byte[] text);
}