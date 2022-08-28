import org.junit.Test;

import static org.junit.Assert.assertEquals;
import ciphers.AES;

public class AESTest {
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    public static final String PLAINTEXT = "00112233445566778899aabbccddeeff";
    public static final String KEY_FOR_128_BITS = "000102030405060708090a0b0c0d0e0f";
    public static final String KEY_FOR_192_BITS = "000102030405060708090a0b0c0d0e0f1011121314151617";
    public static final String KEY_FOR_256_BITS =  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    @Test
    public void AES128EncryptionTest(){
        final String EXPECTED_CIPHERTEXT = "69c4e0d86a7b0430d8cdb78070b4c55a";

        // Aes-128 test
        byte[] plaintext = hexStringToByteArray(PLAINTEXT);
        byte[] key = hexStringToByteArray(KEY_FOR_128_BITS);

        AES szyfr = new AES(key);
        byte[] ciphertext = szyfr.encrypt(plaintext);

        byte[] actualPlaintext = szyfr.decrypt(ciphertext);

        assertEquals(EXPECTED_CIPHERTEXT, bytesToHex(ciphertext));
        assertEquals(PLAINTEXT, bytesToHex(actualPlaintext));
    }

    @Test
    public void AES128EmptyEncryptionTest(){
        final String PLAINTEXT = "00000000000000000000000000000000";
        final String KEY = "00000000000000000000000000000000";
        final String EXPECTED_CIPHERTEXT = "66e94bd4ef8a2c3b884cfa59ca342b2e";

        // Aes-128 test
        byte[] plaintext = hexStringToByteArray(PLAINTEXT);
        byte[] key = hexStringToByteArray(KEY);

        AES szyfr = new AES(key);
        byte[] ciphertext = szyfr.encrypt(plaintext);

        byte[] actualPlaintext = szyfr.decrypt(ciphertext);

        assertEquals(EXPECTED_CIPHERTEXT, bytesToHex(ciphertext));
        assertEquals(PLAINTEXT, bytesToHex(actualPlaintext));
    }

    @Test
    public void AES192RoundTest(){
        final String EXPECTED_CIPHERTEXT = "dda97ca4864cdfe06eaf70a0ec0d7191";

        // Aes-192 test
        byte[] plaintext = hexStringToByteArray(PLAINTEXT);
        byte[] key = hexStringToByteArray(KEY_FOR_192_BITS);

        AES szyfr = new AES(key);
        byte[] ciphertext = szyfr.encrypt(plaintext);

        byte[] actualPlaintext = szyfr.decrypt(ciphertext);

        assertEquals(EXPECTED_CIPHERTEXT, bytesToHex(ciphertext));
        assertEquals(PLAINTEXT, bytesToHex(actualPlaintext));
    }

    @Test
    public void AES256RoundTest(){
        String key1 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        final String EXPECTED_CIPHERTEXT = "8ea2b7ca516745bfeafc49904b496089";

        // Aes-256 test
        byte[] plaintext = hexStringToByteArray(PLAINTEXT);
        byte[] key = hexStringToByteArray(KEY_FOR_256_BITS);

        AES szyfr = new AES(key);
        byte[] ciphertext = szyfr.encrypt(plaintext);

        byte[] actualPlaintext = szyfr.decrypt(ciphertext);

        assertEquals(EXPECTED_CIPHERTEXT, bytesToHex(ciphertext));
        assertEquals(PLAINTEXT, bytesToHex(actualPlaintext));
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
