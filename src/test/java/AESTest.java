import ciphers.AES;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static utils.Utils.bytesToHex;
import static utils.Utils.hexStringToByteArray;

public class AESTest {
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

}
