import ciphers.AES;
import modes.OCB;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;

public class ODBTest {
    private static final String KEY1 = "000102030405060708090A0B0C0D0E0F";
    private static final String NONCE = "000102030405060708090A0B";

    @Test
    public void doubleTest() {
        String KEY = "00000000000000000000000000000000";
        String TEST_STATE = "80000000000000000000000000000000";
        byte[] key = TestUtils.hexStringToByteArray(KEY);
        byte[] state = TestUtils.hexStringToByteArray(TEST_STATE);

        OCB ocb = new OCB(10, new AES(key));

        state = ocb.toDouble(state);

        assertEquals("00000000000000000000000000000087", TestUtils.bytesToHex(state));
    }

    @Test
    public void doubleTest2() {
        String KEY = "00000000000000000000000000000000";
        String TEST_STATE = "00000000000000000000000000e00123";
        byte[] key = TestUtils.hexStringToByteArray(KEY);
        byte[] state = TestUtils.hexStringToByteArray(TEST_STATE);

        OCB ocb = new OCB(10, new AES(key));

        state = ocb.toDouble(state);

        assertEquals("00000000000000000000000001c00246", TestUtils.bytesToHex(state));
    }


    @Test
    public void hashTest() {
        String KEY = "00000000000000000000000000000000";
        String TEST_STATE = "00000000000000000000000000e00123";
        byte[] key = TestUtils.hexStringToByteArray(KEY);
        byte[] state = TestUtils.hexStringToByteArray(TEST_STATE);

        OCB ocb = new OCB(10, new AES(key));

        state = ocb.hash(state);

        assertEquals("30b0f6e92367359bf558398a12ef794f", TestUtils.bytesToHex(state));
    }

    @Test
    public void encryptTest() {
        byte[] ciphertext;
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray(NONCE);
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("0001020304050607");

        int nonceLength = nonce.length;

        nonce = Arrays.copyOf(nonce, 16);
        nonce[nonceLength] = (byte) 0x80;

        OCB ocb = new OCB(16, new AES(key));

        ciphertext = ocb.encrypt(nonce, associated, plaintext);

        assertEquals("358f700c94a0fb78f0d18aa1a5a5f42e", TestUtils.bytesToHex(ciphertext));
    }

    @Test
    public void encryptExtendedTest() {
        byte[] ciphertext;
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray(NONCE);
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        ciphertext = ocb.encrypt(nonce, associated, plaintext);

        assertEquals("bea5e8798dbe7110031c144da0b26122ceaab9b05df771a657149d53773463cb68c65778b058a635", TestUtils.bytesToHex(ciphertext));
    }

    @Test
    public void decryptExtendedTest() {
        byte[] plaintext;
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray(NONCE);
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] ciphertext = TestUtils.hexStringToByteArray("bea5e8798dbe7110031c144da0b26122ceaab9b05df771a657149d53773463cb68c65778b058a635");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        plaintext = ocb.decrypt(nonce, associated, ciphertext);

        assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627", TestUtils.bytesToHex(plaintext));
    }

    private byte[] getNonce(byte[] nonce) {
        ByteArrayOutputStream nonceStream = new ByteArrayOutputStream();
        for (int i = 0; i < 16 - nonce.length - 1; i++) {
            nonceStream.write(0x00);
        }
        nonceStream.write(0x01);
        for (int i = 0; i < nonce.length; i++) {
            nonceStream.write(nonce[i]);
        }

        nonce = nonceStream.toByteArray();
        return nonce;
    }
}
