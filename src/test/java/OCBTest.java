import ciphers.AES;
import modes.OCB;
import modes.OCBResult;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;

public class OCBTest {
    private static final String KEY1 = "000102030405060708090A0B0C0D0E0F";
    private static final String NONCE = "BBAA9988776655443322110F";

    @Test
    public void doubleTest() {
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
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("0001020304050607");

        int nonceLength = nonce.length;

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreEncrypt(nonce, associated, plaintext);

        assertEquals("6820b3657b6f615a", TestUtils.bytesToHex(result.getResult()));
        assertEquals("5725bda0d3b4eb3a257c9af1f8f03009", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void decryptTest() {
        byte[] plaintext;
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] ciphertext = TestUtils.hexStringToByteArray("6820b3657b6f615a");

        int nonceLength = nonce.length;

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, ciphertext);

        // error in tag creating in decryption
        assertEquals("0001020304050607", TestUtils.bytesToHex(result.getResult()));
        assertEquals("5725bda0d3b4eb3a257c9af1f8f03009", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void encryptExtendedTestCase2() {
        byte[] key = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA9988776655443322110F");
        byte[] associated = TestUtils.hexStringToByteArray("");
        byte[] plaintext = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreEncrypt(nonce, associated, plaintext);

        assertEquals("4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e", TestUtils.bytesToHex(result.getResult()));
        assertEquals("479ad363ac366b95a98ca5f3000b1479", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void decryptExtendedTestCase2() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA9988776655443322110F");
        byte[] associated = TestUtils.hexStringToByteArray("");
        byte[] ciphertext = TestUtils.hexStringToByteArray("4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, ciphertext);


        // error in tag creating in decryption
        assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627", TestUtils.bytesToHex(result.getResult()));
        assertEquals("479ad363ac366b95a98ca5f3000b1479", TestUtils.bytesToHex(result.getTag()));
    }

    // case taken from documentation
    @Test
    public void encryptExtendedTestCase1() {

        byte[] key = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
        byte[] nonce = TestUtils.hexStringToByteArray("000102030405060708090A0B");
        byte[] associated = TestUtils.hexStringToByteArray("");
        byte[] plaintext = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreEncrypt(nonce, associated, plaintext);

        assertEquals("bea5e8798dbe7110031c144da0b26122ceaab9b05df771a657149d53773463cb68c65778b058a635", TestUtils.bytesToHex(result.getResult()));
        assertEquals("060c8467f4abab5e8b3c2067a2e115dc", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void decryptExtendedTestCase1() {

        byte[] key = TestUtils.hexStringToByteArray("000102030405060708090A0B0C0D0E0F");
        byte[] nonce = TestUtils.hexStringToByteArray("000102030405060708090A0B");
        byte[] associated = TestUtils.hexStringToByteArray("");
        byte[] plaintext = TestUtils.hexStringToByteArray("bea5e8798dbe7110031c144da0b26122ceaab9b05df771a657149d53773463cb68c65778b058a635");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, plaintext);

        // error in tag creating in decryption
        assertEquals("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627", TestUtils.bytesToHex(result.getResult()));
        assertEquals("060c8467f4abab5e8b3c2067a2e115dc", TestUtils.bytesToHex(result.getTag()));
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
