import ciphers.AES;
import modes.OCB;
import modes.OCBResult;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;

public class OCBTest {
    private static final String KEY1 = "000102030405060708090A0B0C0D0E0F";

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
    public void encryptTestCase1() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("0001020304050607000102030405060700010203040506070001020304050607");

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreEncrypt(nonce, associated, plaintext);

        assertEquals("e1463e8dba276a7c3b32c3a013c40024b1c0f12fe90c1bdaafa6b508cff48509", TestUtils.bytesToHex(result.getResult()));
        assertEquals("a0940fdf21e99717531149429bec3dad", TestUtils.bytesToHex(result.getTag()));
    }


    @Test
    public void decryptTestCase1() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("e1463e8dba276a7c3b32c3a013c40024b1c0f12fe90c1bdaafa6b508cff48509");

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, plaintext);

        assertEquals("0001020304050607000102030405060700010203040506070001020304050607", TestUtils.bytesToHex(result.getResult()));
        assertEquals("a0940fdf21e99717531149429bec3dad", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void encryptTestCase2() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] plaintext = TestUtils.hexStringToByteArray("0001020304050607");

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreEncrypt(nonce, associated, plaintext);

        assertEquals("6820b3657b6f615a", TestUtils.bytesToHex(result.getResult()));
        assertEquals("5725bda0d3b4eb3a257c9af1f8f03009", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void decryptTestCase2() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("BBAA99887766554433221101");
        byte[] associated = TestUtils.hexStringToByteArray("0001020304050607");
        byte[] ciphertext = TestUtils.hexStringToByteArray("6820b3657b6f615a");

        nonce = getNonce(nonce);

        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, ciphertext);

        assertEquals("0001020304050607", TestUtils.bytesToHex(result.getResult()));
        assertEquals("5725bda0d3b4eb3a257c9af1f8f03009", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void encryptTestCase3() {
        byte[] key = TestUtils.hexStringToByteArray(KEY1);
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
    public void decryptTestCase3() {
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
    public void encryptTestCase4() {

        byte[] key = TestUtils.hexStringToByteArray(KEY1);
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
    public void decryptTestCase4() {

        byte[] key = TestUtils.hexStringToByteArray(KEY1);
        byte[] nonce = TestUtils.hexStringToByteArray("000102030405060708090A0B");
        byte[] associated = TestUtils.hexStringToByteArray("");
        byte[] plaintext = TestUtils.hexStringToByteArray("bea5e8798dbe7110031c144da0b26122ceaab9b05df771a657149d53773463cb68c65778b058a635");

        nonce = getNonce(nonce);
        OCB ocb = new OCB(16, new AES(key));

        OCBResult result = ocb.coreDecrypt(nonce, associated, plaintext);

        // error in tag creating in decryption
        assertEquals("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627", TestUtils.bytesToHex(result.getResult()));
        assertEquals("060c8467f4abab5e8b3c2067a2e115dc", TestUtils.bytesToHex(result.getTag()));
    }

    private byte[] getNonce(byte[] nonce) {
        ByteArrayOutputStream nonceStream = new ByteArrayOutputStream();
        for (int i = 0; i < 16 - nonce.length - 1; i++) {
            nonceStream.write(0x00);
        }
        nonceStream.write(0x01);
        for (byte b : nonce) {
            nonceStream.write(b);
        }

        nonce = nonceStream.toByteArray();
        return nonce;
    }
}
