import saeb.SAEB;
import org.junit.Before;
import org.junit.Test;
import tiny.AES;

import static org.example.Main.hexStringToByteArray;
import static org.junit.Assert.assertEquals;

public class SAEBTest {

    public static final String ASSOCIATED_FULL = "01020304050607081122334455667788";
    public static final String TEST_NONCE_BYTES = "80000001";
    public static final String ASSOCIATED_FULL_NONEVEN = "010203040506070811223344556677880102";
    //    Two chars making one byte (this example makes array of {1,2,3,4,5,6,7,8}
    public static final String ASSOCIATED_FIRST_BLOCK = "0102030405060708";
    public static final String ASSOCIATED_SECOND_BLOCK = "1122334455667788";
    public static final String ASSOCIATED_THIRD_BLOCK = "0102800000000000";

    private SAEB saeb;
    private AES aes;

    @Before
    public void init() {
        byte[] key = hexStringToByteArray(AESTest.KEY_FOR_128_BITS);

        aes = new AES(key);
        saeb = new SAEB();
    }

    @Test
    public void hashEvenRoundTest() {
        byte[] hashState = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(hashState));

        byte[] associated = hexStringToByteArray(ASSOCIATED_FIRST_BLOCK);
        assertEquals("0102030405060708", TestUtils.bytesToHex(associated));

        hashState = saeb.xorFullBlocks(hashState, associated);
        assertEquals("01020304050607080000000000000000", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("18ba69bb4661fee5a7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        associated = hexStringToByteArray(ASSOCIATED_SECOND_BLOCK);
        assertEquals("1122334455667788", TestUtils.bytesToHex(associated));

        hashState = saeb.xorFullBlocks(hashState, associated);
        assertEquals("09985aff1307896da7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        hashState[hashState.length - 1] ^= 0x01;
        assertEquals("09985aff1307896da7cc9ec1a731e279", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("f2a3dea9bad2fed98103e414cb303502", TestUtils.bytesToHex(hashState));

        hashState = saeb.hashLastRound(hashState, hexStringToByteArray(TEST_NONCE_BYTES));
        assertEquals("72a3dea8bad2fed98103e414cb303501", TestUtils.bytesToHex(hashState));

    }

    @Test
    public void hashEvenTest() {
        byte[] result = saeb.hash(hexStringToByteArray(ASSOCIATED_FULL), hexStringToByteArray(TEST_NONCE_BYTES));
        assertEquals("72a3dea8bad2fed98103e414cb303501", TestUtils.bytesToHex(result));
    }

    @Test
    public void hashNonEvenRoundTest() {
        byte[] hashState = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(hashState));

        byte[] associated = hexStringToByteArray(ASSOCIATED_FIRST_BLOCK);
        assertEquals("0102030405060708", TestUtils.bytesToHex(associated));

        hashState = saeb.xorFullBlocks(hashState, associated);
        assertEquals("01020304050607080000000000000000", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("18ba69bb4661fee5a7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        /////////////////////////////////////////////////////////////////////////////////////////

        associated = hexStringToByteArray(ASSOCIATED_SECOND_BLOCK);
        assertEquals("1122334455667788", TestUtils.bytesToHex(associated));

        hashState = saeb.xorFullBlocks(hashState, associated);
        assertEquals("09985aff1307896da7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("a53504caba30cfccf77ecfaf3b9d7fc7", TestUtils.bytesToHex(hashState));

        /////////////////////////////////////////////////////////////////////////////////////////

        hashState[hashState.length - 1] ^= 0x02;
        assertEquals("a53504caba30cfccf77ecfaf3b9d7fc5", TestUtils.bytesToHex(hashState));

        associated = hexStringToByteArray(ASSOCIATED_THIRD_BLOCK);
        assertEquals("0102800000000000", TestUtils.bytesToHex(associated));

        hashState = saeb.xorFullBlocks(hashState, associated);
        assertEquals("a43784caba30cfccf77ecfaf3b9d7fc5", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("0ad86ed88ca7b82e046b34e92fd40079", TestUtils.bytesToHex(hashState));

        hashState = saeb.hashLastRound(hashState, hexStringToByteArray(TEST_NONCE_BYTES));
        assertEquals("8ad86ed98ca7b82e046b34e92fd4007a", TestUtils.bytesToHex(hashState));

    }

    @Test
    public void hashNonEvenTest() {
        byte[] result = saeb.hash(hexStringToByteArray(ASSOCIATED_FULL_NONEVEN), hexStringToByteArray(TEST_NONCE_BYTES));
        assertEquals("8ad86ed98ca7b82e046b34e92fd4007a", TestUtils.bytesToHex(result));
    }

}
