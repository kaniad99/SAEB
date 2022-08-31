import ciphers.AES;
import org.junit.Before;
import org.junit.Test;
import saeb.SAEB;
import saeb.SAEBResult;

import java.io.ByteArrayOutputStream;

import static org.junit.Assert.assertEquals;
import static utils.Utils.hexStringToByteArray;

public class SAEBComponentTest {

    public static final String ASSOCIATED_FULL = "01020304050607081122334455667788";
    public static final String TEST_NONCE_BYTES = "80000001";
    public static final String ASSOCIATED_FULL_NONEVEN = "010203040506070811223344556677880102";
    //    Two chars making one byte (this example makes array of {1,2,3,4,5,6,7,8}
    public static final String ASSOCIATED_FIRST_BLOCK = "0102030405060708";
    public static final String ASSOCIATED_SECOND_BLOCK = "1122334455667788";
    public static final String ASSOCIATED_THIRD_BLOCK = "0102800000000000";

    public static final String PLAINTEXT_FIRST_BLOCK = "010203040506";
    public static final String PLAINTEXT_SECOND_BLOCK = "070811223344";
    public static final String PLAINTEXT_THIRD_BLOCK = "010203040506";

    public static final String PLAINTEXT_FULL_BLOCK = "0123456789abcdef0123456789abcdef0123456789abcdef";
    public static final String CIPHERTEXT_FULL_BLOCK = "c7827e500e248a11d4771c9477f78f8b60f8fa54b48494b1";
    public static final String PLAINTEXT_NON_EVEN_FULL_BLOCK = "0123456789abcdef0123456789abcdef0123456789abcdef0123";
    public static final String CIPHERTEXT_NON_EVEN_FULL_BLOCK = "c7827e500e248a11d4771c9477f78f8b60f8fa54b48494b111b3";


    public static final int R = 6;

    private SAEB saeb;
    private AES aes;

    @Before
    public void init() {
        int n = 16;
        int r1 = 8;
        int r = 6;
        int t = 12;

        byte[] key = hexStringToByteArray(AESTest.KEY_FOR_128_BITS);

        aes = new AES(key);
        saeb = new SAEB(n, r1, r, t, aes);
    }

    @Test
    public void encryptEvenBasicOperationsTest() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        byte[] iv = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(iv));

        byte[] state = aes.encrypt(iv);
        assertEquals("c6a13b37878f5b826f4f8162a1c8d879", TestUtils.bytesToHex(state));

        byte[] plaintextBlock = TestUtils.hexStringToByteArray(PLAINTEXT_FIRST_BLOCK);
        state = saeb.xorBlocks(state, plaintextBlock);
        assertEquals("c7a3383382895b826f4f8162a1c8d879", TestUtils.bytesToHex(state));
        stream.write(state, 0, R);
        state = aes.encrypt(state);
        assertEquals("b278fa28336f49bf95d326b642d874c8", TestUtils.bytesToHex(state));

        plaintextBlock = TestUtils.hexStringToByteArray(PLAINTEXT_SECOND_BLOCK);
        state = saeb.xorBlocks(state, plaintextBlock);
        assertEquals("b570eb0a002b49bf95d326b642d874c8", TestUtils.bytesToHex(state));
        stream.write(state, 0, R);
        state = aes.encrypt(state);
        assertEquals("846042c86c8007a857cd1a1827af0586", TestUtils.bytesToHex(state));

        plaintextBlock = TestUtils.hexStringToByteArray(PLAINTEXT_THIRD_BLOCK);
        state = saeb.xorBlocks(state, plaintextBlock);
        state[state.length - 1] ^= 0x01;
        assertEquals("856241cc698607a857cd1a1827af0587", TestUtils.bytesToHex(state));

    }

    @Test
    public void encryptEven() {
        byte[] iv = new byte[16];

        SAEBResult saebEncResult = saeb.coreEncrypt(iv, TestUtils.hexStringToByteArray(PLAINTEXT_FULL_BLOCK));

        assertEquals(CIPHERTEXT_FULL_BLOCK, TestUtils.bytesToHex(saebEncResult.getResult()));
    }

    @Test
    public void decryptEven() {
        byte[] iv = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(iv));

        SAEBResult saebDecResult = saeb.coreDecrypt(iv, TestUtils.hexStringToByteArray(CIPHERTEXT_FULL_BLOCK));

        assertEquals(PLAINTEXT_FULL_BLOCK, TestUtils.bytesToHex(saebDecResult.getResult()));
    }

    @Test
    public void encryptNonEven() {
        byte[] iv = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(iv));

        SAEBResult saebEncResult = saeb.coreEncrypt(iv, TestUtils.hexStringToByteArray(PLAINTEXT_NON_EVEN_FULL_BLOCK));

        assertEquals(CIPHERTEXT_NON_EVEN_FULL_BLOCK, TestUtils.bytesToHex(saebEncResult.getResult()));
    }

    @Test
    public void decryptNonEven() {
        byte[] iv = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(iv));

        SAEBResult saebDecResult = saeb.coreDecrypt(iv, TestUtils.hexStringToByteArray(CIPHERTEXT_NON_EVEN_FULL_BLOCK));

        assertEquals(PLAINTEXT_NON_EVEN_FULL_BLOCK, TestUtils.bytesToHex(saebDecResult.getResult()));
    }


    @Test
    public void hashEvenRoundTest() {
        byte[] hashState = new byte[16];
        assertEquals("00000000000000000000000000000000", TestUtils.bytesToHex(hashState));

        byte[] associated = hexStringToByteArray(ASSOCIATED_FIRST_BLOCK);
        assertEquals("0102030405060708", TestUtils.bytesToHex(associated));

        hashState = saeb.xorBlocks(hashState, associated);
        assertEquals("01020304050607080000000000000000", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("18ba69bb4661fee5a7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        associated = hexStringToByteArray(ASSOCIATED_SECOND_BLOCK);
        assertEquals("1122334455667788", TestUtils.bytesToHex(associated));

        hashState = saeb.xorBlocks(hashState, associated);
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

        hashState = saeb.xorBlocks(hashState, associated);
        assertEquals("01020304050607080000000000000000", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("18ba69bb4661fee5a7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        /////////////////////////////////////////////////////////////////////////////////////////

        associated = hexStringToByteArray(ASSOCIATED_SECOND_BLOCK);
        assertEquals("1122334455667788", TestUtils.bytesToHex(associated));

        hashState = saeb.xorBlocks(hashState, associated);
        assertEquals("09985aff1307896da7cc9ec1a731e278", TestUtils.bytesToHex(hashState));

        hashState = aes.encrypt(hashState);
        assertEquals("a53504caba30cfccf77ecfaf3b9d7fc7", TestUtils.bytesToHex(hashState));

        /////////////////////////////////////////////////////////////////////////////////////////

        hashState[hashState.length - 1] ^= 0x02;
        assertEquals("a53504caba30cfccf77ecfaf3b9d7fc5", TestUtils.bytesToHex(hashState));

        associated = hexStringToByteArray(ASSOCIATED_THIRD_BLOCK);
        assertEquals("0102800000000000", TestUtils.bytesToHex(associated));

        hashState = saeb.xorBlocks(hashState, associated);
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
