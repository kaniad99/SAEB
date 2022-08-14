import SAEB.SAEB;
import org.junit.Test;
import tiny.AES;

import static org.example.Main.hexStringToByteArray;
import static org.junit.Assert.assertEquals;

public class SAEBTest {

    public static final String ASSOCIATED_FULL = "01020304050607081122334455667788";
    //    Two chars making one byte (this example makes array of {1,2,3,4,5,6,7,8}
    public static final String ASSOCIATED_FIRST_BLOCK = "0102030405060708";
    public static final String ASSOCIATED_SECOND_BLOCK = "1122334455667788";

    @Test
    public void hashRoundTest() {
        byte[] key = hexStringToByteArray(AESTest.KEY_FOR_128_BITS);

        AES aes = new AES(key);
        SAEB saeb = new SAEB();

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

        hashState = aes.encrypt(hashState);
        assertEquals("a53504caba30cfccf77ecfaf3b9d7fc7", TestUtils.bytesToHex(hashState));




        byte[] result = saeb.hash(hexStringToByteArray(ASSOCIATED_FULL), new byte[8]);
        assertEquals(TestUtils.bytesToHex(hashState), TestUtils.bytesToHex(result));

    }


}
