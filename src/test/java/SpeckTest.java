import ciphers.Speck;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class SpeckTest {

    @Test
    public void speck64128Test() {
        byte[] plaintext = TestUtils.hexStringToByteArray("3b7265747475432d");
        byte[] plaintextBase = TestUtils.hexStringToByteArray("3b7265747475432d");
        byte[] ciphertext = TestUtils.hexStringToByteArray("8c6fa548454e028b");
        byte[] key = TestUtils.hexStringToByteArray("1b1a1918131211100b0a090803020100");

        Speck speck = new Speck(64, key);

        byte[] ciphertext2 = speck.encrypt(plaintext);
        assertArrayEquals(ciphertext, ciphertext2);

        byte[] plaintext2 = speck.decrypt(ciphertext);
        assertArrayEquals(plaintextBase, plaintext2);
    }

    @Test
    public void speck128256Test() {
        byte[] plaintext = TestUtils.hexStringToByteArray("65736f6874206e49202e72656e6f6f70");
        byte[] plaintextBase = TestUtils.hexStringToByteArray("65736f6874206e49202e72656e6f6f70");
        byte[] ciphertext = TestUtils.hexStringToByteArray("4109010405c0f53e4eeeb48d9c188f43");
        byte[] key = TestUtils.hexStringToByteArray("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

        Speck speck = new Speck(128, key);

        byte[] ciphertext2 = speck.encrypt(plaintext);
        assertArrayEquals(ciphertext, ciphertext2);

        byte[] plaintext2 = speck.decrypt(ciphertext);
        assertArrayEquals(plaintextBase, plaintext2);
    }
}
