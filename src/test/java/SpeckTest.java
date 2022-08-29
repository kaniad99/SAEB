import ciphers.Speck;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class SpeckTest {

    @Test
    public void SpeckEncryptionTest() {
        //    Simon128/256
        //    Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
        //    Plaintext: 74206e69206d6f6f 6d69732061207369
        //    Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868

        byte[] plaintext = TestUtils.hexStringToByteArray("3b7265747475432d");
        byte[] plaintextBase = TestUtils.hexStringToByteArray("3b7265747475432d");
        byte[] ciphertext = TestUtils.hexStringToByteArray("8c6fa548454e028b");
        byte[] key = TestUtils.hexStringToByteArray("1b1a1918131211100b0a090803020100");

        System.out.println("SIMON 64/128");
        System.out.print("Key: ");
        System.out.println(TestUtils.bytesToHex(key));
        System.out.println();

        System.out.print("Plaintext (original): ");
        System.out.println(TestUtils.bytesToHex(plaintext));
        System.out.println();

        Speck speck = new Speck(64, key);

        byte[] ciphertext2 = speck.encrypt(plaintext);

        assertArrayEquals(ciphertext, ciphertext2);

        System.out.print("Ciphertext: ");
        System.out.println(TestUtils.bytesToHex(ciphertext));
        System.out.println();

        byte[] plaintext2 = speck.decrypt(ciphertext);

        System.out.print("Plaintext (decryption): ");
        System.out.println(TestUtils.bytesToHex(plaintext2));
        System.out.println();

        assertArrayEquals(plaintextBase, plaintext2);
    }

    @Test
    public void Speck128256EncryptionTest() {
        byte[] plaintext = TestUtils.hexStringToByteArray("65736f6874206e49202e72656e6f6f70");
        byte[] plaintextBase = TestUtils.hexStringToByteArray("65736f6874206e49202e72656e6f6f70");
        byte[] ciphertext = TestUtils.hexStringToByteArray("4109010405c0f53e4eeeb48d9c188f43");
        byte[] key = TestUtils.hexStringToByteArray("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

        System.out.println("SIMON 128/256");
        System.out.print("Key: ");
        System.out.println(TestUtils.bytesToHex(key));
        System.out.println();

        System.out.print("Plaintext (original): ");
        System.out.println(TestUtils.bytesToHex(plaintext));
        System.out.println();

        Speck speck = new Speck(64, key);

        byte[] ciphertext2 = speck.encrypt(plaintext);

        assertArrayEquals(ciphertext, ciphertext2);

        System.out.print("Ciphertext: ");
        System.out.println(TestUtils.bytesToHex(ciphertext));
        System.out.println();

        byte[] plaintext2 = speck.decrypt(ciphertext);

        System.out.print("Plaintext (decryption): ");
        System.out.println(TestUtils.bytesToHex(plaintext2));
        System.out.println();

        assertArrayEquals(plaintextBase, plaintext2);
    }
}
