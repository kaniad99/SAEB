import ciphers.SimonEngine;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class SimonTest {

//    Simon32/64
//    Key: 1918 1110 0908 0100
//    Plaintext: 6565 6877
//    Ciphertext: c69b e9bb

//    Simon48/72
//    Key: 121110 0a0908 020100
//    Plaintext: 612067 6e696c
//    Ciphertext: dae5ac 292cac

//    Simon48/96
//    Key: 1a1918 121110 0a0908 020100
//    Plaintext: 726963 20646e
//    Ciphertext: 6e06a5 acf156

//    Simon64/96
//    Key: 13121110 0b0a0908 03020100
//    Plaintext: 6f722067 6e696c63
//    Ciphertext: 5ca2e27f 111a8fc8

//    Simon64/128
//    Key: 1b1a1918 13121110 0b0a0908 03020100
//    Plaintext: 656b696c 20646e75
//    Ciphertext: 44c8fc20 b9dfa07a

//    Simon96/96
//    Key: 0d0c0b0a0908 050403020100
//    Plaintext: 2072616c6c69 702065687420
//    Ciphertext: 602807a462b4 69063d8ff082

//    Simon96/144
//    Key: 151413121110 0d0c0b0a0908 050403020100
//    Plaintext: 746168742074 73756420666f
//    Ciphertext: ecad1c6c451e 3f59c5db1ae9

//    Simon128/128
//    Key: 0f0e0d0c0b0a0908 0706050403020100
//    Plaintext: 6373656420737265 6c6c657661727420
//    Ciphertext: 49681b1e1e54fe3f 65aa832af84e0bbc

//    Simon128/192
//    Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
//    Plaintext: 206572656874206e 6568772065626972
//    Ciphertext: c4ac61effcdc0d4f 6c9c8d6e2597b85b

//    Simon128/256
//    Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
//    Plaintext: 74206e69206d6f6f 6d69732061207369
//    Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868


    @Test
    public void testEncryptSimon() {
        //SIMON 64/128
        //Key: 1b1a1918 13121110 0b0a0908 03020100
        //Plaintext: 656b696c 20646e75
        //Ciphertext: 44c8fc20 b9dfa07a
        final byte[] key64 = {
                0x1b, 0x1a, 0x19, 0x18, 0x13, 0x12, 0x11, 0x10, 0x0b, 0x0a, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00
        };
        final byte[] io64 = {
                0x65, 0x6b, 0x69, 0x6c, 0x20, 0x64, 0x6e, 0x75
        };

        System.out.println("SIMON 64/128");
        System.out.print("Key: ");
        System.out.println(TestUtils.bytesToHex(key64));
        System.out.println();

        System.out.print("Plaintext (original): ");
        System.out.println(TestUtils.bytesToHex(io64));
        System.out.println();

        byte[] plaintext1 = Arrays.copyOf(io64, io64.length);

        byte[] ciphertext = SimonEngine.encrypt1(64, key64, io64);

        System.out.print("Ciphertext: ");
        System.out.println(TestUtils.bytesToHex(ciphertext));
        System.out.println();

        byte[] plaintext2 = SimonEngine.decrypt1(64, key64, ciphertext);

        System.out.print("Plaintext (decryption): ");
        System.out.println(TestUtils.bytesToHex(io64));
        System.out.println();

        Assert.assertArrayEquals(plaintext1, plaintext2);
    }

    @Test
    public void anotherEncryptionTest() {
        //    Simon128/256
        //    Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
        //    Plaintext: 74206e69206d6f6f 6d69732061207369
        //    Ciphertext: 8d2b5579afc8a3a0 3bf72a87efe7b868

        byte[] state = TestUtils.hexStringToByteArray("74206e69206d6f6f6d69732061207369");
        byte[] key = TestUtils.hexStringToByteArray("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

        System.out.println("SIMON 64/128");
        System.out.print("Key: ");
        System.out.println(TestUtils.bytesToHex(key));
        System.out.println();

        System.out.print("Plaintext (original): ");
        System.out.println(TestUtils.bytesToHex(state));
        System.out.println();

        byte[] plaintext1 = Arrays.copyOf(state, state.length);

        byte[] ciphertext = SimonEngine.encrypt1(128, key, state);

        System.out.print("Ciphertext: ");
        System.out.println(TestUtils.bytesToHex(ciphertext));
        System.out.println();

        byte[] plaintext2 = SimonEngine.decrypt1(128, key, ciphertext);

        System.out.print("Plaintext (decryption): ");
        System.out.println(TestUtils.bytesToHex(state));
        System.out.println();

        Assert.assertArrayEquals(plaintext1, plaintext2);
    }
}
