package modes;

import ciphers.Cipher;
import utils.GF2_128;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class GCM {
    //    Block cipher size (in bytes)
    private final int n;
    //    Associated data block size in bytes
    private final int r1;
    //    Plaintext and ciphertext block sizes in bytes
    private final int r;
    //    Tag size in bytes
    private final int t;
    //    block cipher class implementing Cipher interface
    private final Cipher cipher;

    public GCM(int n, int r1, int r, int t, Cipher cipher) {
        this.n = n;
        this.r1 = r1;
        this.r = r;
        this.t = t;
        this.cipher = cipher;
    }

    //
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    //

    public GCMResult encrypt(byte[] iv, byte[] plaintext, byte[] associatedData) {
        GF2_128 h = new GF2_128(cipher.encrypt(new byte[n]));
        GF2_128 x = new GF2_128(new byte[n]);

        ghashInit(x, h, associatedData);

        System.out.println("h: " + bytesToHex(h.toByteArray()));

        byte[] y0;
        byte[] plaintextBlock;
        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        if (iv.length == 12) {
            y0 = Arrays.copyOf(iv, n);
            y0[y0.length - 1] = (byte) 0x01;
        } else {
            y0 = ghashForIV(h, iv);
        }

        System.out.println("y0: " + bytesToHex(y0));

        byte[] y = Arrays.copyOf(y0, y0.length);

        System.out.println("y: " + bytesToHex(y));

        System.out.println("E(K,Yo): " + bytesToHex(cipher.encrypt(y0)));

        byte[] temp;

        int i;
        for (i = 0; i + n < plaintext.length; i = i + n) {
            incr(y);
            System.out.println("y: " + bytesToHex(y));
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + n);
            temp = xorBlocks(plaintextBlock, cipher.encrypt(y));
            System.out.println("E(K,Y): " + bytesToHex(temp));
            ciphertextStream.writeBytes(temp);

        }

        int dif = plaintext.length - i;
        if (dif == n) {
            incr(y);
            System.out.println("y: " + bytesToHex(y));
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + n);
            temp = xorBlocks(plaintextBlock, cipher.encrypt(y));
            System.out.println("E(K,Y): " + bytesToHex(temp));
            ciphertextStream.writeBytes(temp);

        } else {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + dif);

            ciphertextStream.writeBytes(xorBlocks(plaintextBlock, cipher.encrypt(y)));
            incr(y);
        }

        byte[] ghash = ghash(h, associatedData, ciphertextStream.toByteArray());

        System.out.println("GHASH(): " + bytesToHex(ghash));

        byte[] state = xorBlocks(ghash(h, associatedData, ciphertextStream.toByteArray()), cipher.encrypt(y0));
        byte[] tag = Arrays.copyOf(state, t);
        return new GCMResult(ciphertextStream.toByteArray(), tag);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
    private byte[] ghash(GF2_128 h, byte[] ciphertext) {
        GF2_128 x = new GF2_128();

        int i;
        for (i = 0; i + 16 < ciphertext.length; i += 16) {
            GF2_128.add(x, x, new GF2_128(Arrays.copyOfRange(ciphertext, i, i + 16)));
            GF2_128.mul(x, x, h);

            System.out.println("x: " + bytesToHex(x.toByteArray()));
        }
        System.out.println("Ciphertext: " + bytesToHex(ciphertext));

        GF2_128.add(x, x, new GF2_128(Arrays.copyOfRange(ciphertext, i, i + 16)));
        GF2_128.mul(x, x, h);

        System.out.println("x: " + bytesToHex(x.toByteArray()));

        byte[] lengths = getLengths(0, ciphertext.length);
        GF2_128 length = new GF2_128(lengths);

        System.out.println("Len(A)||len(C): " + bytesToHex(length.toByteArray()));
        GF2_128.add(x, x, length);
        GF2_128.mul(x, x, h);

        System.out.println("x: " + bytesToHex(x.toByteArray()));
        return x.toByteArray();
    }

    private byte[] ghash(GF2_128 h, byte[] associatedData, byte[] ciphertext) {
        GF2_128 x = new GF2_128();

        int i;
        for (i = 0; i + 16 < ciphertext.length; i += 16) {
            GF2_128.add(x, x, new GF2_128(Arrays.copyOfRange(ciphertext, i, i + 16)));
            GF2_128.mul(x, x, h);

            System.out.println("x: " + bytesToHex(x.toByteArray()));
        }
        System.out.println("Ciphertext: " + bytesToHex(ciphertext));

        GF2_128.add(x, x, new GF2_128(Arrays.copyOfRange(ciphertext, i, i + 16)));
        GF2_128.mul(x, x, h);

        System.out.println("x: " + bytesToHex(x.toByteArray()));

        GF2_128 length = new GF2_128(getLengths(associatedData.length, ciphertext.length));

        System.out.println("Len(A)||len(C): " + bytesToHex(length.toByteArray()));
        GF2_128.add(x, x, length);
        GF2_128.mul(x, x, h);

        System.out.println("x: " + bytesToHex(x.toByteArray()));
        return x.toByteArray();
    }

    private byte[] getLengths(int associatedDataLength, int ciphertextlength) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            stream.write(longToBytes(associatedDataLength * 8L));
            stream.write(longToBytes(ciphertextlength * 8L));
            return stream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(x);
        return buffer.array();
    }

    private byte[] ghashForIV(GF2_128 h, byte[] iv) {
        byte[] ivBlock;

        GF2_128 res = new GF2_128();
        GF2_128 ivCalc;
        GF2_128 x = new GF2_128(new byte[n]);

        int i;
        for (i = 0; i < iv.length; i += n) {
            ivBlock = Arrays.copyOfRange(iv, i, i + n);
            ivCalc = new GF2_128(ivBlock);
            GF2_128.add(res, res, ivCalc);
            GF2_128.mul(res, res, h);
        }
        long[] sizes = new long[]{0, (iv.length / 16) + 1};
        GF2_128 dataSizes = new GF2_128(sizes);
        GF2_128.add(res, x, dataSizes);
        GF2_128.mul(res, res, h);
        return res.toByteArray();
    }

    private void ghashInit(GF2_128 x, GF2_128 h, byte[] associatedData) {
        byte[] associatedDataBlock;

        GF2_128 res = new GF2_128();
        GF2_128 hCalc = new GF2_128(h);
        GF2_128 aCalc;

        for (int i = 0; i < associatedData.length; i += n) {
            associatedDataBlock = Arrays.copyOfRange(associatedData, i, i + n);
            aCalc = new GF2_128(associatedDataBlock);
            GF2_128.add(res, res, aCalc);
            GF2_128.mul(res, res, hCalc);
        }
    }

    private byte[] xorBlocks(byte[] plaintextBlock, byte[] encrypt) {
        byte[] x = new byte[plaintextBlock.length];

        for (int i = 0; i < plaintextBlock.length; i++) {
            x[i] = (byte) (plaintextBlock[i] ^ encrypt[i]);
        }
        return x;
    }

    public static void incr(byte[] y) {
        y[y.length - 1] += 1;

        if (y[y.length - 1] == (byte) 0x00) {
            y[y.length - 2] += 1;
            if (y[y.length - 2] == (byte) 0x00) {
                y[y.length - 3] += 1;
                if (y[y.length - 3] == (byte) 0x00) {
                    y[y.length - 4] += 1;
                    if (y[y.length - 4] == (byte) 0x00) {
                        throw new ArithmeticException("Counter overflow. There are over 2^{32} rounds.");
                    }
                }
            }
        }
    }
}
