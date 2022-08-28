package modes;

import Utils.GF2_128;
import ciphers.Cipher;

import java.io.ByteArrayOutputStream;
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

        byte[] y0;
        byte[] plaintextBlock;
        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        if (iv.length == 12) {
            y0 = Arrays.copyOf(iv, n);
            y0[y0.length - 1] = (byte) 0x01;
        } else {
            y0 = ghashForIV(h, iv);
        }

        byte[] y = Arrays.copyOf(y0, y0.length);

        int i;
        for (i = 0; i + n < plaintext.length; i = i + n) {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + n);
            ciphertextStream.writeBytes(xorBlocks(plaintextBlock, cipher.encrypt(y)));
            incr(y);
        }

        int dif = plaintext.length - i;
        if (dif == n) {
            incr(y);
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + n);
            ciphertextStream.writeBytes(xorBlocks(plaintextBlock, cipher.encrypt(y)));

        } else {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + dif);

            ciphertextStream.writeBytes(xorBlocks(plaintextBlock, cipher.encrypt(y)));
            incr(y);
        }
        System.out.println(bytesToHex(y0));
        System.out.println(bytesToHex(cipher.encrypt(y0)));
        System.out.println(bytesToHex(ciphertextStream.toByteArray()));

        byte[] state = xorBlocks(ghash(h, associatedData, ciphertextStream.toByteArray()), cipher.encrypt(y0));
        byte[] tag = Arrays.copyOf(state, t);
        return new GCMResult(ciphertextStream.toByteArray(), tag);
    }

    private byte[] ghash(GF2_128 h, byte[] associatedData, byte[] ciphertext) {
        return new byte[16];
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
