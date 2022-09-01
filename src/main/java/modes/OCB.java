package modes;

import ciphers.Cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class OCB {
    //    Block cipher size (in bytes)
    private static final int N_BYTES = 16;
    //    Tag size in bytes
    private final int t;
    //    block cipher class implementing Cipher interface
    private final Cipher cipher;

    public OCB(int t, Cipher cipher) {
        this.t = t;
        this.cipher = cipher;
    }

    public byte[] hash(byte[] associatedData) {
        byte[] sum = new byte[N_BYTES];
        byte[] offset = new byte[N_BYTES];

        byte[] lInit = cipher.encrypt(new byte[N_BYTES]);
        byte[] l0 = toDouble(toDouble(lInit));
        byte[] l = Arrays.copyOf(l0, N_BYTES);

        byte[] associatedDataBlock;
        int i;
        for (i = 0; i + N_BYTES <= associatedData.length; i += N_BYTES) {
            associatedDataBlock = Arrays.copyOfRange(associatedData, i, i + 16);

            byte[] temp = lFunction(l, (i / 16) + 1);
            offset = xorBlocks(offset, temp);
            sum = xorBlocks(sum, cipher.encrypt(xorBlocks(associatedDataBlock, offset)));
        }

        int dif = associatedData.length - i;
        if (dif != 0) {
            offset = xorBlocks(offset, lInit);

            associatedDataBlock = Arrays.copyOfRange(associatedData, i, i + 16);
            associatedDataBlock[dif] = (byte) 0x80;

            byte[] cipherInput = xorBlocks(associatedDataBlock, offset);
            sum = xorBlocks(sum, cipher.encrypt(cipherInput));
        }
        return sum;
    }


    public OCBResult coreEncrypt(byte[] nonce, byte[] associatedData, byte[] plaintext) {
        byte[] lInit = cipher.encrypt(new byte[N_BYTES]);
        byte[] lDollar = toDouble(lInit);
        byte[] l0 = toDouble(lDollar);

        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        int bottom = nonce[nonce.length - 1] & 0b00111111;

        byte[] temp = Arrays.copyOf(nonce, N_BYTES);
        temp[temp.length - 1] = (byte) (temp[temp.length - 1] & 0b11000000);
        byte[] kTop = cipher.encrypt(temp);

        ByteArrayOutputStream stretchStream = new ByteArrayOutputStream();
        try {
            stretchStream.write(kTop);
            stretchStream.write(xorBlocks(Arrays.copyOfRange(kTop, 0, 8), Arrays.copyOfRange(kTop, 1, 9)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] stretch = stretchStream.toByteArray();
        byte[] offset = getOffset(stretch, bottom);
        byte[] checksum = new byte[16];


        byte[] plaintextBlock;
        int i;
        for (i = 0; i + N_BYTES <= plaintext.length; i += N_BYTES) {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + N_BYTES);

            byte[] temp1 = lFunction(l0, (i / N_BYTES) + 1);
            offset = xorBlocks(offset, temp1);
            try {
                ciphertextStream.write(xorBlocks(offset, cipher.encrypt(xorBlocks(plaintextBlock, offset))));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            checksum = xorBlocks(checksum, plaintextBlock);
        }

        int dif = plaintext.length - i;
        if (dif != 0) {
            offset = xorBlocks(offset, lInit);
            byte[] pad = cipher.encrypt(offset);

            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + dif);

            try {
                ciphertextStream.write(xorBlocksAndCut(pad, plaintextBlock));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            byte[] plaintextFull = Arrays.copyOf(plaintextBlock, 16);
            plaintextFull[dif] = (byte) 0x80;

            checksum = xorBlocks(checksum, plaintextFull);
        }

        byte[] tempo = xorBlocks(xorBlocks(checksum, offset), lDollar);
        byte[] tag = xorBlocks(cipher.encrypt(tempo), hash(associatedData));

        return new OCBResult(ciphertextStream.toByteArray(), Arrays.copyOf(tag, t));
    }

    public byte[] decrypt(byte[] nonce, byte[] associatedData, byte[] ciphertext, byte[] tag) {
        OCBResult result = coreDecrypt(nonce, associatedData, ciphertext);
        if (Arrays.equals(result.getTag(), tag)) {
            return result.getResult();
        } else {
            return new byte[0];
        }
    }

    public OCBResult coreDecrypt(byte[] nonce, byte[] associatedData, byte[] ciphertext) {
        byte[] lInit = cipher.encrypt(new byte[N_BYTES]);
        byte[] lDollar = toDouble(lInit);
        byte[] l0 = toDouble(lDollar);
        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();

        int bottom = nonce[nonce.length - 1] & 0b00111111;

        byte[] temp = Arrays.copyOf(nonce, N_BYTES);
        temp[temp.length - 1] = (byte) (temp[temp.length - 1] & 0b11000000);
        byte[] kTop = cipher.encrypt(temp);

        ByteArrayOutputStream stretchStream = new ByteArrayOutputStream();
        try {
            stretchStream.write(kTop);
            stretchStream.write(xorBlocks(Arrays.copyOfRange(kTop, 0, 8), Arrays.copyOfRange(kTop, 1, 9)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] stretch = stretchStream.toByteArray();
        byte[] offset = getOffset(stretch, bottom);
        byte[] checksum = new byte[16];

        byte[] ciphertextBlock;
        byte[] plaintextBlock;
        int i;
        for (i = 0; i + N_BYTES <= ciphertext.length; i += N_BYTES) {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + N_BYTES);

            byte[] temp1 = lFunction(l0, (i / N_BYTES) + 1);
            offset = xorBlocks(offset, temp1);

            plaintextBlock = xorBlocks(offset, cipher.decrypt(xorBlocks(ciphertextBlock, offset)));

            try {
                plaintextStream.write(plaintextBlock);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            checksum = xorBlocks(checksum, plaintextBlock);
        }

        int dif = ciphertext.length - i;
        if (dif != 0) {
            offset = xorBlocks(offset, lInit);
            byte[] pad = cipher.encrypt(offset);

            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + dif);

            byte[] plaintextFull = xorBlocksAndCut(pad, ciphertextBlock);
            try {
                plaintextStream.write(plaintextFull);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            plaintextFull = Arrays.copyOf(plaintextFull, 16);
            plaintextFull[dif] = (byte) 0x80;

            checksum = xorBlocks(checksum, plaintextFull);
        }
        byte[] tag = xorBlocks(cipher.encrypt(xorBlocks(xorBlocks(checksum, offset), lDollar)), hash(associatedData));

        return new OCBResult(plaintextStream.toByteArray(), tag);
    }

    private byte[] getOffset(byte[] stretch, int bottom) {
        shiftLeft(stretch, bottom);
        return Arrays.copyOf(stretch, 16);

    }

    public byte[] lFunction(byte[] l0, int n) {
        int j = ntz(n);
        for (int i = 0; i < j; i++) {
            l0 = toDouble(l0);
        }
        return l0;
    }

    static byte[] xorBlocks(byte[] biggerBlock, byte[] smallerBlock) {
        byte[] temp = new byte[biggerBlock.length];
        System.arraycopy(biggerBlock, 0, temp, 0, biggerBlock.length);

        for (int i = 0; i < smallerBlock.length; i++) {
            temp[i] = (byte) (biggerBlock[i] ^ smallerBlock[i]);
        }
        return temp;
    }

    static byte[] xorBlocksAndCut(byte[] biggerBlock, byte[] smallerBlock) {
        byte[] temp = new byte[smallerBlock.length];
        System.arraycopy(smallerBlock, 0, temp, 0, smallerBlock.length);

        for (int i = 0; i < smallerBlock.length; i++) {
            temp[i] = (byte) (biggerBlock[i] ^ smallerBlock[i]);
        }
        return temp;
    }

    public byte[] toDouble(byte[] state) {
        byte[] temp = Arrays.copyOf(state, state.length);
        int firstBit = ((temp[0] >> 7) & 1);
        shiftLeft(temp, 1);
        byte[] add = new byte[N_BYTES];

        if (firstBit == 1) {
            add[add.length - 1] = (byte) 0b10000111;
        }
        temp = xorBlocks(temp, add);
        return temp;
    }

    public int ntz(int n) {
        int ctr = 0;
        while ((n & 1) == 0) {
            n = n >> 1;
            ctr++;
        }
        return ctr;
    }

    /**
     * Left shift of whole byte array by shiftBitCount bits.
     * This method will alter the input byte array.
     */
    static void shiftLeft(byte[] byteArray, int shiftBitCount) {
        final int shiftMod = shiftBitCount % 8;
        final byte carryMask = (byte) ((1 << shiftMod) - 1);
        final int offsetBytes = (shiftBitCount / 8);

        int sourceIndex;
        for (int i = 0; i < byteArray.length; i++) {
            sourceIndex = i + offsetBytes;
            if (sourceIndex >= byteArray.length) {
                byteArray[i] = 0;
            } else {
                byte src = byteArray[sourceIndex];
                byte dst = (byte) (src << shiftMod);
                if (sourceIndex + 1 < byteArray.length) {
                    dst |= byteArray[sourceIndex + 1] >>> (8 - shiftMod) & (carryMask & 0xff);
                }
                byteArray[i] = dst;
            }
        }
    }
}