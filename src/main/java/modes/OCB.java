package modes;

import ciphers.Cipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class OCB {
    //    Block cipher size (in bytes)
    private static final int n = 16;
    //    Tag size in bytes
    private final int t;
    //    block cipher class implementing Cipher interface
    private final Cipher cipher;

    public OCB(int t, Cipher cipher) {
        this.t = t;
        this.cipher = cipher;
    }

    public byte[] hash(byte[] associatedData) {
        byte[] sum = new byte[n];
        byte[] offset = new byte[n];

        byte[] lInit = cipher.encrypt(new byte[n]);
        byte[] l0 = toDouble(toDouble(lInit));
        byte[] l = Arrays.copyOf(l0, n);

        byte[] associatedDataBlock;
        int i;
        for (i = 0; i + n <= associatedData.length; i += n) {
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
        byte[] lInit = cipher.encrypt(new byte[n]);
        byte[] lDollar = toDouble(lInit);
        byte[] l0 = toDouble(lDollar);
        byte[] l = Arrays.copyOf(l0, n);


        System.out.println("L_*: " + bytesToHex(lInit));
        System.out.println("L_$: " + bytesToHex(lDollar));
        System.out.println("L0: " + bytesToHex(l0));

        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        int bottom = nonce[nonce.length - 1] & 0b00111111;
        System.out.println("Bottom: " + bottom);

        byte[] temp = Arrays.copyOf(nonce, n);
        temp[temp.length - 1] = (byte) (temp[temp.length - 1] & 0b11000000);
        byte[] kTop = cipher.encrypt(temp);
        System.out.println("kTop: " + bytesToHex(kTop));

        ByteArrayOutputStream stretchStream = new ByteArrayOutputStream();
        try {
            stretchStream.write(kTop);
            stretchStream.write(xorBlocks(Arrays.copyOfRange(kTop, 0, 8), Arrays.copyOfRange(kTop, 1, 9)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] stretch = stretchStream.toByteArray();
        System.out.println("Stretch: " + bytesToHex(stretch));

        byte[] offset = getOffset(stretch, bottom);
        System.out.println("Offset: " + bytesToHex(offset));
        byte[] checksum = new byte[16];


        byte[] plaintextBlock;
        int i;
        for (i = 0; i + n < plaintext.length; i += n) {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + n);

            byte[] temp1 = lFunction(l0, (i / n) + 1);
            offset = xorBlocks(offset, temp1);
            System.out.println("Offset: " + bytesToHex(offset));

            try {
                ciphertextStream.write(xorBlocks(offset, cipher.encrypt(xorBlocks(plaintextBlock, offset))));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            checksum = xorBlocks(checksum, plaintextBlock);
            System.out.println("Checksum: " + bytesToHex(checksum));
        }

        int dif = plaintext.length - i;
        if (dif != 0) {
            offset = xorBlocks(offset, lInit);
            System.out.println("Offset: " + bytesToHex(offset));
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
            System.out.println("Checksum: " + bytesToHex(checksum));
        }

        byte[] tempo = xorBlocks(xorBlocks(checksum, offset), lDollar);
        byte[] tag = xorBlocks(cipher.encrypt(tempo), hash(associatedData));
        System.out.println("TAG: " + bytesToHex(tag));

        return new OCBResult(ciphertextStream.toByteArray(), Arrays.copyOf(tag, t));

    }

    public byte[] decrypt(byte[] nonce, byte[] associatedData, byte[] ciphertext){
        OCBResult result = coreDecrypt(nonce, associatedData, ciphertext);

        return result.getResult();
    }
    public OCBResult coreDecrypt(byte[] nonce, byte[] associatedData, byte[] ciphertext) {
        byte[] lInit = cipher.encrypt(new byte[n]);
        byte[] lDollar = toDouble(lInit);
        byte[] l0 = toDouble(lDollar);


        System.out.println("L_*: " + bytesToHex(lInit));
        System.out.println("L_$: " + bytesToHex(lDollar));
        System.out.println("L0: " + bytesToHex(l0));

        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();

        int bottom = nonce[nonce.length - 1] & 0b00111111;
        System.out.println("Bottom: " + bottom);

        byte[] temp = Arrays.copyOf(nonce, n);
        temp[temp.length - 1] = (byte) (temp[temp.length - 1] & 0b11000000);
        byte[] kTop = cipher.encrypt(temp);
        System.out.println("kTop: " + bytesToHex(kTop));

        ByteArrayOutputStream stretchStream = new ByteArrayOutputStream();
        try {
            stretchStream.write(kTop);
            stretchStream.write(xorBlocks(Arrays.copyOfRange(kTop, 0, 8), Arrays.copyOfRange(kTop, 1, 9)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] stretch = stretchStream.toByteArray();
        System.out.println("Stretch: " + bytesToHex(stretch));

        byte[] offset = getOffset(stretch, bottom);
        System.out.println("Offset: " + bytesToHex(offset));
        byte[] checksum = new byte[16];


        byte[] ciphertextBlock;
        byte[] plaintextBlock;
        int i;
        for (i = 0; i + n < ciphertext.length; i += n) {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + n);

            byte[] temp1 = lFunction(l0, (i / n) + 1);
            offset = xorBlocks(offset, temp1);
            System.out.println("Offset: " + bytesToHex(offset));

            plaintextBlock = xorBlocks(offset, cipher.decrypt(xorBlocks(ciphertextBlock, offset)));

            try {
                plaintextStream.write(plaintextBlock);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            checksum = xorBlocks(checksum, plaintextBlock);
            System.out.println("Checksum: " + bytesToHex(checksum));
        }

        int dif = ciphertext.length - i;
        if (dif != 0) {
            offset = xorBlocks(offset, lInit);
            System.out.println("Offset: " + bytesToHex(offset));
            byte[] pad = cipher.encrypt(offset);

            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + dif);

            try {
                plaintextStream.write(xorBlocksAndCut(pad, ciphertextBlock));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            byte[] plaintextFull = Arrays.copyOf(ciphertextBlock, 16);
            plaintextFull[dif] = (byte) 0x80;

            checksum = xorBlocks(checksum, plaintextFull);
            System.out.println("Checksum: " + bytesToHex(checksum));
        }

        byte[] tag = xorBlocks(xorBlocks(cipher.encrypt(xorBlocks(checksum, offset)), l0), hash(associatedData));
        System.out.println("TAG: " + bytesToHex(tag));


        return new OCBResult(plaintextStream.toByteArray(), tag);

    }

    public static String bytesToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
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
        byte[] add = new byte[n];

        if (firstBit == 1) {
            add[add.length - 1] = (byte) 0b10000111;
        }
        System.out.println("Add: " + bytesToHex(add));
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
    static byte[] shiftLeft(byte[] byteArray, int shiftBitCount) {
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
                    dst |= byteArray[sourceIndex + 1] >>> (8 - shiftMod) & carryMask;
                }
                byteArray[i] = dst;
            }
        }
        return byteArray;
    }
}