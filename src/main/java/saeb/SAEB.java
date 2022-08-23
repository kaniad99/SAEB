package saeb;

import ciphers.Cipher;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class SAEB {
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

    public SAEB(int n, int r1, int r, int t, Cipher cipher) {
        this.n = n;
        this.r1 = r1;
        this.r = r;
        this.t = t;
        this.cipher = cipher;
    }

    public byte[] hash(byte[] associatedData, byte[] nonce) {
        byte[] state = new byte[n];

        int i;
        for (i = 0; i + r1 < associatedData.length; i = i + r1) {
            state = hashRound(state, Arrays.copyOfRange(associatedData, i, i + r1));
        }

        if (associatedData.length - i == r1) {
            state[state.length - 1] ^= 0x01;
            state = hashRound(state, Arrays.copyOfRange(associatedData, i, i + r1));
        } else {
            byte[] lastBlock = createLastHashBlock(associatedData, i);

            state[state.length - 1] ^= 0x02;
            state = hashRound(state, lastBlock);
        }

        return hashLastRound(state, nonce);
    }

    private byte[] createLastHashBlock(byte[] associatedData, int i) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (int j = i; j < associatedData.length; j++) {
            stream.write(associatedData[j]);
        }
        stream.write(0x80);
        for (int j = stream.size(); j < r1; j++) {
            stream.write(0x00);
        }
        return stream.toByteArray();
    }

    public byte[] hashLastRound(byte[] state, byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            state[i] = (byte) (state[i] ^ nonce[i]);
        }

        state[state.length - 1] ^= 0x03;
        return state;
    }

    public byte[] hashRound(byte[] state, byte[] associatedData) {
        return cipher.encrypt(xorBlocks(state, associatedData));
    }


    public byte[] xorBlocks(byte[] state, byte[] smallerBlock) {
        byte[] temp = new byte[state.length];
        System.arraycopy(state, 0, temp, 0, state.length);

        for (int i = 0; i < smallerBlock.length; i++) {
            temp[i] = (byte) (state[i] ^ smallerBlock[i]);
        }
        return temp;
    }

    public SAEBResult encrypt(byte[] nonce, byte[] associatedData, byte[] plaintext) {
        byte[] iv = hash(associatedData, nonce);
        return coreEncrypt(iv, plaintext);
    }

    public byte[] decrypt(byte[] nonce, byte[] associatedData, byte[] ciphertext, byte[] sentTag) {
        byte[] iv = hash(associatedData, nonce);
        SAEBResult decResult = coreDecrypt(iv, ciphertext);
        if (Arrays.equals(decResult.getTag(), sentTag)) {
            return decResult.getResult();
        } else {
            return new byte[0];
        }
    }

    public SAEBResult coreEncrypt(byte[] iv, byte[] plaintext) {
        byte[] state = cipher.encrypt(iv);
        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        byte[] plaintextBlock;

        int i;
        for (i = 0; i + r < plaintext.length; i = i + r) {
            plaintextBlock = Arrays.copyOfRange(plaintext, i, i + r);

            state = xorBlocks(state, plaintextBlock);

            for (int j = 0; j < plaintextBlock.length; j++) {
                ciphertextStream.write(state[j]);
            }
            state = cipher.encrypt(state);
        }
        int dif = plaintext.length - i;

        plaintextBlock = Arrays.copyOfRange(plaintext, i, i + state.length);

        if (dif == r) {
            state[state.length - 1] ^= 0x01;

            state = xorBlocks(state, plaintextBlock);

            for (int j = 0; j < r; j++) {
                ciphertextStream.write(state[j]);
            }
        } else {
            plaintextBlock[dif] = (byte) 0x80;
            plaintextBlock[plaintextBlock.length - 1] = 0x02;

            state = xorBlocks(state, plaintextBlock);

            for (int j = 0; j < dif; j++) {
                ciphertextStream.write(state[j]);
            }
        }

        state = cipher.encrypt(state);
        byte[] tag = Arrays.copyOf(state, t);

        return new SAEBResult(ciphertextStream.toByteArray(), tag);
    }

    public SAEBResult coreDecrypt(byte[] iv, byte[] ciphertext) {
        byte[] state = cipher.encrypt(iv);

        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();

        byte[] ciphertextBlock;
        byte[] plaintextBlock;

        int i;
        for (i = 0; i + r < ciphertext.length; i = i + r) {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + r);
            plaintextBlock = Arrays.copyOfRange(xorBlocks(state, ciphertextBlock), 0, r);

            for (int j = 0; j < ciphertextBlock.length; j++) {
                plaintextStream.write(plaintextBlock[j]);
            }

            state = xorBlocks(state, plaintextBlock);
            state = cipher.encrypt(state);
        }

        byte[] lastCiphertextBlock = Arrays.copyOfRange(ciphertext, i, i + state.length);
        int dif = ciphertext.length - i;
        if (dif == r) {
            plaintextBlock = Arrays.copyOfRange(xorBlocks(state, lastCiphertextBlock), 0, r);

            for (byte b : plaintextBlock) {
                plaintextStream.write(b);
            }

            byte[] temp = Arrays.copyOf(plaintextBlock, state.length);
            temp[temp.length - 1] = 0x01;

            state = xorBlocks(state, temp);
        } else {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + dif);
            plaintextBlock = Arrays.copyOf(xorBlocks(state, ciphertextBlock), dif);

            for (int j = 0; j < dif; j++) {
                plaintextStream.write(plaintextBlock[j]);
            }

            byte[] temp = Arrays.copyOf(plaintextBlock, state.length);
            temp[dif] = (byte) 0x80;
            temp[temp.length - 1] = 0x02;

            state = xorBlocks(state, temp);
        }
        state = cipher.encrypt(state);
        byte[] tag = Arrays.copyOf(state, t);

        return new SAEBResult(plaintextStream.toByteArray(), tag);
    }
}
