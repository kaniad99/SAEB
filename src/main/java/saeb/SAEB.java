package saeb;

import tiny.AES;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.example.Main.hexStringToByteArray;

public class SAEB {
    public static final String KEY = "000102030405060708090a0b0c0d0e0f";

    //    Block cipher size (in bytes)
    public static final int N_BYTES = 16;
    // Block Cipher size (in bits)
    public static final int N_BITS = 128;

    // Associated data block size in bytes
    public static final int R1 = 8;
    public static final int R2 = 4;
    public static final int R = 6;
    public static final int t = 5;

    private final AES aes;

    public SAEB() {
        aes = new AES(hexStringToByteArray(KEY));
    }

    public byte[] hash(byte[] associatedData, byte[] nonce) {
        byte[] state = new byte[N_BYTES];

        int i;
        for (i = 0; i + R1 < associatedData.length; i = i + R1) {
            state = hashRound(state,
                    Arrays.copyOfRange(associatedData, i, i + R1));
        }

        int dif = associatedData.length - i;

        if (dif == R1) {
            state[state.length - 1] ^= 0x01;
            state = hashRound(state,
                    Arrays.copyOfRange(associatedData, i, i + R1));
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
        for (int j = stream.size(); j < R1; j++) {
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
        return aes.encrypt(xorFullBlocks(state, associatedData));
    }


    public byte[] xorFullBlocks(byte[] stated, byte[] smallerBlock) {
        byte[] temp = new byte[stated.length];

        System.arraycopy(stated, 0, temp, 0, stated.length);

        for (int i = 0; i < smallerBlock.length; i++) {
            temp[i] = (byte) (stated[i] ^ smallerBlock[i]);
        }
        return temp;
    }

    public byte[] coreEncrypt(byte[] iv, byte[] plaintext) {
        byte[] state = aes.encrypt(iv);
        ByteArrayOutputStream ciphertextStream = new ByteArrayOutputStream();

        byte[] messageBlock;

        int i;
        for (i = 0; i + R < plaintext.length; i = i + R) {
            messageBlock = Arrays.copyOfRange(plaintext, i, i + R);

            state = xorFullBlocks(state, messageBlock);

            for (int j = 0; j < messageBlock.length; j++) {
                ciphertextStream.write(state[j]);
            }
            state = aes.encrypt(state);
        }

        byte[] lastPlaintextBlock = Arrays.copyOfRange(plaintext, i, i + state.length);

        int dif = plaintext.length - i;
        if (dif == R) {
            state[state.length - 1] ^= 0x01;

            state = xorFullBlocks(state, lastPlaintextBlock);

            for (int j = 0; j < R; j++) {
                ciphertextStream.write(state[j]);
            }
        } else {
            lastPlaintextBlock[dif] = (byte) 0x80;
            lastPlaintextBlock[lastPlaintextBlock.length - 1] = 0x02;

            state = xorFullBlocks(state, lastPlaintextBlock);

            for (int j = 0; j < dif; j++) {
                ciphertextStream.write(state[j]);
            }
        }

        state = aes.encrypt(state);
        byte[] tag = Arrays.copyOf(state, t);
        System.out.println("Encryption TAG: " + Arrays.toString(tag));

        return ciphertextStream.toByteArray();
    }

    public byte[] coreDecrypt(byte[] iv, byte[] ciphertext) {
        byte[] state = aes.encrypt(iv);

        ByteArrayOutputStream plaintextStream = new ByteArrayOutputStream();

        byte[] ciphertextBlock;
        byte[] plaintextBlock;

        int i;
        for (i = 0; i + R < ciphertext.length; i = i + R) {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + R);
            plaintextBlock = Arrays.copyOfRange(xorFullBlocks(state, ciphertextBlock), 0, R);

            for (int j = 0; j < ciphertextBlock.length; j++) {
                plaintextStream.write(plaintextBlock[j]);
            }

            state = xorFullBlocks(state, plaintextBlock);
            state = aes.encrypt(state);
        }

        byte[] lastCiphertextBlock = Arrays.copyOfRange(ciphertext, i, i + state.length);
        int dif = ciphertext.length - i;
        if (dif == R) {
            plaintextBlock = Arrays.copyOfRange(xorFullBlocks(state, lastCiphertextBlock), 0, R);

            for (byte b : plaintextBlock) {
                plaintextStream.write(b);
            }

            byte[] temp = Arrays.copyOf(plaintextBlock, state.length);
            temp[temp.length - 1] = 0x01;

            state = xorFullBlocks(state, temp);
        } else {
            ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + dif);
            plaintextBlock = Arrays.copyOf(xorFullBlocks(state, ciphertextBlock), dif);

            for (int j = 0; j < dif; j++) {
                plaintextStream.write(plaintextBlock[j]);
            }

            byte[] temp = Arrays.copyOf(plaintextBlock, state.length);
            temp[dif] = (byte) 0x80;
            temp[temp.length-1] = 0x02;

            state = xorFullBlocks(state, temp);
        }

        state = aes.encrypt(state);
        byte[] tag = Arrays.copyOf(state, t);
        System.out.println("Decryption TAG: " + Arrays.toString(tag));

        return plaintextStream.toByteArray();
    }

    public byte[] createLastMessageBlock(byte[] messageData, int i, int r) {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (int j = i; j < messageData.length; j++) {
            stream.write(messageData[j]);
        }
        stream.write(0x80);
        for (int j = stream.size(); j < r; j++) {
            stream.write(0x00);
        }
        return stream.toByteArray();
    }
}
