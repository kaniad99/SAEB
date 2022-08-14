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
        } else if (dif <= 0 || dif >= R1) {
            throw new IllegalArgumentException("Bad last block dif number: " + dif);
        } else {
            byte[] lastBlock = createLastBlock(associatedData, i);

            state[state.length - 1] ^= 0x02;
            state = hashRound(state, lastBlock);
        }

        return hashLastRound(state, nonce);
    }

    private byte[] createLastBlock(byte[] associatedData, int i) {
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


    public byte[] xorFullBlocks(byte[] state, byte[] associated) {
        if (state.length < associated.length) {
            throw new IllegalStateException("Kurwa");
        }

        for (int i = 0; i < associated.length; i++) {
            state[i] = (byte) (state[i] ^ associated[i]);
        }
        return state;
    }
}
