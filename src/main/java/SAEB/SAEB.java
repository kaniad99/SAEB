package SAEB;

import tiny.AES;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    public AES aes;

    public SAEB() {
        aes = new AES(hexStringToByteArray(KEY));
    }

    public byte[] hash(byte[] associatedData, byte[] nonce) {
        byte[] state = new byte[N_BYTES];

        for (int i = 0; i + R1 <= associatedData.length; i = i + R1) {
            state = hashRound(state,
                    Arrays.copyOfRange(associatedData, i, i + R1));
        }
        return state;
    }

    public byte[] hashRound(byte[] state, byte[] associatedData) {
        return aes.encrypt(xorFullBlocks(state, associatedData));
    }

    public byte[] divideAssociatedData(byte[] data, int size) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for (int i = 0; i < data.length; i = i + size) {
            try {
                out.write(Arrays.copyOfRange(data, i, i + size));
            } catch (IOException e) {
                throw new IllegalArgumentException(e);
            }
        }

        return out.toByteArray();
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
