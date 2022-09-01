package ciphers;

import java.util.Arrays;

public class Simon implements Cipher {
    public static final int SIMON_32 = 32;
    public static final int SIMON_48 = 48;
    public static final int SIMON_64 = 64;
    public static final int SIMON_96 = 96;
    public static final int SIMON_128 = 128;

    private static byte[] keyBytes;

    private final SimonCipher cipher;

    public static byte[] encrypt1(final int blockSizeBits,
                                  final byte[] key,
                                  final byte[] io) {
        return crypt(true, blockSizeBits, key, io);
    }

    public static byte[] decrypt1(final int blockSizeBits,
                                  final byte[] key,
                                  final byte[] io) {
        return crypt(false, blockSizeBits, key, io);
    }

    public byte[] encrypt(byte[] text) {
        return encrypt1(text.length * 8, keyBytes, text);
    }

    public byte[] decrypt(byte[] text) {
        return decrypt1(text.length * 8, keyBytes, text);
    }

    private static byte[] crypt(final boolean forEncryption,
                                final int blockSizeBits,
                                final byte[] key,
                                final byte[] io) {
        Simon se = new Simon(blockSizeBits, key);
        se.init(forEncryption, key);
        se.processBlock(io, 0, io, 0);
        return io;
    }

    public Simon(final int blockSizeBits, byte[] key) {
        keyBytes = Arrays.copyOf(key, key.length);
        switch (blockSizeBits) {
            case SIMON_32:
                cipher = new Simon32Cipher();
                break;
            case SIMON_48:
                cipher = new Simon48Cipher();
                break;
            case SIMON_64:
                cipher = new Simon64Cipher();
                break;
            case SIMON_96:
                cipher = new Simon96Cipher();
                break;
            case SIMON_128:
                cipher = new Simon128Cipher();
                break;
            default:
                throw new IllegalArgumentException("Unknown Simon block size: " + blockSizeBits);
        }
    }

    public void init(final boolean forEncryption, final byte[] keyBytes)
            throws IllegalArgumentException {
        cipher.init(forEncryption, keyBytes);
    }

    public void processBlock(final byte[] in, final int inOff, final byte[] out, final int outOff)
            throws IllegalArgumentException,
            IllegalStateException {
        cipher.processBlock(in, inOff, out, outOff);
    }

    private abstract static class SimonCipher {
        private static final byte[][] Z = new byte[][]{
                {0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00,},
                {0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00,},
                {0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01,},
                {0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,},
                {0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01,}
        };

        protected final int blockSize;
        protected final int wordSize;
        protected final int wordSizeBits;
        private final int sequenceBase;
        protected int rounds;
        protected byte[] constants;
        private boolean initialised = false;
        private boolean forEncryption;

        protected SimonCipher(int wordSize, int sequenceBase) {
            this.wordSize = wordSize;
            this.sequenceBase = sequenceBase;
            this.blockSize = wordSize * 2;
            this.wordSizeBits = wordSize * 8;
        }

        public final String getAlgorithmName() {
            return "Simon" + (blockSize * 8);
        }

        public final void init(boolean forEncryption, byte[] keyBytes) {
            this.forEncryption = forEncryption;

            rounds = checkKeySize(keyBytes.length);

            final int keyWords = keyBytes.length / wordSize;
            this.constants = Z[sequenceBase + keyWords - 2];

            setKey(keyBytes);

            initialised = true;
        }

        protected abstract int checkKeySize(int keySizeBytes);

        protected abstract void setKey(byte[] keyBytes);

        public final void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
            if (!initialised) {
                throw new IllegalStateException(getAlgorithmName() + " engine not initialised");
            }

            if ((inOff + blockSize) > in.length) {
                throw new IllegalArgumentException("input buffer too short");
            }

            if ((outOff + blockSize) > out.length) {
                throw new IllegalArgumentException("output buffer too short");
            }

            unpackBlock(in, inOff);
            if (forEncryption) {
                encryptBlock();
            } else {
                decryptBlock();
            }
            packBlock(out, outOff);
        }

        protected abstract void unpackBlock(byte[] in, int inOff);

        protected abstract void packBlock(byte[] out, int outOff);
        protected abstract void encryptBlock();
        protected abstract void decryptBlock();

    }

    private abstract static class SimonIntCipher
            extends SimonCipher {
        private final int c;
        private int[] k;
        private int x;
        private int y;
        protected SimonIntCipher(int wordSize, int sequenceBase) {
            super(wordSize, sequenceBase);
            c = mask(0xfffffffc);
        }

        @Override
        protected void setKey(byte[] keyBytes) {
            k = new int[rounds];

            int keyWords = keyBytes.length / wordSize;

            for (int i = 0; i < keyWords; i++) {
                k[i] = bytesToWord(keyBytes, (keyWords - i - 1) * wordSize);
            }

            for (int i = keyWords; i < rounds; i++) {
                int tmp = mask(rotr(k[i - 1], 3));
                if (keyWords == 4) {
                    tmp ^= k[i - 3];
                }
                tmp = mask(tmp ^ rotr(tmp, 1));
                k[i] = tmp ^ k[i - keyWords] ^ constants[(i - keyWords) % 62] ^ c;
            }
        }

        @Override
        protected void encryptBlock() {
            int x = this.x;
            int y = this.y;

            for (int r = 0; r < rounds; r++) {
                int tmp = x;
                x = mask(y ^ (rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2) ^ k[r]);
                y = tmp;
            }

            this.x = x;
            this.y = y;
        }

        @Override
        protected void decryptBlock() {
            int x = this.x;
            int y = this.y;

            for (int r = rounds - 1; r >= 0; r--) {
                int tmp = y;
                y = mask(x ^ (rotl(y, 1) & rotl(y, 8)) ^ rotl(y, 2) ^ k[r]);
                x = tmp;
            }
            this.x = x;
            this.y = y;
        }

        protected abstract int mask(int val);
        private int rotl(int i, int distance) {
            return ((i << distance) | (i >>> (wordSizeBits - distance)));
        }
        private int rotr(int i, int distance) {
            return ((i >>> distance) | (i << (wordSizeBits - distance)));
        }

        @Override
        protected void unpackBlock(byte[] in, int inOff) {
            y = bytesToWord(in, inOff + wordSize);
            x = bytesToWord(in, inOff);
        }

        @Override
        protected void packBlock(byte[] out, int outOff) {
            wordToBytes(y, out, outOff + wordSize);
            wordToBytes(x, out, outOff);
        }

        private int bytesToWord(final byte[] bytes, final int off) {
            if ((off + wordSize) > bytes.length) {
                throw new IllegalArgumentException();
            }

            int word;
            int index = off;

            word = (bytes[index++] & 0xff);
            word = (word << 8) | (bytes[index++] & 0xff);
            if (wordSize > 2) {
                word = (word << 8) | (bytes[index++] & 0xff);
                if (wordSize > 3) {
                    word = (word << 8) | (bytes[index] & 0xff);
                }
            }

            return word;
        }

        private void wordToBytes(final int word, final byte[] bytes, final int off) {
            if ((off + wordSize) > bytes.length) {
                throw new IllegalArgumentException();
            }

            int index = off + wordSize - 1;

            bytes[index--] = (byte) word;
            bytes[index--] = (byte) (word >> 8);
            if (wordSize > 2) {
                bytes[index--] = (byte) (word >> 16);
                if (wordSize > 3) {
                    bytes[index--] = (byte) (word >> 24);
                }
            }
        }
    }

    private abstract static class SimonLongCipher
            extends SimonCipher {
        private final long c;
        private long[] k;
        private long x;
        private long y;

        protected SimonLongCipher(int wordSize, int sequenceBase) {
            super(wordSize, sequenceBase);
            c = mask(0xfffffffffffffffcL);
        }

        @Override
        protected void setKey(byte[] keyBytes) {
            k = new long[rounds];

            int keyWords = keyBytes.length / wordSize;

            for (int i = 0; i < keyWords; i++) {
                k[i] = bytesToWord(keyBytes, (keyWords - i - 1) * wordSize);
            }

            for (int i = keyWords; i < rounds; i++) {
                long tmp = mask(rotr(k[i - 1], 3));
                if (keyWords == 4) {
                    tmp ^= k[i - 3];
                }
                tmp = mask(tmp ^ rotr(tmp, 1));
                k[i] = tmp ^ k[i - keyWords] ^ constants[(i - keyWords) % 62] ^ c;
            }
        }

        @Override
        protected void encryptBlock() {
            long x = this.x;
            long y = this.y;

            for (int r = 0; r < rounds; r++) {
                long tmp = x;
                x = mask(y ^ (rotl(x, 1) & rotl(x, 8)) ^ rotl(x, 2) ^ k[r]);
                y = tmp;
            }
            this.x = x;
            this.y = y;
        }

        @Override
        protected void decryptBlock() {
            long x = this.x;
            long y = this.y;

            for (int r = rounds - 1; r >= 0; r--) {
                long tmp = y;
                y = mask(x ^ (rotl(y, 1) & rotl(y, 8)) ^ rotl(y, 2) ^ k[r]);
                x = tmp;
            }
            this.x = x;
            this.y = y;
        }

        protected abstract long mask(long val);

        private long rotl(long i, int distance) {
            return (i << distance) | (i >>> (wordSizeBits - distance));
        }
        private long rotr(long i, int distance) {
            return (i >>> distance) | (i << (wordSizeBits - distance));
        }

        @Override
        protected void unpackBlock(byte[] in, int inOff) {
            y = bytesToWord(in, inOff + wordSize);
            x = bytesToWord(in, inOff);
        }

        @Override
        protected void packBlock(byte[] out, int outOff) {
            wordToBytes(y, out, outOff + wordSize);
            wordToBytes(x, out, outOff);
        }

        private long bytesToWord(final byte[] bytes, final int off) {
            if ((off + wordSize) > bytes.length) {
                throw new IllegalArgumentException();
            }

            long word;
            int index = off;

            word = (bytes[index++] & 0xffL);
            word = (word << 8) | (bytes[index++] & 0xffL);
            word = (word << 8) | (bytes[index++] & 0xffL);
            word = (word << 8) | (bytes[index++] & 0xffL);
            word = (word << 8) | (bytes[index++] & 0xffL);
            word = (word << 8) | (bytes[index++] & 0xffL);
            if (wordSize == 8) {
                word = (word << 8) | (bytes[index++] & 0xffL);
                word = (word << 8) | (bytes[index++] & 0xffL);
            }

            return word;
        }

        private void wordToBytes(final long word, final byte[] bytes, final int off) {
            if ((off + wordSize) > bytes.length) {
                throw new IllegalArgumentException();
            }
            int index = off + wordSize - 1;

            bytes[index--] = (byte) word;
            bytes[index--] = (byte) (word >> 8);
            bytes[index--] = (byte) (word >> 16);
            bytes[index--] = (byte) (word >> 24);
            bytes[index--] = (byte) (word >> 32);
            bytes[index--] = (byte) (word >> 40);
            if (wordSize == 8) {
                bytes[index--] = (byte) (word >> 48);
                bytes[index--] = (byte) (word >> 56);
            }
        }

    }

    private static final class Simon32Cipher
            extends SimonIntCipher {

        private Simon32Cipher() {
            super(2, -2);
        }

        @Override
        protected int mask(int val) {
            return (val & 0xffff);
        }

        @Override
        protected int checkKeySize(int keySizeBytes) {
            if (keySizeBytes != 8) {
                throw new IllegalArgumentException("Simon32 requires a key of 64 bits.");
            }
            return 32;
        }

    }

    private static final class Simon48Cipher
            extends SimonIntCipher {

        private Simon48Cipher() {
            super(3, -1);
        }

        @Override
        protected int mask(int val) {
            return (val & 0xffffff);
        }

        @Override
        protected int checkKeySize(int keySizeBytes) {
            if (keySizeBytes != 9 && keySizeBytes != 12) {
                throw new IllegalArgumentException("Simon48 requires a key of 72 or 96 bits.");
            }
            return 36;
        }
    }

    private static final class Simon64Cipher
            extends SimonIntCipher {

        private Simon64Cipher() {
            super(4, 1);
        }

        @Override
        protected int mask(int val) {
            return val;
        }

        @Override
        protected int checkKeySize(int keySizeBytes) {
            if (keySizeBytes != 12 && keySizeBytes != 16) {
                throw new IllegalArgumentException("Simon64 requires a key of 96 or 128 bits.");
            }
            return (keySizeBytes == 12) ? 42 : 44;
        }

    }

    private static final class Simon96Cipher
            extends SimonLongCipher {

        public Simon96Cipher() {
            super(6, 2);
        }

        @Override
        protected long mask(long val) {
            return (val & 0x0000ffffffffffffl);
        }

        @Override
        protected int checkKeySize(int keySizeBytes) {
            if (keySizeBytes != 12 && keySizeBytes != 18) {
                throw new IllegalArgumentException("Simon96 requires a key of 96 or 144 bits.");
            }
            return (keySizeBytes == 12) ? 52 : 54;
        }
    }

    private static final class Simon128Cipher
            extends SimonLongCipher {

        public Simon128Cipher() {
            super(8, 2);
        }

        @Override
        protected long mask(long val) {
            return val;
        }

        @Override
        protected int checkKeySize(int keySizeBytes) {
            if (keySizeBytes != 16 && keySizeBytes != 24 && keySizeBytes != 32) {
                throw new IllegalArgumentException("Simon128 requires a key of 128, 192 or 256 bits.");
            }
            return (keySizeBytes == 16) ? 68 : ((keySizeBytes == 24) ? 69 : 72);
        }

    }

}
