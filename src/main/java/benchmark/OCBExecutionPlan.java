package benchmark;

import ciphers.AES;
import ciphers.Cipher;
import ciphers.Simon;
import ciphers.Speck;
import modes.OCB;
import org.apache.commons.lang3.RandomUtils;
import org.openjdk.jmh.annotations.*;

import static utils.Utils.hexStringToByteArray;

@State(Scope.Benchmark)
public class OCBExecutionPlan {
    @Param({"1","1024"})
    int plaintextLength;

    @Param({"1","1024"})
    int associatedDataLength;

    @Param({"aes", "speck", "simon"})
    String cipherName;

    @Param({"000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"})
    public String key;

    byte[] plaintext;
    byte[] associatedData;
    byte[] nonce;
    OCB ocb;
    int t = 16;

    @Setup(Level.Invocation)
    public void setUp() {
        plaintext = RandomUtils.nextBytes(plaintextLength);
        associatedData = RandomUtils.nextBytes(associatedDataLength);
        nonce = RandomUtils.nextBytes(4);

        Cipher cipher;
        if(cipherName.equals("aes")) {
            cipher = new AES(hexStringToByteArray(key));
        } else if(cipherName.equals("speck")) {
            cipher = new Speck(128, hexStringToByteArray(key));
        } else {
            cipher = new Simon(128, hexStringToByteArray(key));
        }

        ocb = new OCB(t, cipher);
    }
}
