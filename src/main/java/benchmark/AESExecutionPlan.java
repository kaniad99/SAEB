package benchmark;

import ciphers.AES;
import org.apache.commons.lang3.RandomUtils;
import org.openjdk.jmh.annotations.*;

import static utils.Utils.hexStringToByteArray;

@State(Scope.Benchmark)
public class AESExecutionPlan {
    @Param({"000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f1011121314151617", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"})
    public String key;

    public AES aes;
    public byte[] state;

    @Setup(Level.Invocation)
    public void setUp() {
        state = RandomUtils.nextBytes(16);
        aes = new AES(hexStringToByteArray(key));
    }
}

