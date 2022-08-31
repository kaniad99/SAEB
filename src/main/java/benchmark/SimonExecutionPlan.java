package benchmark;

import ciphers.Simon;
import org.apache.commons.lang3.RandomUtils;
import org.openjdk.jmh.annotations.*;

import static utils.Utils.hexStringToByteArray;

@State(Scope.Benchmark)
public class SimonExecutionPlan {
    @Param({"0f0e0d0c0b0a09080706050403020100", "17161514131211100f0e0d0c0b0a09080706050403020100", "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"})
    public String key;

    public Simon simon;
    public byte[] state;

    @Setup(Level.Invocation)
    public void setUp() {
        state = RandomUtils.nextBytes(16);
        simon = new Simon(128, hexStringToByteArray(key));
    }
}
