package benchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;


public class BenchmarkRunner {
    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.Main.main(args);

    }

//    @Benchmark
//    @Fork(value = 1, warmups = 1)
//    @BenchmarkMode({Mode.All})
//    @OutputTimeUnit(TimeUnit.SECONDS)
//    @Warmup(iterations = 1)
//    public void aesBenchmark(AESExecutionPlan plan) {
//        plan.aes.encrypt(plan.state);
//    }
//
//    @Benchmark
//    @Fork(value = 1, warmups = 1)
//    @BenchmarkMode({Mode.All})
//    @OutputTimeUnit(TimeUnit.SECONDS)
//    @Warmup(iterations = 1)
//    public void speckBenchmark(SpeckExecutionPlan plan) {
//        plan.speck.encrypt(plan.state);
//    }
//
//    @Benchmark
//    @Fork(value = 1, warmups = 1)
//    @BenchmarkMode({Mode.All})
//    @OutputTimeUnit(TimeUnit.SECONDS)
//    @Warmup(iterations = 1)
//    public void simonBenchmark(SimonExecutionPlan plan) {
//        plan.simon.encrypt(plan.state);
//    }

    @Benchmark
    @Fork(value = 1, warmups = 1)
    @BenchmarkMode({Mode.All})
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1)
    public void saebBenchmark(SAEBExecutionPlan plan) {
        plan.saeb.encrypt(plan.nonce, plan.associatedData, plan.plaintext);
    }

    @Benchmark
    @Fork(value = 1, warmups = 1)
    @BenchmarkMode({Mode.All})
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Warmup(iterations = 1)
    public void ocbBenchmark(OCBExecutionPlan plan) {
        plan.ocb.coreEncrypt(plan.nonce, plan.associatedData, plan.plaintext);
    }


}
