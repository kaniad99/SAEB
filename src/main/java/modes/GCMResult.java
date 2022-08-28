package modes;

public class GCMResult {
    private final byte[] result;
    private final byte[] tag;

    public GCMResult(byte[] result, byte[] tag) {
        this.result = result;
        this.tag = tag;
    }

    public byte[] getResult() {
        return result;
    }

    public byte[] getTag() {
        return tag;
    }
}
