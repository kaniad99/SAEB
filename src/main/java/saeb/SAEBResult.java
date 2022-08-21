package saeb;

public class SAEBResult {
    private final byte[] result;
    private final byte[] tag;

    public SAEBResult(byte[] result, byte[] tag) {
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
