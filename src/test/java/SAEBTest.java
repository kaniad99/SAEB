import org.junit.Assert;
import org.junit.Test;
import saeb.SAEB;

import java.util.Arrays;

public class SAEBTest {

    @Test
    public void saebTest(){
        byte[] message = "dupabladakilbasa".getBytes();
        byte[] iv = "0000000000100000".getBytes();
        String KEY = "000102030405060708090a0b0c0d0e0f";

        SAEB saeb = new SAEB(KEY.getBytes());

        byte[] ciphertext = saeb.coreEncrypt(iv, message);

        ciphertext = saeb.coreDecrypt(iv, ciphertext);

        Assert.assertArrayEquals(message, ciphertext);
    }
}
