import ciphers.AES;
import ciphers.Simon;
import org.junit.Test;
import saeb.SAEB;
import saeb.SAEBResult;

import static org.junit.Assert.assertArrayEquals;

public class SAEBTest {

    byte[] plaintext = "randomStringPlaintext".getBytes();
    byte[] iv = "0000000000100000".getBytes();
    byte[] associatedData = "RandomAssociatedDataString".getBytes();
    byte[] nonce = "15".getBytes();
    String KEY = "000102030405060708090a0b0c0d0e0f";

    @Test
    public void saebTestWithAes(){
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 5;

        AES aes = new AES(KEY.getBytes());

        SAEB saeb = new SAEB(n, r1, r, t, aes);

        SAEBResult saebEncResult = saeb.encrypt(nonce, associatedData,plaintext);


        byte[] decryptedPlaintext = saeb.decrypt(nonce, associatedData,saebEncResult.getResult(), saebEncResult.getTag());

        assertArrayEquals(plaintext, decryptedPlaintext);
    }

    @Test
    public void saebTestWithSimon(){
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 5;

        Simon simon = new Simon(128, KEY.getBytes());

        SAEB saeb = new SAEB(n, r1, r, t, simon);

        SAEBResult saebEncResult = saeb.encrypt(nonce, associatedData,plaintext);

        byte[] decryptedPlaintext = saeb.decrypt(nonce, associatedData,saebEncResult.getResult(), saebEncResult.getTag());

        assertArrayEquals(plaintext, decryptedPlaintext);
    }
}
