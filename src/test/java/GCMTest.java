import ciphers.AES;
import modes.GCM;
import modes.GCMResult;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class GCMTest {

    @Test
    public void test(){

        byte[] test = {1,2,3,4,5};
        byte[] y0 = Arrays.copyOf(test, 16);
        for (int i = 0; i < 10; i++) {
            System.out.println(Arrays.toString(y0));
            GCM.incr(y0);
        }
    }

    @Test
    public void overrideTest(){
        System.out.println("Overrride test");

        byte[] test = {1,2,3,4,5};
        byte[] y0 = Arrays.copyOf(test, 16);
        y0[y0.length - 1] = (byte) 0xfe;
        y0[y0.length - 2] = (byte) 0xff;
        for (int i = 0; i < 10; i++) {
            System.out.println(Arrays.toString(y0));
            GCM.incr(y0);
        }
    }


    @Test(expected = ArithmeticException.class)
    public void override2Test(){
        System.out.println("Overrride test");

        byte[] test = {1,2,3,4,5};
        byte[] y0 = Arrays.copyOf(test, 16);
        y0[y0.length - 1] = (byte) 0xfe;
        y0[y0.length - 2] = (byte) 0xff;
        y0[y0.length - 3] = (byte) 0xff;
        y0[y0.length - 4] = (byte) 0xff;
        for (int i = 0; i < 10; i++) {
            System.out.println(Arrays.toString(y0));
            GCM.incr(y0);
        }
    }

    @Test
    public void testCase1() {
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 16;

        byte[] plaintext = TestUtils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] key = TestUtils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] iv = TestUtils.hexStringToByteArray("000000000000000000000000");


        AES aes = new AES(key);

        GCM gcm = new GCM(n,r,r1,t, aes);

        GCMResult result = gcm.encrypt(iv,plaintext, new byte[16]);

        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getResult()));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void testCase2() {
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 16;

        byte[] plaintext = TestUtils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] key = TestUtils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] iv = TestUtils.hexStringToByteArray("000000000000000000000000");


        AES aes = new AES(key);

        GCM gcm = new GCM(n,r,r1,t, aes);

        GCMResult result = gcm.encrypt(iv,plaintext, new byte[16]);


        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a",
                TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("00000000000000000000000000000001"))));
        Assert.assertEquals("0388dace60b6a392f328c2b971b2fe78",
                TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("00000000000000000000000000000002"))));

        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getResult()));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void testCase4() {
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 16;

        byte[] plaintext = TestUtils.hexStringToByteArray(   "d9313225f88406e5a55909c5aff5269a" +
                                                                "86a7a9531534f7da2e4c303d8a318a72" +
                                                                "1c3c0c95956809532fcf0e2449a6b525" +
                                                                "b16aedf5aa0de657ba637b39");
        byte[] associatedData = TestUtils.hexStringToByteArray("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] key = TestUtils.hexStringToByteArray("feffe9928665731c6d6a8f9467308308");
        byte[] iv = TestUtils.hexStringToByteArray("cafebabefacedbaddecaf888");


        AES aes = new AES(key);

        GCM gcm = new GCM(n,r,r1,t, aes);

        GCMResult result = gcm.encrypt(iv,plaintext, associatedData);

        Assert.assertEquals("3247184b3c4f69a44dbcd22887bbb418",
                TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("cafebabefacedbaddecaf88800000001"))));

        Assert.assertEquals("3247184b3c4f69a44dbcd22887bbb418", TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("cafebabefacedbaddecaf88800000001"))));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getResult()));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getTag()));
    }

    @Test
    public void testCase8() {
        int n = 16;
        int r = 6;
        int r1 = 10;
        int t = 16;

        byte[] plaintext = TestUtils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] associatedData = TestUtils.hexStringToByteArray("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] key = TestUtils.hexStringToByteArray("00000000000000000000000000000000" +
                "0000000000000000");
        byte[] iv = TestUtils.hexStringToByteArray("000000000000000000000000");


        AES aes = new AES(key);

        GCM gcm = new GCM(n,r,r1,t, aes);

        GCMResult result = gcm.encrypt(iv,plaintext, associatedData);

        Assert.assertEquals("cd33b28ac773f74ba00ed1f312572435",
                TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("00000000000000000000000000000001"))));

        Assert.assertEquals("3247184b3c4f69a44dbcd22887bbb418", TestUtils.bytesToHex(aes.encrypt(TestUtils.hexStringToByteArray("cafebabefacedbaddecaf88800000001"))));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getResult()));
        Assert.assertEquals("58e2fccefa7e3061367f1d57a4e7455a", TestUtils.bytesToHex(result.getTag()));
    }
}
