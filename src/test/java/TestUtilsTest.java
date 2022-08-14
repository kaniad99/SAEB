import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.Assert.*;

public class TestUtilsTest {

    @Test
    public void divisionTest() {
        int a = 32;
        int b = 8;


        assertEquals(4, a / b);
        assertEquals(4, (a + 2) / b);
        assertEquals(3, (a - 2) / b);
    }

    @Test
    public void byteXorTest() {
        byte[] bytes = new byte[]{0, 1, 2, 3, 4, 5, 6, -127};

        ByteArrayOutputStream out = new ByteArrayOutputStream(8);

        for (byte aByte : bytes) {
            String s = String.format("%8s", Integer.toBinaryString(aByte & 0xFF)).replace(' ', '0');
            out.write(aByte);
            System.out.println(s);
        }

        System.out.println(out);
        System.out.println("dupa");
        assertEquals(0,0);
    }


    @Test
    public void anotherDummyTest(){
        byte[] nonce = new byte[]{2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
        byte[] associated = new byte[]{3, 1, 2, 3, 4, 5, 6, 5, 8};
        int a = associated.length / 4;

        byte[] state = nonce;
        for (int i = 0; i < a - 1; i++) {
            state[i] = (byte) (nonce[i] ^ associated[i]);
        }

        assertNotEquals(associated.length, a*4 );

        System.out.println(Arrays.toString(state));
    }
}
