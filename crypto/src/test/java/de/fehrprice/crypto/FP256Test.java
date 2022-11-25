package de.fehrprice.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import de.fehrprice.crypto.FP256.fp256;

class FP256Test {

    FP256 fp;
    AES aes; 
    
    @BeforeAll
    static void setUpBeforeClass() throws Exception {
    }

    @AfterAll
    static void tearDownAfterClass() throws Exception {
    }

    @BeforeEach
    void setUp() throws Exception {
        fp = new FP256();
        aes = new AES();
        aes.setSeed(RandomSeed.createSeed());
    }

    @AfterEach
    void tearDown() throws Exception {
    }

    @Test
    void testConversions() {
        // String conversions
        String hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        System.out.println("hex: " + hex);
        fp256 f = fp.fromString(hex);
        System.out.println(fp.dump(f));
        assertEquals(hex, fp.toString(f));
        
        // test with random numbers:
        for (int i = 0; i < 100; i++) {
            String h = Conv.toString(aes.random(32)); 
            f = fp.fromString(h);
            assertEquals(h, fp.toString(f));
        }
        
        // BigInteger conversions
        hex = "a9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        System.out.println("hex: " + hex);
        BigInteger big = new BigInteger(hex, 16);
        System.out.println("BigInteger: " + big.toString(16));
        f = fp.fromBigInteger(big);
        System.out.println(fp.dump(f));

        // test with random numbers:
        for (int i = 0; i < 100; i++) {
            String h = Conv.toString(aes.random(32)); 
            big = new BigInteger(h, 16);
            f = fp.fromString(h);
            fp256 f2 = fp.fromBigInteger(big);
            assertEquals(f, f2);
            BigInteger big2 = fp.toBigInteger(f2);
            assertEquals(big, big2);
        }
        
    }
    
    /**
     * Map BigInteger to allowed 256 bit range
     * @param b
     * @return
     */
    private BigInteger mod(BigInteger b) {
        return b.mod(BigInteger.TWO.pow(256));
    }

    @Test
    void testAdditions() {
        fp256 a = fp.fromBigInteger(new BigInteger("7fffffffffffffff", 16));
        fp256 b = fp.fromBigInteger(new BigInteger("1"));
        fp256 r = fp.zero();
        
        fp.add(r, a, b);
        System.out.println(fp.dump(r));
        assertEquals(new BigInteger("8000000000000000", 16), fp.toBigInteger(r));
        //if (true) return;

        // test with random numbers:
        for (int i = 0; i < 1000; i++) {
            // first make add ition with BigInteger:
            String h = Conv.toString(aes.random(32)); 
            BigInteger big = new BigInteger(h, 16);
            h = Conv.toString(aes.random(32)); 
            BigInteger big2 = new BigInteger(h, 16);
            BigInteger bigr = mod(big.add(big2));
            
            // now add with fp256
            fp256 f = fp.fromBigInteger(big);
            fp256 f2 = fp.fromBigInteger(big2);
            fp.add(r, f, f2);
            if (!bigr.equals(fp.toBigInteger(r))) {
                System.out.println("error on run " + i + 1);
                System.out.println(fp.dump(f));
                System.out.println(fp.dump(f2));
                System.out.println(fp.dump(r));
                System.out.println(fp.dump(fp.fromBigInteger(bigr)));
                System.out.println(bigr.toString(16));
                System.out.println(fp.toBigInteger(r).toString(16));
            }
            assertEquals(bigr, fp.toBigInteger(r));
        }
    }

    @Test
    void testSubtractions() {
        fp256 a = fp.fromBigInteger(new BigInteger("10000000000000000", 16));
        fp256 b = fp.fromBigInteger(new BigInteger("1"));
        fp256 r = fp.zero();
        
        fp.subtract(r, a, b);
        System.out.println(fp.dump(r));
        assertEquals(new BigInteger("ffffffffffffffff", 16), fp.toBigInteger(r));
        //if (true) return;

        // test with random numbers:
        for (int i = 0; i < 1000; i++) {
            // first make add ition with BigInteger:
            String h = Conv.toString(aes.random(32)); 
            BigInteger big = new BigInteger(h, 16);
            h = Conv.toString(aes.random(32)); 
            BigInteger big2 = new BigInteger(h, 16);
            BigInteger bigr = mod(big.subtract(big2));
            
            // now add with fp256
            fp256 f = fp.fromBigInteger(big);
            fp256 f2 = fp.fromBigInteger(big2);
            fp.subtract(r, f, f2);
            if (!bigr.equals(fp.toBigInteger(r))) {
                System.out.println("error on run " + i + 1);
                System.out.println(fp.dump(f));
                System.out.println(fp.dump(f2));
                System.out.println(fp.dump(r));
                System.out.println(fp.dump(fp.fromBigInteger(bigr)));
                System.out.println(bigr.toString(16));
                System.out.println(fp.toBigInteger(r).toString(16));
            }
            assertEquals(bigr, fp.toBigInteger(r));
        }
    }
}
