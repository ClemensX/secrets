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
		//System.out.println("hex: " + hex);
		fp256 f = fp.fromString(hex);
		//System.out.println(fp.dump(f));
		assertEquals(hex, fp.toString(f));

		// test with random numbers:
		for (int i = 0; i < 100; i++) {
			String h = Conv.toString(aes.random(32));
			f = fp.fromString(h);
			assertEquals(h, fp.toString(f));
		}

		// BigInteger conversions
		hex = "a9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
		//System.out.println("hex: " + hex);
		BigInteger big = new BigInteger(hex, 16);
		//System.out.println("BigInteger: " + big.toString(16));
		f = fp.fromBigInteger(big);
		//System.out.println(fp.dump(f));

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
	 * 
	 * @param b
	 * @return
	 */
	private BigInteger mod(BigInteger b) {
		return b.mod(BigInteger.TWO.pow(256));
	}

	@Test
	void testAdditions() {
		// case 1:
		fp256 a = fp.fromBigInteger(new BigInteger("7fffffffffffffff", 16));
		fp256 b = fp.fromBigInteger(new BigInteger("1"));
		fp256 r = fp.zero();

		fp.add(r, a, b);
		//System.out.println(fp.dump(r));
		assertEquals(new BigInteger("8000000000000000", 16), fp.toBigInteger(r));

		// case 2:
//		BigInteger bigm = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
//		BigInteger ad = new BigInteger("d7248fa0bfd7e6183e72f957a1bfc26140c6ab608c9b8fa26a58752e0868ff48", 16);
//		a = fp.fromBigInteger(ad);
//		b = fp.fromBigInteger(bigm);
//		r = fp.zero();
//		fp.add(r, a, b);
//		assertEquals(ad.add(bigm).mod(bigm), fp.toBigInteger(r));

		// test with random numbers:
		for (int i = 0; i < 100000; i++) {
			// first make addition with BigInteger:
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
		//System.out.println(fp.dump(r));
		assertEquals(new BigInteger("ffffffffffffffff", 16), fp.toBigInteger(r));
		// if (true) return;

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

	@Test
	void test64Mul() {
		//System.out.println("umul64:");
		long a = 0x8102030405060708L;
		long a_lo = (int) a;
		long a_hi = a >>> 32; // unsigned right shift
//		System.out.println("lo " + Long.toHexString(a_lo));
//		System.out.println("hi " + Long.toHexString(a_hi));
		assertEquals(0x81020304L, a_hi);
		assertEquals(0x05060708L, a_lo);

		a = 0x2a209b1f1bf45e04L;
		a = 0x1b08f66dfe33d144L; // 453.572.205
		// a = 0xffffffffffffffffL;
		// long b = 0x8102030405060708L;
		long b = 0x9cbab0f69f229cffL;
		b = 0xf4974b7dbf47cf91L; // 4.103.555.965
		// b = 0xffffffffffffffffL;
		fp256 r = fp.zero();
		BigInteger bmul = new BigInteger(Long.toHexString(a), 16).multiply(new BigInteger(Long.toHexString(b), 16));
//		System.out.println(bmul.toString(16));
		// fp.karatsuba64(r, a, b);
		fp.umul64(r, a, b);
//		System.out.println(fp.dump(r));
//		System.out.println(fp.dump(fp.fromBigInteger(bmul)));
		assertEquals(bmul, fp.toBigInteger(r));

		// test with random numbers:
		for (long i = 0; i < 1000; i++) {
			// first make multiplication with BigInteger:
			String h = Conv.toString(aes.random(8));
			BigInteger big = new BigInteger(h, 16);
			h = Conv.toString(aes.random(8));
			BigInteger big2 = new BigInteger(h, 16);
			BigInteger bigr = big.multiply(big2);

			// now mult 64 bit values with fp256
			a = big.longValue();
			b = big2.longValue();
			r = fp.zero();
			// fp.karatsuba64(r, a, b);
			fp.umul64(r, a, b);
			if (!bigr.equals(fp.toBigInteger(r))) {
				System.out.println("error on run " + i + 1);
				System.out.println("a " + Long.toHexString(a));
				System.out.println("b " + Long.toHexString(b));
				System.out.println(fp.dump(r));
				System.out.println(fp.dump(fp.fromBigInteger(bigr)));
				System.out.println(bigr.toString(16));
				System.out.println(fp.toBigInteger(r).toString(16));
			}
			assertEquals(bigr, fp.toBigInteger(r));
		}
	}
	
    /**
     * Test 256 bit multiplication
     */
    @Test
    void testMul() {
        System.out.println("umul:");
//    	BigInteger biga = new BigInteger("0f0e0d0c0b0a0908070605040302010011223344556677889900988776655443", 16);
//    	BigInteger bigb = new BigInteger("f00e0d0c0b0a0908070605040302010011223344556677889900988776655443", 16);
    	//BigInteger biga = new BigInteger("b54444f2feda55f6e6948b2039ff54e63f51f7bde5af9db19b2a6db6685f04db", 16);
    	BigInteger biga = new BigInteger("b54444f2feda55f6e6948b2039ff54e63f51f7bde5af9db19b2a6db6685f04db", 16);
        // e3ef34cfde49 251b97b1eed92004
//    	BigInteger biga = new BigInteger("ffffffffffffffffff", 16);
//    	BigInteger bigb = new BigInteger("010000000000000000", 16);
//    	BigInteger bigb = new BigInteger("e3ef34cfde49251b97b1eed92004", 16);
//      BigInteger bigb = new BigInteger("0100000000000000", 16);
    	BigInteger bigb = new BigInteger("ffffffffffffffffffffffffffffffffff", 16);
//    	BigInteger bigb = new BigInteger("f00e0d0c0b0a090800", 16);
        BigInteger bmul = biga.multiply(bigb).mod(BigInteger.TWO.pow(256));
        fp256 r = fp.zero();
        fp256 a = fp.fromBigInteger(biga);
        fp256 b = fp.fromBigInteger(bigb);
        System.out.println(bmul.toString(16));
        fp.umul(r, a, b);
        System.out.println(fp.dump(r));
        System.out.println(fp.dump(fp.fromBigInteger(bmul)));
        assertEquals(bmul, fp.toBigInteger(r));
		// test with random numbers:
		for (long i = 0; i < 1000; i++) {
			// first make multiplication with BigInteger:
			String h = Conv.toString(aes.random(32));
			BigInteger big = new BigInteger(h, 16);
			h = Conv.toString(aes.random(32));
			BigInteger big2 = new BigInteger(h, 16);
			// limit b for now:
			//big2 = big2.mod(BigInteger.TWO.pow(192));
			BigInteger bigr = big.multiply(big2).mod(BigInteger.TWO.pow(256));

			// now mult big with big2
			a = fp.fromBigInteger(big);
			b = fp.fromBigInteger(big2);
			r = fp.zero();
			fp.umul(r, a, b);
	        //System.out.println(fp.dump(r));
			if (!bigr.equals(fp.toBigInteger(r))) {
				System.out.println("error on run " + (i + 1));
				System.out.println("a " + fp.dump(a));
				System.out.println("b " + fp.dump(b));
				System.out.println(fp.dump(r));
				System.out.println(fp.dump(fp.fromBigInteger(bigr)));
//				System.out.println(bigr.toString(16));
//				System.out.println(fp.toBigInteger(r).toString(16));
			}
			assertEquals(bigr, fp.toBigInteger(r));
		}
    }
    /**
     * Test modular arithmetic assumptions
     */
    @Test
    void testModular() {
    	// can we calc modulo with word length and apply lower modulo afterwards?
    	BigInteger base = new BigInteger("0500000001", 16);
    	int exp = 33; // 4 bytes
    	BigInteger modWord = new BigInteger("0100000000", 16);
    	BigInteger modPrime = new BigInteger("4294967291");
    	System.out.println("modPrime hex: " + modPrime.toString(16));
    	BigInteger wordMod = base.mod(modWord);
    	System.out.println("mod word: " + wordMod.toString(16));
    	BigInteger wordPrimeMod = wordMod.mod(modPrime);
    	System.out.println("mod word + prime: " + wordPrimeMod.toString(16));
    	BigInteger primeMod = base.mod(modPrime); 
    	System.out.println("mod prime: " + primeMod.toString(16));
    }

    /**
     * Test 256 bit mod
     */
    @Test
    void testMod() {
    	BigInteger bigm = new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
        fp256 m = fp.fromBigInteger(bigm);
        aes.setSeed(new byte[32]); // use fixed zero seed for repeatable number generation
		// test with random numbers:
		for (long i = 0; i < 1000; i++) {
			// first make multiplication with BigInteger:
			String h = Conv.toString(aes.random(32));
			BigInteger big = new BigInteger(h, 16);
			BigInteger bigr = big.mod(bigm);

			// now mod with fp256
			fp256 a = fp.fromBigInteger(big);
			fp256 r = fp.zero();
			fp.modh(r, a, m);
	        //System.out.println(fp.dump(r));
			if (!bigr.equals(fp.toBigInteger(r))) {
				System.out.println("error on run " + (i + 1));
				System.out.println("r " + fp.dump(r));
				System.out.println(fp.dump(fp.fromBigInteger(bigr)));
			}
			assertEquals(bigr, fp.toBigInteger(r));
		}
    }
}
