package de.fehrprice.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.RSA;
import de.fehrprice.crypto.SHA;
//import junit.framework.TestCase;

public class CryptoTest {

	// indicate use of big keys that will slow test execution considerably
	// use for final tests, not during development
	private static final boolean USE_LARGE_KEY_TESTS = false;

	private static final int Nb = 4; // always 4 state columns

    @BeforeAll
    public static void setUp() throws Exception {
        System.out.println("CryptoTest");
//        Properties props = System.getProperties();
//        String sec = props.getProperty("securerandom.source");
//        //props.setProperty("gate.home", "http://gate.ac.uk/wiki/code-repository");
//        System.out.println("securerandom.source: " + sec);
//        if (sec.contains("/dev")) {
//            props.setProperty("securerandom.source", "file:/dev/urandom");
//            props = System.getProperties();
//            sec = props.getProperty("securerandom.source");
//            System.out.println("securerandom.source: " + sec);
//        }
    }

    @Test
	public void testCurveConversions() {
		Curve25519 crv = new Curve25519();
		byte[] coded = crv.toByteArrayLittleEndian("0000000000000000000000000000000000000000000000000000000000000001");
		BigInteger v = crv.decodeLittleEndian(coded, 255);
		assertTrue(v.intValue() == 1);

		coded = crv.toByteArrayLittleEndian("0000000000000000000000000000000000000000000000000000000000000101");
		v = crv.decodeLittleEndian(coded, 255);
		assertTrue(v.intValue() == 0x0101);

		coded = crv.toByteArrayLittleEndian("000000000000000000000000000000000000000000000000000000000000ff01");
		v = crv.decodeLittleEndian(coded, 255);
		assertTrue(v.intValue() == 0xff01);

		coded = crv.toByteArrayLittleEndian("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44");
		v = crv.decodeLittleEndian(coded, 255);
		System.out.println("---> " + v.toString(16));
		System.out.println("     " + v.toString());

		coded = crv.toByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
		v = crv.decodeLittleEndian(coded, 255);
		System.out.println("---> " + v.toString(16));
		System.out.println("     " + v.toString());

		coded = crv.toByteArray("a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44");
		v = crv.decodeLittleEndian(coded, 255);
		System.out.println("---> " + v.toString(16));
		System.out.println("     " + v.toString());
		assertTrue(
				v.toString().equals("31029842492115040904895560451863089656472772604678260265531221036453811406496"));

		System.out.println("\n\n p is " + Curve25519.p);
	}

	// 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
	// byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	// 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	// 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	@Test
	public void testAES() {
		Charset.forName("UTF-8");
		int[] w = null;
		AES aes = new AES();

		byte[] plaintext = { (byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8, (byte) 0x88, (byte) 0x5a, (byte) 0x30,
				(byte) 0x8d, (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2, (byte) 0xe0, (byte) 0x37, (byte) 0x07,
				(byte) 0x34 };
		byte[] key128 = { (byte) 0x2b, (byte) 0x7e, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2,
				(byte) 0xa6, (byte) 0xab, (byte) 0xf7, (byte) 0x15, (byte) 0x88, (byte) 0x09, (byte) 0xcf, (byte) 0x4f,
				(byte) 0x3c };
		// byte[] key128 = {(byte)0x2b, (byte)0x28, (byte)0xab, (byte)0x09, (byte)0x7e,
		// (byte)0xae, (byte)0xf7, (byte)0xcf, (byte)0x15, (byte)0xd2, (byte)0x15,
		// (byte)0x4f, (byte)0x16, (byte)0xa6, (byte)0x88, (byte)0x3c};
		byte[] crypt1 = aes.cipher(key128, plaintext, Nb, 10, 4, w);
		byte[] res1 = { (byte) 0x39, (byte) 0x02, (byte) 0xdc, (byte) 0x19, (byte) 0x25, (byte) 0xdc, (byte) 0x11,
				(byte) 0x6a, (byte) 0x84, (byte) 0x09, (byte) 0x85, (byte) 0x0b, (byte) 0x1d, (byte) 0xfb, (byte) 0x97,
				(byte) 0x32 };
		for (int i = 0; i < res1.length; i++) {
			assertEquals(res1[i], crypt1[i]);
		}

		byte[] plaintext_2 = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa,
				(byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff };
		byte[] key128_2 = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				0x0f };
		byte[] res2 = aes.cipher(key128_2, plaintext_2, Nb, 10, 4, w);
		assertEquals("69c4e0d86a7b0430d8cdb78070b4c55a", aes.toStringTransposed(res2));

		byte[] plaintext192 = Conv.toByteArray("00112233445566778899aabbccddeeff");
		byte[] key192 = Conv.toByteArray("000102030405060708090a0b0c0d0e0f1011121314151617");
		byte[] res192 = aes.cipher(key192, plaintext192, Nb, 12, 6, w);
		assertEquals("dda97ca4864cdfe06eaf70a0ec0d7191", aes.toStringTransposed(res192));

		byte[] plaintext256 = Conv.toByteArray("00112233445566778899aabbccddeeff");
		byte[] key256 = Conv.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		byte[] res256 = aes.cipher(key256, plaintext256, Nb, 14, 8, w);
		byte[] res256_2 = aes.cipher256SingleBlock("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				"00112233445566778899aabbccddeeff");
		assertEquals("8ea2b7ca516745bfeafc49904b496089", aes.toStringTransposed(res256));
		assertEquals("8ea2b7ca516745bfeafc49904b496089", aes.toStringTransposed(res256_2));
		byte[] dec_input = Conv.toByteArray(aes.toStringTransposed(res256));
		String key_string = Conv.toString(key256);
		byte[] dec = aes.decipher256SingleBlock(key_string, res256);
		System.out.println("AES decypher: " + Conv.toString(dec));

		// assertEquals("8ea2b7ca516745bfeafc49904b496089",
		// aes.toStringTransposed(res256));
		String zeroKey = "0000000000000000000000000000000000000000000000000000000000000000";
		// String zeroKey =
		// "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
		String zeroInput = "00000000000000000000000000000000";
		byte[] res_5 = aes.cipher256SingleBlock(zeroKey, zeroInput);
		// byte[] res_6 = aes.cipher256(zeroKey,"00000000000000000000000000000001");
		byte[] dec_5 = aes.decipher256SingleBlock(zeroKey, res_5);
		assertArrayEquals(Conv.toByteArray(zeroInput), dec_5);
	}

	@Test
	public void testLongByteConversion () {
		byte[] k =  Conv.toByteArray("00000000000000000000000000000001");
		long l = Conv.bytesToUnsignedLong(k);
		assertEquals(0L, l);
		k =  Conv.toByteArray("00000000000000020000000000000001");
		l = Conv.bytesToUnsignedLong(k);
		assertEquals(2L, l);
		k =  Conv.toByteArray("ffffffffffffffff0000000000000001");
		l = Conv.bytesToUnsignedLong(k);
		assertEquals(0, Long.compareUnsigned(0xffffffffffffffffL, l));
		assertEquals(0xffffffffffffffffL, l);
		Conv.UnsingedLongToByteArray(0xfeL, k);
		l = Conv.bytesToUnsignedLong(k);
		assertEquals(254L, l);
		l -= 2;
		Conv.UnsingedLongToByteArray(l, k);
		l = Conv.bytesToUnsignedLong(k);
		assertEquals(252L, l);
	}
	
	@Test
	public void testAESFullMessage() {
		AES aes = new AES();
		
		byte[] key2 = Conv.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		byte[] key =  Conv.toByteArray("4cad16ec5f116c449accc58f4c44f28ac921f502471e387fdcd4f493b115af2d");
		byte[] m = "Niklas ist der Beste!".getBytes(StandardCharsets.UTF_8);
		//byte[] m = "Niklas ist der".getBytes(StandardCharsets.UTF_8);
		//byte[] m = "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
		byte[] enc =  aes.cipher256(key, m);
		System.out.println("cipher: " + Conv.toString(enc));
		byte[] dec = aes.decipher256(key, enc);
		assertArrayEquals(m, dec);
	}

	// create random byte buffer and check encryption/decryption
	@Test
	public void testAESRandomMessage() {
		AES aes = new AES();
		Random random = new Random();
		int runs = 200;
		for (int i = 0; i < runs; i++) {
			// input message length: between 0 and 15000
			int len = random.nextInt(15000);
			byte[] message = new byte[len];
			random.nextBytes(message);
			//System.out.println("msg: " + Conv.toString(message));
			byte[] key = Conv.toByteArray("4cad16ec5f116c449accc58f4c44f28ac921f502471e387fdcd4f493b115af2d");
			byte[] enc = aes.cipher256(key, message);
			byte[] dec = aes.decipher256(key, enc);
			assertArrayEquals(message, dec);
		}
		
	}

	@Test
	public void testKeyExpansion() {
		int[] w = null;
		AES aes = new AES();

		byte[] key128 = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6, (byte) 0xab, (byte) 0xf7,
				0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c };
		w = aes.keyExpansion(key128, 4, Nb, 10);
		assertEquals(w[43], 0xb6630ca6);

		byte[] key192 = { (byte) 0x8e, 0x73, (byte) 0xb0, (byte) 0xf7, (byte) 0xda, 0x0e, 0x64, 0x52, (byte) 0xc8, 0x10,
				(byte) 0xf3, 0x2b, (byte) 0x80, (byte) 0x90, 0x79, (byte) 0xe5, 0x62, (byte) 0xf8, (byte) 0xea,
				(byte) 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
		w = aes.keyExpansion(key192, 6, Nb, 12);
		assertEquals(w[51], 0x01002202);

		byte[] key256 = { 0x60, 0x3d, (byte) 0xeb, 0x10, 0x15, (byte) 0xca, 0x71, (byte) 0xbe, 0x2b, 0x73, (byte) 0xae,
				(byte) 0xf0, (byte) 0x85, 0x7d, 0x77, (byte) 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08,
				(byte) 0xd7, 0x2d, (byte) 0x98, 0x10, (byte) 0xa3, 0x09, 0x14, (byte) 0xdf, (byte) 0xf4 };
		w = aes.keyExpansion(key256, 8, Nb, 14);
		assertEquals(w[59], 0x706c631e);
//		for (int i = 0; i < w.length; i++) {
//			System.out.println("w[" + i + "] = " + Integer.toHexString(w[i]));
//		}
	}

	@Test
	public void testMult() {
		AES aes = new AES();
		byte r;
		r = aes.galoisFastMult((byte) 0xbf, (byte) 0x03);
		assertEquals((byte) 0xda, r);
		r = aes.galoisFastMult((byte) 0x57, (byte) 0x13);
		assertEquals((byte) 0xfe, r);
	}

	private long highMod(long x, long exponent, long modulo) {
		long sum = x;
		for (long i = 0; i < (exponent - 1); i++) {
			sum = (sum * x) % modulo;
		}
		return sum;

	}

	@Test
	public void testRandom() {
		AES aes = new AES();
		if (!USE_LARGE_KEY_TESTS)
			return;
		// aes.setSeed(aes.toByteArray("c14907f6ca3b3aa070e9aa313b52b5ec5f9c6abfbac634aa50409fa766677653"));
		double pi = calculatePi(aes, 1000000L);
		// System.out.println("(1000000) Pi = " + pi);
		assertTrue(pi >= 3.14d && pi <= 3.15d, "pi within expected range");
	}

	private double calculatePi(AES aes, long num_points) {
		// use random numbers with 6 bytes (0 .. 16.7 Mio) to simulate field
		double r2d = (new Long(0xffffffffffffL)).doubleValue();
		r2d *= r2d;
		double A_squared = (new Long(0x1000000000000L)).doubleValue();
		A_squared *= A_squared;
		long Num_square = 0;
		for (long i = 0; i < num_points; i++) {
			long x = toLong(aes.random(6), aes);
			long y = toLong(aes.random(6), aes);
			double xd = (new Long(x)).doubleValue();
			double yd = (new Long(y)).doubleValue();
			double dist_2d = xd * xd + yd * yd;
			if (dist_2d <= r2d) {
				Num_square++;
			}
			// System.out.println("x y all inside " + Long.toHexString(x) + " " +
			// Long.toHexString(y) + " " + Num_all + " " + Num_square + " " + dist_2d + " "
			// + r2d);
		}
		double alld = (new Long(num_points)).doubleValue();
		double insided = (new Long(Num_square)).doubleValue();
		return (insided / alld) * 4;
	}

	private long toLong(byte[] b, AES aes) {
		long high = aes.word((byte) 0, (byte) 0, b[0], b[1]) & 0xffffffffL;
		long low = aes.word(b[2], b[3], b[4], b[5]) & 0xffffffffL;
		return (high << 32) | low;
	}

	@Test
	public void testConversions() {
		AES aes = new AES();
		byte[] plaintext = { (byte) 0x32, (byte) 0x43, (byte) 0xf6, (byte) 0xa8, (byte) 0x88, (byte) 0x5a, (byte) 0x30,
				(byte) 0x8d, (byte) 0x31, (byte) 0x31, (byte) 0x98, (byte) 0xa2, (byte) 0xe0, (byte) 0x37, (byte) 0x07,
				(byte) 0x34 };
		String plain = Conv.toString(plaintext);
		assertEquals("3243f6a8885a308d313198a2e0370734", plain);
		byte[] re = Conv.toByteArray(plain);
		for (int i = 0; i < re.length; i++) {
			assertEquals(re[i], plaintext[i]);
		}
		// System.out.println((aes.toStringTransposed(aes.toByteArray("696ad870c47bcdb4e004b7c5d830805a"))));
		assertEquals("69c4e0d86a7b0430d8cdb78070b4c55a",
				(aes.toStringTransposed(Conv.toByteArray("696ad870c47bcdb4e004b7c5d830805a"))));

		// System.out.println("exp " + highMod(2,4,1000));
		// cypher
		assertEquals(highMod(230911, 1721, 263713), 1715);
		assertEquals(highMod(91605, 1721, 263713), 184304);
		assertEquals(highMod(40901, 1721, 263713), 219983);
		// decypher
		assertEquals(highMod(1715, 1373, 263713), 230911);
		assertEquals(highMod(184304, 1373, 263713), 91605);
		assertEquals(highMod(219983, 1373, 263713), 40901);
	}

	@Test
	public void testRSA() {
		// test RSA and key generation:
		RSA rsa = new RSA();
		// rsa.createPrimesPQ(32);
		// rsa.createPrimesPQ(2048);
		// rsa.createPrimesPQ(8192);
		// System.out.println("found prime: " prime.toString(16));

		rsa.generateKeys(32);
		String dec, input;
		input = "Dies ist ein toller Test!";
		BigInteger m = null;
		try {
			m = rsa.encrypt(input);
			fail();
		} catch (NumberFormatException e) {
		}

		rsa.generateKeys(48);
		input = "Dies";
		m = rsa.encrypt(input);
		dec = rsa.decrypt(m);
		assertEquals(input, dec);

		rsa.generateKeys(208);
		input = "Dies ist ein toller Test!";
		m = rsa.encrypt(input);
		dec = rsa.decrypt(m);
		assertEquals(input, dec);

		if (!USE_LARGE_KEY_TESTS)
			return;

		rsa.generateKeys(2048);
		input = "This should really be a big text to see what is possible here.";
		for (int i = 0; i < 2; i++)
			input += input;
		m = rsa.encrypt(input);
		dec = rsa.decrypt(m);
		assertEquals(input, dec);

		input = "T";
		m = rsa.encrypt(input);
		dec = rsa.decrypt(m);
		assertEquals(input, dec);
	}

	/*
	 * not able to encrypt 2 bytes with RSA 16 bits not able to encrypt 4 bytes with
	 * RSA 32 bits not able to encrypt 8 bytes with RSA 64 bits not able to encrypt
	 * 16 bytes with RSA 128 bits not able to encrypt 32 bytes with RSA 256 bits not
	 * able to encrypt 64 bytes with RSA 512 bits not able to encrypt 128 bytes with
	 * RSA 1024 bits not able to encrypt 256 bytes with RSA 2048 bits not able to
	 * encrypt 512 bytes with RSA 4096 bits
	 */
	// @Test disabled for long runtime, see result in list above
	public void testRSASigningLength() {
		// first do some key length tests
		int keyLength[] = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096 };
		AES aes = new AES();
		for (int klen : keyLength) {
			// check key length and encryption
			RSA rsa = new RSA();
			rsa.generateKeys(klen);
			int messageSize = 1;
			boolean ok = true;
			while (ok) {
				try {
					byte[] msg = aes.random(messageSize);
					assertEquals(messageSize, msg.length);
					for (int i = 0; i < msg.length; i++) {
						msg[i] = (byte) 0xff;
					}
					BigInteger enc = rsa.encrypt(msg);
					messageSize++;
				} catch (NumberFormatException e) {
					ok = false;
					System.out.println("not able to encrypt " + messageSize + " bytes with RSA " + klen + " bits");
				}
			}
		}
	}

	@Test
	public void testRSASigning() {
		String secret_k = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
		RSA rsa = new RSA();
		rsa.generateKeys(1024);
		String alice_public = rsa.keys.n.toString(16);
		String alice_private = rsa.keys.d.toString(16);
		String e_fixed = rsa.keys.e.toString(16);

		System.out.println("Modul n (public key): " + alice_public);
		System.out.println("  private key d: " + alice_private);
		System.out.println("  fixed e: " + e_fixed);

		// we want do sign 64 byte SHA-512 hashes:
		String message = secret_k + "|mode=Init|" + alice_public;

		// compute msg hash:
		SHA sha = new SHA();
		byte[] hash = sha.sha512(message);
		assertEquals(64, hash.length);

		// encrypt hash with static encryption method:
		String hashString = Conv.toString(hash);
		System.out.println(" message hash: " + hashString);
		String bigencString = RSA.encryptMessageWithPrivateKey(hashString, alice_private, alice_public);

		String fullMessageWithSignature = message + "|" + bigencString;
		System.out.println("fullMessageWithSignature " + fullMessageWithSignature);

		// assume fullMessageWithSignature was transmitted
		// verify message:
		String[] parts = fullMessageWithSignature.split(Pattern.quote("|"));
		assertEquals(4, parts.length);

		String encryptedHex = parts[3];
		String publicKey = parts[2];
		assertEquals(bigencString, encryptedHex);
		assertEquals(alice_public, publicKey);
		String decryptedHex = RSA.decryptMessageWithPublicKey(encryptedHex, publicKey);
		System.out.println("decrypted message: " + decryptedHex);
		assertEquals(hashString, decryptedHex);
	}

	@Test
	public void testBigIntegerConversions() {
		RSA rsa = new RSA();
		String res, input = "01";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals(input, res);
		input = "ff";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals(input, res);
		input = "00010000";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals("010000", res);
		input = "00000000000000000001";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals("01", res);
		input = "ffffffffffffffffffff";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals("ff", res);
		input = "ffffffffffffffffffff000000";
		res = Conv.toString(rsa.decodeFromBigInteger(rsa.encodeToBigInteger(Conv.toByteArray(input))));
		assertEquals("ff000000", res);

		System.out.println("curve25519 tests");
		input = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
		BigInteger bi = rsa.encodeToBigInteger(Conv.toByteArray(input));
		System.out.println(bi);
		bi = new BigInteger("31029842492115040904895560451863089656472772604678260265531221036453811406496");
		System.out.println("input: " + bi);
		res = Conv.toString(rsa.decodeFromBigIntegerLittleEndian(bi));
		System.out.println("decoded: " + res);
	}

	// SHA

	@Test
	public void testSHA() {
		SHA sha = new SHA();
		byte[] digest = null;

		sha.startSha512Feed();
		String manya = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				+ "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
		manya += manya;
		sha.feed(manya.getBytes());
		digest = sha.endSha512Feed();
		byte[] simpleDigest = sha.sha512(manya);
		assertArrayEquals(digest, simpleDigest);

		sha.startSha512Feed();
		sha.feed("a".getBytes());
		sha.feed("b".getBytes());
		sha.feed("c".getBytes());
		digest = sha.endSha512Feed();
		// System.out.println("digest: " + aes.toString(digest));
		assertTrue(Conv.toString(digest).equalsIgnoreCase(
				"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"));

		digest = sha.pad1024("abc".getBytes());
		assertEquals(1024 / 8, digest.length);

		digest = sha.sha512("abc");
		assertEquals(512 / 8, digest.length);
		// System.out.println("digest: " + aes.toString(digest));
		assertTrue(Conv.toString(digest).equalsIgnoreCase(
				"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"));

		digest = sha.sha512(
				"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
		assertEquals(512 / 8, digest.length);
		// System.out.println("digest: " + aes.toString(digest));
		assertTrue(Conv.toString(digest).equalsIgnoreCase(
				"8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"));
	}
}
