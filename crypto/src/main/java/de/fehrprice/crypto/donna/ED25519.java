package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.FP256;
import de.fehrprice.crypto.SHA;
import de.fehrprice.crypto.donna.niels.Bignum25519;
import de.fehrprice.crypto.donna.niels.ConstDef;
import de.fehrprice.crypto.donna.niels.Niels;
import de.fehrprice.crypto.FP256.fp256;
import de.fehrprice.crypto.donna.niels.ge25519;
import de.fehrprice.crypto.Long4;

public class ED25519 {
	
	private FP256 fp = new FP256();
	private Curve25519 cv = new Curve25519();
	private Niels niels = new Niels();
	private ConstDef constDef = new ConstDef();
	private Long4 long4 = new Long4();
	public static final long reduce_mask_51 = 0x0007ffffffffffffL;
	/* multiples of p */
	public static final long twoP0      = 0x0fffffffffffdaL;
	public static final long twoP1234   = 0x0ffffffffffffeL;
	public static final long fourP0     = 0x1fffffffffffb4L;
	public static final long fourP1234  = 0x1ffffffffffffcL;
	
	public static void print64(String name, byte[] b) {
		System.out.print(name + " ");
		for (int i = 0; i < 64; i++) {
			System.out.printf("%02x", b[i]);
		}
		System.out.println();
	}
	
	public static void print96(String name, byte[] b) {
		System.out.print(name + " ");
		for (int i = 0; i < 96; i++) {
			System.out.printf("%02x", b[i]);
		}
		System.out.println();
	}
	
	private void print128(String txt, fp256 f) {
		System.out.printf("%s ", txt); for (int i = 1; i >= 0; i--) printLong(f.getInternalLongArray()[i]); System.out.println();
	}
	
	public static void printBig(String txt, Bignum25519 v) {
		printB256modm(txt, v);
//		int i;
//		System.out.printf("%s ", txt);
//		System.out.printf("%016x ", v.m[0]);
//		System.out.printf("%016x ", v.m[1]);
//		System.out.printf("%016x ", v.m[2]);
//		System.out.printf("%016x ", v.m[3]);
//		System.out.printf("%016x ", v.m[4]);
//		System.out.printf("\n");
	}
	
	
	public static void printLong(long l) {
		System.out.printf("%016x ", l);
	}
	public static void print64t(String txt, long l) {
		System.out.printf("%s %016x \n", txt, l);
	}
	public static void printB256modm(String txt, Bignum256modm a) {
		int i;
		System.out.printf("%s ", txt); for (i = 0; i < 5; i++) printLong(a.m[i]); System.out.println();
	}
	
	
	public String publicKey(String secretKeyString) {
		Key secretKey = new Key();
		Key publicKey = new Key();
		Convert.toKey(secretKey, secretKeyString);
		publicKey(secretKey, publicKey);
		return Convert.fromKey(publicKey);
	}
	
	
	/**
	 * Create public key from secret key.
	 * @param secretKey
	 * @param publicKey
	 */
	public void publicKey(Key secretKey, Key publicKey) {
		Bignum256modm a = new Bignum256modm();
		ge25519 A = new ge25519();
		
		/* A = aB */
		System.out.println("publickey()");
		byte[] extsk = new byte[64];
		extsk(extsk, secretKey);
		print64("sk SHA", extsk);
		expand256_modm(a, extsk, 32);
		niels.scalarmult_base_niels(A, ConstDef.ge25519_niels_base_multiples, a);
		//ge25519_pack(pk, &A);
	}
	
	/* Take a little-endian, 32-byte number and expand it into polynomial form */
	public static void expand32(Bignum256modm out, byte[] in) {
		Bignum256modm x = new Bignum256modm();
		x.m[0] = U8TO64_LE(in,0);
		x.m[1] = U8TO64_LE(in,8);
		x.m[2] = U8TO64_LE(in,16);
		x.m[3] = U8TO64_LE(in,24);
		//System.out.print("x8 "); for (int i = 0; i < 5; i++) printLong(x.m[i]); System.out.println();
		
		out.m[0] = x.m[0] & reduce_mask_51; x.m[0] = (x.m[0] >>> 51) | (x.m[1] << 13);
		out.m[1] = x.m[0] & reduce_mask_51; x.m[1] = (x.m[1] >>> 38) | (x.m[2] << 26);
		out.m[2] = x.m[1] & reduce_mask_51; x.m[2] = (x.m[2] >>> 25) | (x.m[3] << 39);
		out.m[3] = x.m[2] & reduce_mask_51; x.m[3] = (x.m[3] >>> 12);
		out.m[4] = x.m[3] & reduce_mask_51;
		
		//printB256modm("exp32", out);
	}
	
	public static void swap_conditional(Bignum25519 a, Bignum25519 b, long iswap) {
		long swap = -iswap;
		long x0,x1,x2,x3,x4;
		
		x0 = swap & (a.m[0] ^ b.m[0]); a.m[0] ^= x0; b.m[0] ^= x0;
		x1 = swap & (a.m[1] ^ b.m[1]); a.m[1] ^= x1; b.m[1] ^= x1;
		x2 = swap & (a.m[2] ^ b.m[2]); a.m[2] ^= x2; b.m[2] ^= x2;
		x3 = swap & (a.m[3] ^ b.m[3]); a.m[3] ^= x3; b.m[3] ^= x3;
		x4 = swap & (a.m[4] ^ b.m[4]); a.m[4] ^= x4; b.m[4] ^= x4;
	}
	
	/* out = -a */
	public static void neg(Bignum25519 out, Bignum25519 a) {
		long c;
		out.m[0] = twoP0    - a.m[0]    ; c = (out.m[0] >>> 51); out.m[0] &= reduce_mask_51;
		out.m[1] = twoP1234 - a.m[1] + c; c = (out.m[1] >>> 51); out.m[1] &= reduce_mask_51;
		out.m[2] = twoP1234 - a.m[2] + c; c = (out.m[2] >>> 51); out.m[2] &= reduce_mask_51;
		out.m[3] = twoP1234 - a.m[3] + c; c = (out.m[3] >>> 51); out.m[3] &= reduce_mask_51;
		out.m[4] = twoP1234 - a.m[4] + c; c = (out.m[4] >>> 51); out.m[4] &= reduce_mask_51;
		out.m[0] += c * 19;
	}
	
	public void expand256_modm(Bignum256modm out, byte[] in, int len) {
		byte work[] = new byte[64];
		long x[] = new long[16];
		Bignum256modm q1 = new Bignum256modm();
		
		System.arraycopy(in, 0, work, 0, len);
		x[0] = U8TO64_LE(work,0);
		x[1] = U8TO64_LE(work,8);
		x[2] = U8TO64_LE(work,16);
		x[3] = U8TO64_LE(work,24);
		x[4] = U8TO64_LE(work,32);
		x[5] = U8TO64_LE(work,40);
		x[6] = U8TO64_LE(work,48);
		x[7] = U8TO64_LE(work,56);
		System.out.print("x8 "); for (int i = 0; i < 8; i++) printLong(x[i]); System.out.println();
		
		
		/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
		out.m[0] = (                         x[0]) & 0xffffffffffffffL;
		out.m[1] = ((x[ 0] >>> 56) | (x[ 1] <<  8)) & 0xffffffffffffffL;
		out.m[2] = ((x[ 1] >>> 48) | (x[ 2] << 16)) & 0xffffffffffffffL;
		out.m[3] = ((x[ 2] >>> 40) | (x[ 3] << 24)) & 0xffffffffffffffL;
		out.m[4] = ((x[ 3] >>> 32) | (x[ 4] << 32)) & 0x0000ffffffffffL;
		printB256modm("exp no red", out);
		
		/* under 252 bits, no need to reduce */
		if (len < 32)
			return;
		
		/* q1 = x >> 248 = 264 bits */
		q1.m[0] = ((x[ 3] >>> 56) | (x[ 4] <<  8)) & 0xffffffffffffffL;
		q1.m[1] = ((x[ 4] >>> 48) | (x[ 5] << 16)) & 0xffffffffffffffL;
		q1.m[2] = ((x[ 5] >>> 40) | (x[ 6] << 24)) & 0xffffffffffffffL;
		q1.m[3] = ((x[ 6] >>> 32) | (x[ 7] << 32)) & 0xffffffffffffffL;
		q1.m[4] = ((x[ 7] >>> 24)                );
		
		barrett_reduce256_modm(out, q1, out);
		printB256modm("q b256", out);
	}
	
	
	/**
	 * @param r byte[64]
	 * @param in
	 */
	public static void contract256_window4_modm(byte r[], Bignum256modm in) {
		byte carry;
		//signed char *quads = r;
		int quads = 0; // iterate index of r[]
		int i, j;
		long v, m;
		
		for (i = 0; i < 5; i++) {
			v = in.m[i];
			m = (i == 4) ? 8 : 14;
			for (j = 0; j < m; j++) {
			    r[quads++] = (byte)(v & 15);
				v >>= 4;
			}
		}
		
		/* making it signed */
		carry = 0;
		for(i = 0; i < 63; i++) {
			r[i] += carry;
			r[i+1] += (r[i] >> 4);
			r[i] &= 15;
			carry = (byte)(r[i] >> 3);
			r[i] -= (carry << 4);
		}
		r[63] += carry;
	}
	
	static long modm_m[] = {
			0x12631a5cf5d3edL,
			0xf9dea2f79cd658L,
			0x000000000014deL,
			0x00000000000000L,
			0x00000010000000L
	};
	
	static long modm_mu[] = {
			0x9ce5a30a2c131bL,
			0x215d086329a7edL,
			0xffffffffeb2106L,
			0xffffffffffffffL,
			0x00000fffffffffL
	};
	
	private void reduce256_modm(Bignum256modm r) {
		Bignum256modm t = new Bignum256modm();
		long b, pb, mask;
		
		/* t = r - m */
		pb = 0;
		pb += modm_m[0]; b = lt_modm(r.m[0], pb); t.m[0] = (r.m[0] - pb + (b << 56)); pb = b;
		pb += modm_m[1]; b = lt_modm(r.m[1], pb); t.m[1] = (r.m[1] - pb + (b << 56)); pb = b;
		pb += modm_m[2]; b = lt_modm(r.m[2], pb); t.m[2] = (r.m[2] - pb + (b << 56)); pb = b;
		pb += modm_m[3]; b = lt_modm(r.m[3], pb); t.m[3] = (r.m[3] - pb + (b << 56)); pb = b;
		pb += modm_m[4]; b = lt_modm(r.m[4], pb); t.m[4] = (r.m[4] - pb + (b << 32));
		
		/* keep r if r was smaller than m */
		mask = b - 1;
		
		r.m[0] ^= mask & (r.m[0] ^ t.m[0]);
		r.m[1] ^= mask & (r.m[1] ^ t.m[1]);
		r.m[2] ^= mask & (r.m[2] ^ t.m[2]);
		r.m[3] ^= mask & (r.m[3] ^ t.m[3]);
		r.m[4] ^= mask & (r.m[4] ^ t.m[4]);
	}
	
	
	private void barrett_reduce256_modm(Bignum256modm r, Bignum256modm q1, Bignum256modm r1) {
		Bignum256modm q3 = new Bignum256modm(), r2 = new Bignum256modm();
		fp256 c = fp.zero();
		fp256 mul = fp.zero();
		long f = 0, b = 0, pb = 0;

	/* q1 = x >> 248 = 264 bits = 5 56 bit elements
	   q2 = mu * q1
	   q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264 */
		mul64x64_128(c, modm_mu[0], q1.m[3]);                  mul64x64_128(mul, modm_mu[3], q1.m[0]); add128(c, mul); mul64x64_128(mul, modm_mu[1], q1.m[2]); add128(c, mul); mul64x64_128(mul, modm_mu[2], q1.m[1]); add128(c, mul); f =shr128(c, 56);
		//print128("c", c);
		mul64x64_128(c, modm_mu[0], q1.m[4]); add128_64(c, f); mul64x64_128(mul, modm_mu[4], q1.m[0]); add128(c, mul); mul64x64_128(mul, modm_mu[3], q1.m[1]); add128(c, mul); mul64x64_128(mul, modm_mu[1], q1.m[3]); add128(c, mul); mul64x64_128(mul, modm_mu[2], q1.m[2]); add128(c, mul);
		//print128("c", c);
		f = lo128(c); q3.m[0] = (f >> 40) & 0xffff; f = shr128(c, 56);
		//print64t("f", f);
		//print128("c", c);
		mul64x64_128(c, modm_mu[4], q1.m[1]); add128_64(c, f); mul64x64_128(mul, modm_mu[1], q1.m[4]); add128(c, mul); mul64x64_128(mul, modm_mu[2], q1.m[3]); add128(c, mul); mul64x64_128(mul, modm_mu[3], q1.m[2]); add128(c, mul);
		//print128("c", c);
		f = lo128(c); q3.m[0] |= (f << 16) & 0xffffffffffffffL; q3.m[1] = (f >> 40) & 0xffff; f = shr128(c, 56);
		mul64x64_128(c, modm_mu[4], q1.m[2]); add128_64(c, f); mul64x64_128(mul, modm_mu[2], q1.m[4]); add128(c, mul); mul64x64_128(mul, modm_mu[3], q1.m[3]); add128(c, mul);
		f = lo128(c); q3.m[1] |= (f << 16) & 0xffffffffffffffL; q3.m[2] = (f >> 40) & 0xffff; f = shr128(c, 56);
		mul64x64_128(c, modm_mu[4], q1.m[3]); add128_64(c, f); mul64x64_128(mul, modm_mu[3], q1.m[4]); add128(c, mul);
		f = lo128(c); q3.m[2] |= (f << 16) & 0xffffffffffffffL; q3.m[3] = (f >> 40) & 0xffff; f = shr128(c, 56);
		mul64x64_128(c, modm_mu[4], q1.m[4]); add128_64(c, f);
		//print128("c", c);
		f = lo128(c); q3.m[3] |= (f << 16) & 0xffffffffffffffL; q3.m[4] = (f >> 40) & 0xffff; f = shr128(c, 56);
		q3.m[4] |= (f << 16);
		
		mul64x64_128(c, modm_m[0], q3.m[0]);
		r2.m[0] = lo128(c) & 0xffffffffffffffL; f = shr128(c, 56);
		mul64x64_128(c, modm_m[0], q3.m[1]); add128_64(c, f); mul64x64_128(mul, modm_m[1], q3.m[0]); add128(c, mul);
		r2.m[1] = lo128(c) & 0xffffffffffffffL; f = shr128(c, 56);
		mul64x64_128(c, modm_m[0], q3.m[2]); add128_64(c, f); mul64x64_128(mul, modm_m[2], q3.m[0]); add128(c, mul); mul64x64_128(mul, modm_m[1], q3.m[1]); add128(c, mul);
		r2.m[2] = lo128(c) & 0xffffffffffffffL; f = shr128(c, 56);
		mul64x64_128(c, modm_m[0], q3.m[3]); add128_64(c, f); mul64x64_128(mul, modm_m[3], q3.m[0]); add128(c, mul); mul64x64_128(mul, modm_m[1], q3.m[2]); add128(c, mul); mul64x64_128(mul, modm_m[2], q3.m[1]); add128(c, mul);
		r2.m[3] = lo128(c) & 0xffffffffffffffL; f = shr128(c, 56);
		mul64x64_128(c, modm_m[0], q3.m[4]); add128_64(c, f); mul64x64_128(mul, modm_m[4], q3.m[0]); add128(c, mul); mul64x64_128(mul, modm_m[3], q3.m[1]); add128(c, mul); mul64x64_128(mul, modm_m[1], q3.m[3]); add128(c, mul); mul64x64_128(mul, modm_m[2], q3.m[2]); add128(c, mul);
		r2.m[4] = lo128(c) & 0x0000ffffffffffL;
		
		pb = 0;
		pb += r2.m[0]; b = lt_modm(r1.m[0], pb); r.m[0] = (r1.m[0] - pb + (b << 56)); pb = b;
		pb += r2.m[1]; b = lt_modm(r1.m[1], pb); r.m[1] = (r1.m[1] - pb + (b << 56)); pb = b;
		pb += r2.m[2]; b = lt_modm(r1.m[2], pb); r.m[2] = (r1.m[2] - pb + (b << 56)); pb = b;
		pb += r2.m[3]; b = lt_modm(r1.m[3], pb); r.m[3] = (r1.m[3] - pb + (b << 56)); pb = b;
		pb += r2.m[4]; b = lt_modm(r1.m[4], pb); r.m[4] = (r1.m[4] - pb + (b << 40));
		
		printB256modm("r b256", r);
		reduce256_modm(r);
		reduce256_modm(r);
		printB256modm("r b256", r);
	}
	
	
	private long lt_modm(long a, long b) {
		return (a - b) >>> 63;
	}
	
	
	private long lo128(fp256 c) {
		return c.getInternalLongArray()[0];
	}
	
	
	private void add128_64(fp256 c, long f) {
		fp.add(c, c, fp.fromLong(f));
	}
	
	
	private long shr128(fp256 c, int op) {
		fp256 cn = fp.copy(c);
		for (int i = 0; i < op; i++) {
			fp.shiftRight1(cn);
		}
		return(lo128(cn));
	}
	
	
	private void add128(fp256 a, fp256 b) {
		fp.add(a, a, b);
	}
	
	
	private void mul64x64_128(fp256 c, long a, long b) {
		fp.umul64(c, a, b);
	}
	
	
	/**
	 * convert 8 consecutive bytes from an array to long
	 * least significant byte assumed to be in lowest index position
	 * @param b
	 * @param idx start index
	 * @return
	 */
	private static long U8TO64_LE(byte[] b, int idx) {
		long l = ((long) b[7+idx] << 56)
				| ((long) b[6+idx] & 0xff) << 48
				| ((long) b[5+idx] & 0xff) << 40
				| ((long) b[4+idx] & 0xff) << 32
				| ((long) b[3+idx] & 0xff) << 24
				| ((long) b[2+idx] & 0xff) << 16
				| ((long) b[1+idx] & 0xff) << 8
				| ((long) b[0+idx] & 0xff);
		return l;
	}
	
	
	private void extsk(byte[] extsk, Key secretKey) {
		byte[] b = h(secretKey.k);
		System.arraycopy(b, 0, extsk, 0, 64);
		//print64("sk SHA", extsk);
		// clear lowest 3 bits
		extsk[0] = (byte)(((int)extsk[0]) & 248);
		// clear highest bit
		extsk[31] = (byte)(((int)extsk[31]) & 127);
		// set 2nd highest bit:
		extsk[31] = (byte)(((int)extsk[31]) | 64);
	}
	
	
	private byte[] h(byte[] message) {
		SHA sha = new SHA();
		byte[] digest = sha.sha512(message);
		//System.out.println("digest = " + aes.toString(digest));
		return digest;
	}
	
}
