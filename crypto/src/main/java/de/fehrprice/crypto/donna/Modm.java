package de.fehrprice.crypto.donna;

/*
	Public domain by Andrew M. <liquidsun@gmail.com>
*/


import de.fehrprice.crypto.FixedPointOp;
import de.fehrprice.crypto.fp256;
import static de.fehrprice.crypto.donna.Curve25519.U8TO64_LE;
import static de.fehrprice.crypto.donna.Curve25519.U64TO8_LE;

/*
	Arithmetic modulo the group order n = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989

	k = 32
	b = 1 << 8 = 256
	m = 2^252 + 27742317777372353535851937790883648493 = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	mu = floor( b^(k*2) / m ) = 0xfffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b
*/
public class Modm {
	private final FixedPointOp fp = new FixedPointOp();
	private final Curve25519 cv = new Curve25519();
	public Modm() {
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
	
	
	private long lt_modm(long a, long b) {
		return (a - b) >>> 63;
	}

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
		cv.mul64x64_128(c, modm_mu[0], q1.m[3]);                  cv.mul64x64_128(mul, modm_mu[3], q1.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[1], q1.m[2]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[2], q1.m[1]); cv.add128(c, mul); f =cv.shr128(c, 56);
		//print128("c", c);
		cv.mul64x64_128(c, modm_mu[0], q1.m[4]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_mu[4], q1.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[3], q1.m[1]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[1], q1.m[3]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[2], q1.m[2]); cv.add128(c, mul);
		//print128("c", c);
		f = cv.lo128(c); q3.m[0] = (f >> 40) & 0xffff; f = cv.shr128(c, 56);
		//print64t("f", f);
		//print128("c", c);
		cv.mul64x64_128(c, modm_mu[4], q1.m[1]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_mu[1], q1.m[4]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[2], q1.m[3]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[3], q1.m[2]); cv.add128(c, mul);
		//print128("c", c);
		f = cv.lo128(c); q3.m[0] |= (f << 16) & 0xffffffffffffffL; q3.m[1] = (f >> 40) & 0xffff; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_mu[4], q1.m[2]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_mu[2], q1.m[4]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_mu[3], q1.m[3]); cv.add128(c, mul);
		f = cv.lo128(c); q3.m[1] |= (f << 16) & 0xffffffffffffffL; q3.m[2] = (f >> 40) & 0xffff; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_mu[4], q1.m[3]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_mu[3], q1.m[4]); cv.add128(c, mul);
		f = cv.lo128(c); q3.m[2] |= (f << 16) & 0xffffffffffffffL; q3.m[3] = (f >> 40) & 0xffff; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_mu[4], q1.m[4]); cv.add128_64(c, f);
		//print128("c", c);
		f = cv.lo128(c); q3.m[3] |= (f << 16) & 0xffffffffffffffL; q3.m[4] = (f >> 40) & 0xffff; f = cv.shr128(c, 56);
		q3.m[4] |= (f << 16);
		
		cv.mul64x64_128(c, modm_m[0], q3.m[0]);
		r2.m[0] = cv.lo128(c) & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_m[0], q3.m[1]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_m[1], q3.m[0]); cv.add128(c, mul);
		r2.m[1] = cv.lo128(c) & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_m[0], q3.m[2]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_m[2], q3.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[1], q3.m[1]); cv.add128(c, mul);
		r2.m[2] = cv.lo128(c) & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_m[0], q3.m[3]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_m[3], q3.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[1], q3.m[2]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[2], q3.m[1]); cv.add128(c, mul);
		r2.m[3] = cv.lo128(c) & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, modm_m[0], q3.m[4]); cv.add128_64(c, f); cv.mul64x64_128(mul, modm_m[4], q3.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[3], q3.m[1]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[1], q3.m[3]); cv.add128(c, mul); cv.mul64x64_128(mul, modm_m[2], q3.m[2]); cv.add128(c, mul);
		r2.m[4] = cv.lo128(c) & 0x0000ffffffffffL;
		
		pb = 0;
		pb += r2.m[0]; b = lt_modm(r1.m[0], pb); r.m[0] = (r1.m[0] - pb + (b << 56)); pb = b;
		pb += r2.m[1]; b = lt_modm(r1.m[1], pb); r.m[1] = (r1.m[1] - pb + (b << 56)); pb = b;
		pb += r2.m[2]; b = lt_modm(r1.m[2], pb); r.m[2] = (r1.m[2] - pb + (b << 56)); pb = b;
		pb += r2.m[3]; b = lt_modm(r1.m[3], pb); r.m[3] = (r1.m[3] - pb + (b << 56)); pb = b;
		pb += r2.m[4]; b = lt_modm(r1.m[4], pb); r.m[4] = (r1.m[4] - pb + (b << 40));
		
		//printB256modm("r b256", r);
		reduce256_modm(r);
		reduce256_modm(r);
		//printB256modm("r b256", r);
	}
	
	public void	add256_modm(Bignum256modm r, Bignum256modm x, Bignum256modm y) {
		long c;
		
		c  = x.m[0] + y.m[0]; r.m[0] = c & 0xffffffffffffffL; c >>>= 56;
		c += x.m[1] + y.m[1]; r.m[1] = c & 0xffffffffffffffL; c >>>= 56;
		c += x.m[2] + y.m[2]; r.m[2] = c & 0xffffffffffffffL; c >>>= 56;
		c += x.m[3] + y.m[3]; r.m[3] = c & 0xffffffffffffffL; c >>>= 56;
		c += x.m[4] + y.m[4]; r.m[4] = c;
		
		reduce256_modm(r);
	}
	
	public void	mul256_modm(Bignum256modm r, Bignum256modm x, Bignum256modm y) {
		Bignum256modm q1 = new Bignum256modm();
		Bignum256modm r1 = new Bignum256modm();
		fp256 c = fp.zero();
		fp256 mul = fp.zero();
		long f;
		
		cv.mul64x64_128(c, x.m[0], y.m[0]);
		f = cv.lo128(c); r1.m[0] = f & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[0], y.m[1]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[1], y.m[0]); cv.add128(c, mul);
		f = cv.lo128(c); r1.m[1] = f & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[0], y.m[2]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[2], y.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[1], y.m[1]); cv.add128(c, mul);
		f = cv.lo128(c); r1.m[2] = f & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[0], y.m[3]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[3], y.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[1], y.m[2]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[2], y.m[1]); cv.add128(c, mul);
		f = cv.lo128(c); r1.m[3] = f & 0xffffffffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[0], y.m[4]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[4], y.m[0]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[3], y.m[1]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[1], y.m[3]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[2], y.m[2]); cv.add128(c, mul);
		f = cv.lo128(c); r1.m[4] = f & 0x0000ffffffffffL; q1.m[0] = (f >>> 24) & 0xffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[4], y.m[1]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[1], y.m[4]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[2], y.m[3]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[3], y.m[2]); cv.add128(c, mul);
		f = cv.lo128(c); q1.m[0] |= (f << 32) & 0xffffffffffffffL; q1.m[1] = (f >>> 24) & 0xffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[4], y.m[2]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[2], y.m[4]); cv.add128(c, mul); cv.mul64x64_128(mul, x.m[3], y.m[3]); cv.add128(c, mul);
		f = cv.lo128(c); q1.m[1] |= (f << 32) & 0xffffffffffffffL; q1.m[2] = (f >>> 24) & 0xffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[4], y.m[3]); cv.add128_64(c, f); cv.mul64x64_128(mul, x.m[3], y.m[4]); cv.add128(c, mul);
		f = cv.lo128(c); q1.m[2] |= (f << 32) & 0xffffffffffffffL; q1.m[3] = (f >>> 24) & 0xffffffffL; f = cv.shr128(c, 56);
		cv.mul64x64_128(c, x.m[4], y.m[4]); cv.add128_64(c, f);
		f = cv.lo128(c); q1.m[3] |= (f << 32) & 0xffffffffffffffL; q1.m[4] = (f >>> 24) & 0xffffffffL; f = cv.shr128(c, 56);
		q1.m[4] |= (f << 32);
		
		barrett_reduce256_modm(r, q1, r1);
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
		//System.out.print("x8 "); for (int i = 0; i < 8; i++) printLong(x[i]); System.out.println();
		
		
		/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */
		out.m[0] = (                         x[0]) & 0xffffffffffffffL;
		out.m[1] = ((x[ 0] >>> 56) | (x[ 1] <<  8)) & 0xffffffffffffffL;
		out.m[2] = ((x[ 1] >>> 48) | (x[ 2] << 16)) & 0xffffffffffffffL;
		out.m[3] = ((x[ 2] >>> 40) | (x[ 3] << 24)) & 0xffffffffffffffL;
		out.m[4] = ((x[ 3] >>> 32) | (x[ 4] << 32)) & 0x0000ffffffffffL;
		//printB256modm("exp no red", out);
		
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
		//printB256modm("q b256", out);
	}
	
	// unsigned char out[32]
	public void	contract256_modm(byte[] out, int idx, Bignum256modm in) {
		U64TO8_LE(out,  0+idx, (in.m[0]       ) | (in.m[1] << 56));
		U64TO8_LE(out,  8+idx, (in.m[1] >>>  8) | (in.m[2] << 48));
		U64TO8_LE(out, 16+idx, (in.m[2] >>> 16) | (in.m[3] << 40));
		U64TO8_LE(out, 24+idx, (in.m[3] >>> 24) | (in.m[4] << 32));
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
	
	
	
}
