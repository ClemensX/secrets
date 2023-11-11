package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.FixedPointOp;
import de.fehrprice.crypto.donna.niels.Bignum25519;
import de.fehrprice.crypto.fp256;

/*
	Public domain by Adam Langley <agl@imperialviolet.org> &
	                 Andrew M. <liquidsun@gmail.com>
	See: https://github.com/floodyberry/curve25519-donna

	64bit integer curve25519 implementation
*/
public class Curve25519 {
	
	private FixedPointOp fp = new FixedPointOp();
	public static final long reduce_mask_51 = 0x0007ffffffffffffL;
	
	/* out = in */
	public static void copy(Bignum25519 out, Bignum25519 in) {
		System.arraycopy(in.m, 0, out.m, 0, 5);
	}
	
	/* out = a + b */
	public void add(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		out.m[0] = a.m[0] + b.m[0];
		out.m[1] = a.m[1] + b.m[1];
		out.m[2] = a.m[2] + b.m[2];
		out.m[3] = a.m[3] + b.m[3];
		out.m[4] = a.m[4] + b.m[4];
	}
	
	/* out = a + b, where a and/or b are the result of a basic op (add,sub) */
	public void add_after_basic(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		// TODO no diff to add() ?
		out.m[0] = a.m[0] + b.m[0];
		out.m[1] = a.m[1] + b.m[1];
		out.m[2] = a.m[2] + b.m[2];
		out.m[3] = a.m[3] + b.m[3];
		out.m[4] = a.m[4] + b.m[4];
	}
	
	public static void add_reduce(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		long c;
		out.m[0] = a.m[0] + b.m[0]    ; c = (out.m[0] >>> 51); out.m[0] &= reduce_mask_51;
		out.m[1] = a.m[1] + b.m[1] + c; c = (out.m[1] >>> 51); out.m[1] &= reduce_mask_51;
		out.m[2] = a.m[2] + b.m[2] + c; c = (out.m[2] >>> 51); out.m[2] &= reduce_mask_51;
		out.m[3] = a.m[3] + b.m[3] + c; c = (out.m[3] >>> 51); out.m[3] &= reduce_mask_51;
		out.m[4] = a.m[4] + b.m[4] + c; c = (out.m[4] >>> 51); out.m[4] &= reduce_mask_51;
		out.m[0] += c * 19;
	}
	
	/* multiples of p */
	public static final long twoP0      = 0x0fffffffffffdaL;
	public static final long twoP1234   = 0x0ffffffffffffeL;
	public static final long fourP0     = 0x1fffffffffffb4L;
	public static final long fourP1234  = 0x1ffffffffffffcL;
	
	/* out = a - b */
	public void sub(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		out.m[0] = a.m[0] + twoP0    - b.m[0];
		out.m[1] = a.m[1] + twoP1234 - b.m[1];
		out.m[2] = a.m[2] + twoP1234 - b.m[2];
		out.m[3] = a.m[3] + twoP1234 - b.m[3];
		out.m[4] = a.m[4] + twoP1234 - b.m[4];
	}
	
	/* out = a - b, where a and/or b are the result of a basic op (add,sub) */
	public void sub_after_basic(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		out.m[0] = a.m[0] + fourP0    - b.m[0];
		out.m[1] = a.m[1] + fourP1234 - b.m[1];
		out.m[2] = a.m[2] + fourP1234 - b.m[2];
		out.m[3] = a.m[3] + fourP1234 - b.m[3];
		out.m[4] = a.m[4] + fourP1234 - b.m[4];
	}
	
	public static void sub_reduce(Bignum25519 out, Bignum25519 a, Bignum25519 b) {
		long c;
		out.m[0] = a.m[0] + fourP0    - b.m[0]    ; c = (out.m[0] >>> 51); out.m[0] &= reduce_mask_51;
		out.m[1] = a.m[1] + fourP1234 - b.m[1] + c; c = (out.m[1] >>> 51); out.m[1] &= reduce_mask_51;
		out.m[2] = a.m[2] + fourP1234 - b.m[2] + c; c = (out.m[2] >>> 51); out.m[2] &= reduce_mask_51;
		out.m[3] = a.m[3] + fourP1234 - b.m[3] + c; c = (out.m[3] >>> 51); out.m[3] &= reduce_mask_51;
		out.m[4] = a.m[4] + fourP1234 - b.m[4] + c; c = (out.m[4] >>> 51); out.m[4] &= reduce_mask_51;
		out.m[0] += c * 19;
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
	
	/* out = a * b */
	public void mul(Bignum25519 out, Bignum25519 in2, Bignum25519 in) {
		fp256 t[] = new fp256[5];
		FixedPointOp fp = new FixedPointOp();
		for (int i = 0; i < 5; i++)
			t[i] = fp.zero();
		//fp256 c = fp.zero();
		fp256 mul = fp.zero();
		
		long r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;
		
		r0 = in.m[0];
		r1 = in.m[1];
		r2 = in.m[2];
		r3 = in.m[3];
		r4 = in.m[4];
		
		s0 = in2.m[0];
		s1 = in2.m[1];
		s2 = in2.m[2];
		s3 = in2.m[3];
		s4 = in2.m[4];
		
		mul64x64_128(t[0], r0, s0);
		mul64x64_128(t[1], r0, s1); mul64x64_128(mul, r1, s0); add128(t[1], mul);
		mul64x64_128(t[2], r0, s2); mul64x64_128(mul, r2, s0); add128(t[2], mul); mul64x64_128(mul, r1, s1); add128(t[2], mul);
		mul64x64_128(t[3], r0, s3); mul64x64_128(mul, r3, s0); add128(t[3], mul); mul64x64_128(mul, r1, s2); add128(t[3], mul); mul64x64_128(mul, r2, s1); add128(t[3], mul);
		mul64x64_128(t[4], r0, s4); mul64x64_128(mul, r4, s0); add128(t[4], mul); mul64x64_128(mul, r3, s1); add128(t[4], mul); mul64x64_128(mul, r1, s3); add128(t[4], mul); mul64x64_128(mul, r2, s2); add128(t[4], mul);
		
		r1 *= 19;
		r2 *= 19;
		r3 *= 19;
		r4 *= 19;
		
		mul64x64_128(mul, r4, s1); add128(t[0], mul); mul64x64_128(mul, r1, s4); add128(t[0], mul); mul64x64_128(mul, r2, s3); add128(t[0], mul); mul64x64_128(mul, r3, s2); add128(t[0], mul);
		mul64x64_128(mul, r4, s2); add128(t[1], mul); mul64x64_128(mul, r2, s4); add128(t[1], mul); mul64x64_128(mul, r3, s3); add128(t[1], mul);
		mul64x64_128(mul, r4, s3); add128(t[2], mul); mul64x64_128(mul, r3, s4); add128(t[2], mul);
		mul64x64_128(mul, r4, s4); add128(t[3], mul);
		
		
		r0 = lo128(t[0]) & reduce_mask_51; c = shr128(t[0], 51);
		add128_64(t[1], c);   r1 = lo128(t[1]) & reduce_mask_51; c = shr128(t[1], 51);
		add128_64(t[2], c);   r2 = lo128(t[2]) & reduce_mask_51; c = shr128(t[2], 51);
		add128_64(t[3], c);   r3 = lo128(t[3]) & reduce_mask_51; c = shr128(t[3], 51);
		add128_64(t[4], c);   r4 = lo128(t[4]) & reduce_mask_51; c = shr128(t[4], 51);
		r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
		r1 +=   c;
		
		out.m[0] = r0;
		out.m[1] = r1;
		out.m[2] = r2;
		out.m[3] = r3;
		out.m[4] = r4;
	}
	
	/* out = in^(2 * count) */
	public void square_times(Bignum25519 out, Bignum25519 in, long count) {
		fp256 t[] = new fp256[5];
		FixedPointOp fp = new FixedPointOp();
		for (int i = 0; i < 5; i++)
			t[i] = fp.zero();
		fp256 mul = fp.zero();
		
		long r0,r1,r2,r3,r4,d0,d1,d2,d419,d4,c;
		
		r0 = in.m[0];
		r1 = in.m[1];
		r2 = in.m[2];
		r3 = in.m[3];
		r4 = in.m[4];
		do {
			d0 = r0 * 2;
			d1 = r1 * 2;
			d2 = r2 * 2 * 19;
			d419 = r4 * 19;
			d4 = d419 * 2;
			
			mul64x64_128(t[0], r0, r0); mul64x64_128(mul, d4, r1); add128(t[0], mul); mul64x64_128(mul, d2,      r3); add128(t[0], mul);
			mul64x64_128(t[1], d0, r1); mul64x64_128(mul, d4, r2); add128(t[1], mul); mul64x64_128(mul, r3, r3 * 19); add128(t[1], mul);
			mul64x64_128(t[2], d0, r2); mul64x64_128(mul, r1, r1); add128(t[2], mul); mul64x64_128(mul, d4,      r3); add128(t[2], mul);
			mul64x64_128(t[3], d0, r3); mul64x64_128(mul, d1, r2); add128(t[3], mul); mul64x64_128(mul, r4,    d419); add128(t[3], mul);
			mul64x64_128(t[4], d0, r4); mul64x64_128(mul, d1, r3); add128(t[4], mul); mul64x64_128(mul, r2,      r2); add128(t[4], mul);
			
			r0 = lo128(t[0]) & reduce_mask_51;
			r1 = lo128(t[1]) & reduce_mask_51; c = shl128(t[0], 13); r1 += c;
//			print64t("c", c);
//			print64t("r0", r0);
//			print64t("r1", r1);
			r2 = lo128(t[2]) & reduce_mask_51; c = shl128(t[1], 13); r2 += c;
			r3 = lo128(t[3]) & reduce_mask_51; c = shl128(t[2], 13); r3 += c;
			r4 = lo128(t[4]) & reduce_mask_51; c = shl128(t[3], 13); r4 += c;
			c = shl128(t[4], 13); r0 += c * 19;
			c = r0 >>> 51; r0 &= reduce_mask_51;
			r1 += c     ;  c = r1 >>> 51; r1 &= reduce_mask_51;
			r2 += c     ;  c = r2 >>> 51; r2 &= reduce_mask_51;
			r3 += c     ;  c = r3 >>> 51; r3 &= reduce_mask_51;
			r4 += c     ;  c = r4 >>> 51; r4 &= reduce_mask_51;
			r0 += c * 19;
//			print64t("r0", r0);
//			print64t("r1", r1);
//			print64t("r2", r2);
//			print64t("r3", r3);
//			print64t("r4", r4);
			//System.exit(0);
		} while (--count > 0);
		out.m[0] = r0;
		out.m[1] = r1;
		out.m[2] = r2;
		out.m[3] = r3;
		out.m[4] = r4;
	}
	
	public void square(Bignum25519 out, Bignum25519 in) {
		fp256 t[] = new fp256[5];
		FixedPointOp fp = new FixedPointOp();
		for (int i = 0; i < 5; i++)
			t[i] = fp.zero();
		fp256 mul = fp.zero();
		
		long r0,r1,r2,r3,r4,d0,d1,d2,d419,d4,c;
		
		r0 = in.m[0];
		r1 = in.m[1];
		r2 = in.m[2];
		r3 = in.m[3];
		r4 = in.m[4];
		
		d0 = r0 * 2;
		d1 = r1 * 2;
		d2 = r2 * 2 * 19;
		d419 = r4 * 19;
		d4 = d419 * 2;
		
		mul64x64_128(t[0], r0, r0); mul64x64_128(mul, d4, r1); add128(t[0], mul); mul64x64_128(mul, d2,      r3); add128(t[0], mul);
		mul64x64_128(t[1], d0, r1); mul64x64_128(mul, d4, r2); add128(t[1], mul); mul64x64_128(mul, r3, r3 * 19); add128(t[1], mul);
		mul64x64_128(t[2], d0, r2); mul64x64_128(mul, r1, r1); add128(t[2], mul); mul64x64_128(mul, d4,      r3); add128(t[2], mul);
		mul64x64_128(t[3], d0, r3); mul64x64_128(mul, d1, r2); add128(t[3], mul); mul64x64_128(mul, r4,    d419); add128(t[3], mul);
		mul64x64_128(t[4], d0, r4); mul64x64_128(mul, d1, r3); add128(t[4], mul); mul64x64_128(mul, r2,      r2); add128(t[4], mul);
		
		r0 = lo128(t[0]) & reduce_mask_51; c = shr128(t[0], 51);
		add128_64(t[1], c);   r1 = lo128(t[1]) & reduce_mask_51; c = shr128(t[1], 51);
		add128_64(t[2], c);   r2 = lo128(t[2]) & reduce_mask_51; c = shr128(t[2], 51);
		add128_64(t[3], c);   r3 = lo128(t[3]) & reduce_mask_51; c = shr128(t[3], 51);
		add128_64(t[4], c);   r4 = lo128(t[4]) & reduce_mask_51; c = shr128(t[4], 51);
		r0 +=   c * 19; c = r0 >> 51; r0 = r0 & reduce_mask_51;
		r1 +=   c;
		
		out.m[0] = r0;
		out.m[1] = r1;
		out.m[2] = r2;
		out.m[3] = r3;
		out.m[4] = r4;
	}
	
	public void expand(Bignum25519 out, byte[] in, int i) {
		byte[] b = new byte[32];
		System.arraycopy(in, i, b, 0, 32);
		expand32(out, b);
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
	
	private void contract_carry(long[] t) {
		t[1] += t[0] >>> 51; t[0] &= reduce_mask_51;
		t[2] += t[1] >>> 51; t[1] &= reduce_mask_51;
		t[3] += t[2] >>> 51; t[2] &= reduce_mask_51;
		t[4] += t[3] >>> 51; t[3] &= reduce_mask_51;
	}
	
	private void contract_carry_full(long[] t) {
		contract_carry(t);
		t[0] += 19 * (t[4] >>> 51); t[4] &= reduce_mask_51;
	}
	
	private void contract_carry_final(long[] t) {
		contract_carry(t);
		t[4] &= reduce_mask_51;
	}
	
	private int write51full(byte[] out, int outidx, long[] t, int n, int shift) {
		long f = ((t[n] >>> shift) | (t[n+1] << (51 - shift)));
		for (int i = 0; i < 8; i++, f >>>= 8) out[outidx++] = (byte)f;
		return outidx;
	}
	
	private int write51(byte[] out, int outidx, long[] t, int n) {
		return write51full(out, outidx, t,n,13*n);
	}
	
	/* Take a fully reduced polynomial form number and contract it into a
	 * little-endian, 32-byte array
	 */
	public void contract(byte[] out, Bignum25519 input) {
		long[] t = new long[5];
		long f, i;
		
		t[0] = input.m[0];
		t[1] = input.m[1];
		t[2] = input.m[2];
		t[3] = input.m[3];
		t[4] = input.m[4];
		
		contract_carry_full(t);
		contract_carry_full(t);
		
		/* now t is between 0 and 2^255-1, properly carried. */
		/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
		t[0] += 19;
		contract_carry_full(t);
		
		/* now between 19 and 2^255-1 in both cases, and offset by 19. */
		t[0] += (reduce_mask_51 + 1) - 19;
		t[1] += (reduce_mask_51 + 1) - 1;
		t[2] += (reduce_mask_51 + 1) - 1;
		t[3] += (reduce_mask_51 + 1) - 1;
		t[4] += (reduce_mask_51 + 1) - 1;
		
		/* now between 2^255 and 2^256-20, and offset by 2^255. */
		//print64t("t4 pre", t[4]);
		contract_carry_final(t);
		//print64t("t4 pos", t[4]);
		
		int outidx = 0;
		outidx = write51(out, outidx,t,0);
		outidx = write51(out, outidx,t,1);
		outidx = write51(out, outidx,t,2);
		outidx = write51(out, outidx,t,3);
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
	
	
	/*
		Public domain by Andrew M. <liquidsun@gmail.com>
		See: https://github.com/floodyberry/curve25519-donna
	
		Curve25519 implementation agnostic helpers
	*/
	
	/*
	 * In:  b =   2^5 - 2^0
	 * Out: b = 2^250 - 2^0
	 */
	public void pow_two5mtwo0_two250mtwo0(Bignum25519 b) {
		Bignum25519 t0 = new Bignum25519();
		Bignum25519 c = new Bignum25519();
		
		/* 2^5  - 2^0 */ /* b */
		/* 2^10 - 2^5 */ square_times(t0, b, 5);
		/* 2^10 - 2^0 */ mul(b, t0, b);
		/* 2^20 - 2^10 */ square_times(t0, b, 10);
		/* 2^20 - 2^0 */ mul(c, t0, b);
		/* 2^40 - 2^20 */ square_times(t0, c, 20);
		/* 2^40 - 2^0 */ mul(t0, t0, c);
		/* 2^50 - 2^10 */ square_times(t0, t0, 10);
		/* 2^50 - 2^0 */ mul(b, t0, b);
		/* 2^100 - 2^50 */ square_times(t0, b, 50);
		/* 2^100 - 2^0 */ mul(c, t0, b);
		/* 2^200 - 2^100 */ square_times(t0, c, 100);
		/* 2^200 - 2^0 */ mul(t0, t0, c);
		/* 2^250 - 2^50 */ square_times(t0, t0, 50);
		/* 2^250 - 2^0 */ mul(b, t0, b);
	}
	
	/*
	 * z^(p - 2) = z(2^255 - 21)
	 */
	public void recip(Bignum25519 out, Bignum25519 z) {
		Bignum25519 a = new Bignum25519();
		Bignum25519 t0 = new Bignum25519();
		Bignum25519 b = new Bignum25519();
		
		/* 2 */ square_times(a, z, 1); /* a = 2 */
		//printBig("a", a);
		/* 8 */ square_times(t0, a, 2);
		/* 9 */ mul(b, t0, z); /* b = 9 */
		/* 11 */ mul(a, b, a); /* a = 11 */
		/* 22 */ square_times(t0, a, 1);
		/* 2^5 - 2^0 = 31 */ mul(b, t0, b);
		/* 2^250 - 2^0 */ pow_two5mtwo0_two250mtwo0(b);
		/* 2^255 - 2^5 */ square_times(b, b, 5);
		/* 2^255 - 21 */ mul(out, b, a);
	}
	
	/*
	 * z^((p-5)/8) = z^(2^252 - 3)
	 */
	public void pow_two252m3(Bignum25519 two252m3, Bignum25519 z) {
		Bignum25519 c = new Bignum25519();
		Bignum25519 t0 = new Bignum25519();
		Bignum25519 b = new Bignum25519();
		
		/* 2 */ square_times(c, z, 1); /* c = 2 */
		/* 8 */ square_times(t0, c, 2); /* t0 = 8 */
		/* 9 */ mul(b, t0, z); /* b = 9 */
		/* 11 */ mul(c, b, c); /* c = 11 */
		/* 22 */ square_times(t0, c, 1);
		/* 2^5 - 2^0 = 31 */ mul(b, t0, b);
		/* 2^250 - 2^0 */ pow_two5mtwo0_two250mtwo0(b);
		/* 2^252 - 2^2 */ square_times(b, b, 2);
		/* 2^252 - 3 */ mul(two252m3, b, z);
	}
	
	// 128 bit support methods
	
	
	public long lo128(fp256 c) {
		return c.getInternalLongArray()[0];
	}
	
	
	public void add128_64(fp256 c, long f) {
		fp.add(c, c, fp.fromLong(f));
	}
	
	
	public long shr128(fp256 c, int op) {
		fp256 cn = fp.copy(c);
		for (int i = 0; i < op; i++) {
			fp.shiftRight1(cn);
		}
		return(lo128(cn));
	}
	
	
	public long shl128(fp256 c, int op) {
		fp256 cn = fp.copy(c);
		for (int i = 0; i < op; i++) {
			fp.shiftLeft1(cn);
		}
		// instead of >> 64 we can just use the 2nd long
		return(cn.getInternalLongArray()[1]);
	}
	
	
	public void add128(fp256 a, fp256 b) {
		fp.add(a, a, b);
	}
	
	
	public void mul64x64_128(fp256 c, long a, long b) {
		fp.umul64(c, a, b);
	}
	
	/**
	 * convert 8 consecutive bytes from an array to long
	 * least significant byte assumed to be in lowest index position
	 * @param b
	 * @param idx start index
	 * @return
	 */
	public static long U8TO64_LE(byte[] b, int idx) {
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
	
	
	/**
	 * convert long to 8 consecutive bytes in an array
	 * least significant byte assumed to be in lowest index position
	 * @param p
	 * @param idx start index
	 * @param v
	 * @return
	 */
	public static void U64TO8_LE(byte[] p, int idx, long v) {
		p[0+idx] = (byte)(v      );
		p[1+idx] = (byte)(v >>>  8);
		p[2+idx] = (byte)(v >>> 16);
		p[3+idx] = (byte)(v >>> 24);
		p[4+idx] = (byte)(v >>> 32);
		p[5+idx] = (byte)(v >>> 40);
		p[6+idx] = (byte)(v >>> 48);
		p[7+idx] = (byte)(v >>> 56);
	}
	
	
	
}
