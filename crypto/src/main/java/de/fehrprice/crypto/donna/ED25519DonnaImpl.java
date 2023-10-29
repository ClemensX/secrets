package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.Long4;
import de.fehrprice.crypto.donna.niels.Bignum25519;
import de.fehrprice.crypto.donna.niels.ge25519;
import de.fehrprice.crypto.donna.niels.ge25519_niels;
import de.fehrprice.crypto.donna.niels.ge25519_p1p1;

public class ED25519DonnaImpl {
	
	private final ED25519 ed25519;
	private final Curve25519 curve25519;
	private final Modm modm;
	
	
	public ED25519DonnaImpl(ED25519 ed25519, Curve25519 curve25519, Modm modm) {
		this.ed25519 = ed25519;
		this.curve25519 = curve25519;
		this.modm = modm;
	}
	
	public static final Bignum25519 ge25519_ecd = new Bignum25519(0x00034dca135978a3L,0x0001a8283b156ebdL,
			0x0005e7a26001c029L,0x000739c663a03cbbL,0x00052036cee2b6ffL);
	
	/*
		conversions
	*/
	
	public void p1p1_to_partial(ge25519 r, ge25519_p1p1 p) {
		curve25519.mul(r.x, p.x, p.t);
		curve25519.mul(r.y, p.y, p.z);
		curve25519.mul(r.z, p.z, p.t);
	}
	
	public void p1p1_to_full(ge25519 r, ge25519_p1p1 p) {
		curve25519.mul(r.x, p.x, p.t);
		curve25519.mul(r.y, p.y, p.z);
		curve25519.mul(r.z, p.z, p.t);
		curve25519.mul(r.t, p.x, p.y);
	}

	
	/*
		adding & doubling
	*/
	
	public void double_p1p1(ge25519 r, ge25519 p) {
		Bignum25519 a = new Bignum25519();
		Bignum25519 b = new Bignum25519();
		Bignum25519 c = new Bignum25519();
		
		curve25519.square(a, p.x);
		curve25519.square(b, p.y);
		curve25519.square(c, p.z);
		curve25519.add_reduce(c, c, c);
		curve25519.add(r.x, p.x, p.y);
		curve25519.square(r.x, r.x);
		curve25519.add(r.y, b, a);
		curve25519.sub(r.z, b, a);
		curve25519.sub_after_basic(r.x, r.x, r.y);
		curve25519.sub_after_basic(r.t, c, r.z);
	}
	
	public void double_partial(ge25519 r, ge25519 p) {
		ge25519_p1p1 t = new ge25519_p1p1();
		double_p1p1(t, p);
		p1p1_to_partial(r, t);
	}
	
	public void nielsadd2(ge25519 r, ge25519_niels q) {
		Bignum25519 a = new Bignum25519();
		Bignum25519 b = new Bignum25519();
		Bignum25519 c = new Bignum25519();
		Bignum25519 d = new Bignum25519();
		Bignum25519 e = new Bignum25519();
		Bignum25519 f = new Bignum25519();
		Bignum25519 g = new Bignum25519();
		Bignum25519 h = new Bignum25519();
		
		curve25519.sub(a, r.y, r.x);
		curve25519.add(b, r.y, r.x);
		curve25519.mul(a, a, q.ysubx);
		curve25519.mul(e, b, q.xaddy);
		curve25519.add(h, e, a);
		curve25519.sub(e, e, a);
		curve25519.mul(c, r.t, q.t2d);
		curve25519.add(f, r.z, r.z);
		curve25519.add_after_basic(g, f, c);
		curve25519.sub_after_basic(f, f, c);
		curve25519.mul(r.x, e, f);
		curve25519.mul(r.y, h, g);
		curve25519.mul(r.z, g, f);
		curve25519.mul(r.t, e, h);
	}

	/*
		pack & unpack
	*/
	
	public void pack(byte r[], ge25519 p) {
		Bignum25519 tx = new Bignum25519();
		Bignum25519 ty = new Bignum25519();
		Bignum25519 zi = new Bignum25519();
		byte[] parity = new byte[32];
		curve25519.recip(zi, p.z);
		//printBig("zi", zi);
		curve25519.mul(tx, p.x, zi);
		curve25519.mul(ty, p.y, zi);
		//printBig("ty", ty);
		curve25519.contract(r, ty);
		curve25519.contract(parity, tx);
		r[31] ^= ((parity[0] & 1) << 7);
	}
	
	// unsigned char r[32]
	static byte[] zero = new byte[32];
	static Bignum25519 one = new Bignum25519(1L,0L, 0L,0L, 0L);
	
	// const unsigned char p[32]
	public int unpack_negative_vartime(ge25519 r, byte[] p) {
		byte parity = (byte) (p[31] >>> 7);
		byte[] check = new byte[32];
		Bignum25519 t = new Bignum25519();
		Bignum25519 root = new Bignum25519();
		Bignum25519 num = new Bignum25519();
		Bignum25519 den = new Bignum25519();
		Bignum25519 d3 = new Bignum25519();
		
		curve25519.expand(r.y, p, 0);
		curve25519.copy(r.z, one);
		curve25519.square(num, r.y); /* x = y^2 */
		curve25519.mul(den, num, ge25519_ecd); /* den = dy^2 */
		curve25519.sub_reduce(num, num, r.z); /* x = y^1 - 1 */
		curve25519.add(den, den, r.z); /* den = dy^2 + 1 */
		
		/* Computation of sqrt(num/den) */
		/* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */
		curve25519.square(t, den);
		curve25519.mul(d3, t, den);
		curve25519.square(r.x, d3);
		curve25519.mul(r.x, r.x, den);
		curve25519.mul(r.x, r.x, num);
		//pow_two252m3(r.x, r.x);
//
//		/* 2. computation of r->x = num * den^3 * (num*den^7)^((p-5)/8) */
//		curve25519_mul(r->x, r->x, d3);
//		curve25519_mul(r->x, r->x, num);
//
//		/* 3. Check if either of the roots works: */
//		curve25519_square(t, r->x);
//		curve25519_mul(t, t, den);
//		curve25519_sub_reduce(root, t, num);
//		curve25519_contract(check, root);
//		if (!ed25519_verify(check, zero, 32)) {
//			curve25519_add_reduce(t, t, num);
//			curve25519_contract(check, t);
//			if (!ed25519_verify(check, zero, 32))
//				return 0;
//			curve25519_mul(r->x, r->x, ge25519_sqrtneg1);
//		}
//
//		curve25519_contract(check, r->x);
//		if ((check[0] & 1) == parity) {
//			curve25519_copy(t, r->x);
//			curve25519_neg(r->x, t);
//		}
//		curve25519_mul(r->t, r->x, r->y);
		return 1;
	}
	
	private Long4 long4 = new Long4();
	
	private int
	windowb_equal(int b, int c) {
		return ((b ^ c) - 1) >>> 31;
	}
	
	private void scalarmult_base_choose_niels(ge25519_niels t, byte[][] table, int pos, byte b) {
		//System.out.printf("b %02x\n", b);
		Bignum25519 neg = new Bignum25519();
		int sign = (int)(((b & 0xff) >>> 7) & 0xff);
		//System.out.printf("sign %08x\n", sign);
		int mask = ~(sign - 1);
		//System.out.printf("mask %08x\n", mask);
		int u = (b + mask) ^ mask;
		//System.out.printf("u %08x\n", u);
		int i;
		
		/* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
		byte packed[] = new byte[96];
		packed[0] = 1;
		packed[32] = 1;
		
		for (i = 0; i < 8; i++) {
			move_conditional_bytes(packed, table[(pos * 8) + i], windowb_equal(u, i + 1));
		}
		//print96("packed", packed);
		
		/* expand in to t */
		curve25519.expand(t.ysubx, packed, 0);
		//printBig("ysubx", t.ysubx);
		curve25519.expand(t.xaddy, packed, 32);
		//printBig("xaddy", t.xaddy);
		curve25519.expand(t.t2d  , packed, 64);
		//printBig("t2d", t.t2d);
		//exit(0);
		
		/* adjust for sign */
		curve25519.swap_conditional(t.ysubx, t.xaddy, sign);
		curve25519.neg(neg, t.t2d);
		curve25519.swap_conditional(t.t2d, neg, sign);
		//printBig("ysubx", t.ysubx);
		//printBig("xaddy", t.xaddy);
		//printBig("t2d", t.t2d);
	}
	
	/* computes [s]basepoint */
	public void scalarmult_base_niels(ge25519 r, byte[][] basepoint_table, Bignum256modm s) {
		byte b[] = new byte[64];
		int i;
		ge25519_niels t = new ge25519_niels();
		
		modm.contract256_window4_modm(b, s);
		//print64("b", b);
		
		scalarmult_base_choose_niels(t, basepoint_table, 0, b[1]);
		
		curve25519.sub_reduce(r.x, t.xaddy, t.ysubx);
		//printBig("sub_red r.x", r.x);
		curve25519.add_reduce(r.y, t.xaddy, t.ysubx);
		//printBig("add_red r.x", r.y);
		r.z = new Bignum25519();
		curve25519.copy(r.t, t.t2d);
		r.z.m[0] = 2;
		//printBig("r.z", r.z);
		
		for (i = 3; i < 64; i += 2) {
			scalarmult_base_choose_niels(t, basepoint_table, i / 2, b[i]);
			nielsadd2(r, t);
		}
		double_partial(r, r);
		double_partial(r, r);
		double_partial(r, r);
		double_(r, r);
		scalarmult_base_choose_niels(t, basepoint_table, 0, b[0]);
		curve25519.mul(t.t2d, t.t2d, ge25519_ecd);
		
		nielsadd2(r, t);
		for(i = 2; i < 64; i += 2) {
			scalarmult_base_choose_niels(t, basepoint_table, i / 2, b[i]);
			nielsadd2(r, t);
		}
		
	}
	
	
	
	/**
	 * Convert big-endian byte array to long array.
	 * for each censcutive 8 bytes in byte array: MSB byte at lowest index
	 * @param to long[12]
	 * @param from byte[96]
	 */
	private void toLong(long[] to, byte[] from) {
		for (int i = 0; i  < 12; i++) {
			to[i] = long4.toLong(from, i * 8);
		}
	}
	
	void toByte(byte[] to, long from, int index) {
		to[index+0] = (byte) (from >> 0);
		to[index+1] = (byte) (from >> 8);
		to[index+2] = (byte) (from >> 16);
		to[index+3] = (byte) (from >> 24);
		to[index+4] = (byte) (from >> 32);
		to[index+5] = (byte) (from >> 40);
		to[index+6] = (byte) (from >> 48);
		to[index+7] = (byte) (from >> 56);
	}
	void toByte(byte[] to, long[] from) {
		for (int i = 0; i  < 12; i++) {
			toByte(to, from[i], i*8);
		}
	}
	/**
	 * @param out
	 * @param in
	 * @param flag
	 */
	private void move_conditional_bytes(byte out[], byte in[], long flag) {
		long nb = flag - 1, b = ~nb;
		long[] inq = new long[12];//(const uint64_t *)in;
		long[] outl = new long[12];
		toLong(inq, in);
		toLong(outl, out);
		//uint64_t *outq = (uint64_t *)out;
		outl[0] = (outl[0] & nb) | (inq[0] & b);
		outl[1] = (outl[1] & nb) | (inq[1] & b);
		outl[2] = (outl[2] & nb) | (inq[2] & b);
		outl[3] = (outl[3] & nb) | (inq[3] & b);
		outl[4] = (outl[4] & nb) | (inq[4] & b);
		outl[5] = (outl[5] & nb) | (inq[5] & b);
		outl[6] = (outl[6] & nb) | (inq[6] & b);
		outl[7] = (outl[7] & nb) | (inq[7] & b);
		outl[8] = (outl[8] & nb) | (inq[8] & b);
		outl[9] = (outl[9] & nb) | (inq[9] & b);
		outl[10] = (outl[10] & nb) | (inq[10] & b);
		outl[11] = (outl[11] & nb) | (inq[11] & b);
		toByte(out, outl);
	}
	
	
	public void double_(ge25519 r, ge25519 p) {
		ge25519_p1p1 t = new ge25519_p1p1();
		double_p1p1(t, p);
		p1p1_to_full(r, t);
	}
	
	
	
}
