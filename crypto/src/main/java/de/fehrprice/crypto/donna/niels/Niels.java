package de.fehrprice.crypto.donna.niels;

import java.util.Arrays;
import java.util.Collections;

import de.fehrprice.crypto.Long4;
import de.fehrprice.crypto.donna.Bignum256modm;
import de.fehrprice.crypto.donna.ED25519;
import de.fehrprice.crypto.edu25519.Field;
import de.fehrprice.crypto.edu25519.Serialize;

import static de.fehrprice.crypto.donna.ED25519.contract256_window4_modm;
import static de.fehrprice.crypto.donna.ED25519.print64;
import static de.fehrprice.crypto.donna.ED25519.print96;
import static de.fehrprice.crypto.donna.ED25519.printBig;

public class Niels {
	
	/*
	 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
	 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
	 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
	 */
	
	//private ED25519 ed25519 = new ED25519();
	private Long4 long4 = new Long4();
	private int
	windowb_equal(int b, int c) {
		return ((b ^ c) - 1) >>> 31;
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
	
	private void scalarmult_base_choose_niels(ge25519_niels t, byte[][] table, int pos, byte b) {
		System.out.printf("b %02x\n", b);
		Bignum25519 neg = new Bignum25519();
		int sign = (int)(((b & 0xff) >>> 7) & 0xff);
		System.out.printf("sign %08x\n", sign);
		int mask = ~(sign - 1);
		System.out.printf("mask %08x\n", mask);
		int u = (b + mask) ^ mask;
		System.out.printf("u %08x\n", u);
		int i;
		
		/* ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0 */
		byte packed[] = new byte[96];
		packed[0] = 1;
		packed[32] = 1;
		
		for (i = 0; i < 8; i++) {
			move_conditional_bytes(packed, table[(pos * 8) + i], windowb_equal(u, i + 1));
		}
		print96("packed", packed);
		
		/* expand in to t */
		expand(t.ysubx, packed, 0);
		//printBig("ysubx", t.ysubx);
		expand(t.xaddy, packed, 32);
		//printBig("xaddy", t.xaddy);
		expand(t.t2d  , packed, 64);
		//printBig("t2d", t.t2d);
		//exit(0);
		
		/* adjust for sign */
		ED25519.swap_conditional(t.ysubx, t.xaddy, sign);
		ED25519.neg(neg, t.t2d);
		ED25519.swap_conditional(t.t2d, neg, sign);
		printBig("ysubx", t.ysubx);
		printBig("xaddy", t.xaddy);
		printBig("t2d", t.t2d);
	}
	
	
	private void expand(Bignum25519 out, byte[] in, int i) {
		Field.s64Array fa = new Field.s64Array();
		byte[] b = new byte[32];
		System.arraycopy(in, i, b, 0, 32);
		//Serialize.deserialize(fa, b);
		// TODO: use ED25519.expand256_modm() !!!
		//ED25519 ed25519 = new ED25519();
		//Collections.reverse(Arrays.asList(b));
		ED25519.expand32(out, b);
		//System.arraycopy(fa.it, 0, out.m, 0, 5);
	}
	
	
	/* computes [s]basepoint */
	public void scalarmult_base_niels(ge25519 r, byte[][] basepoint_table, Bignum256modm s) {
		byte b[] = new byte[64];
		int i;
		ge25519_niels t = new ge25519_niels();
		
		contract256_window4_modm(b, s);
		print64("b", b);
		
		scalarmult_base_choose_niels(t, basepoint_table, 0, b[1]);
	}
	
	
}
