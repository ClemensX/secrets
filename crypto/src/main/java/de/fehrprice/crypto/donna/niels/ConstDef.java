package de.fehrprice.crypto.donna.niels;

public class ConstDef {
	/*
	 * multiples of the base point in packed {ysubx, xaddy, t2d} form.
	 * we have to read from multiple classes because full int table is too large for one class constant.
	 */
	public static byte[][] ge25519_niels_base_multiples;
	public static ge25519_niels[] ge25519_niels_sliding_multiples;

	private Bignum25519 getBignum(int i, int j) {
		Bignum25519 b = new Bignum25519(CSlidingMultiples.nlm[i][j][0], CSlidingMultiples.nlm[i][j][1], CSlidingMultiples.nlm[i][j][2], CSlidingMultiples.nlm[i][j][3], CSlidingMultiples.nlm[i][j][4]);
		return b;
	}
	public ConstDef() {
		// create ge25519_niels_sliding_multiples from CSlidingMultiples:
		//System.out.println("length: " + CSlidingMultiples.nlm.length);
		//System.out.println("length []: " + CSlidingMultiples.nlm[0].length);
		//System.out.println("length [][]: " + CSlidingMultiples.nlm[0][0].length);
		ge25519_niels_sliding_multiples = new ge25519_niels[32];
		for (int i = 0; i < 32; i++) {
			ge25519_niels ge = new ge25519_niels();
			ge.ysubx = getBignum(i, 0);
			ge.xaddy = getBignum(i, 1);
			ge.t2d = getBignum(i, 2);
			ge25519_niels_sliding_multiples[i] = ge;
		}
		
		// assemble ge25519_niels_base_multiples table:
		ge25519_niels_base_multiples = new byte[256][96];
		for (int outer = 0; outer < 100; outer++) {
			for (int inner = 0; inner < 96; inner++) {
				ge25519_niels_base_multiples[outer][inner] = (byte) C0.a[outer][inner];
			}
		}
		for (int outer = 100; outer < 200; outer++) {
			for (int inner = 0; inner < 96; inner++) {
				ge25519_niels_base_multiples[outer][inner] = (byte) C1.a[outer-100][inner];
			}
		}
		for (int outer = 200; outer < 256; outer++) {
			for (int inner = 0; inner < 96; inner++) {
				ge25519_niels_base_multiples[outer][inner] = (byte) C2.a[outer-200][inner];
			}
		}
	}
};
