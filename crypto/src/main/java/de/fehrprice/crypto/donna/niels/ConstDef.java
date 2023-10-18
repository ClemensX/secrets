package de.fehrprice.crypto.donna.niels;

public class ConstDef {
	/*
	 * multiples of the base point in packed {ysubx, xaddy, t2d} form.
	 * we have to read from multiple classes because full int table is too large for one class constant.
	 */
	public static byte[][] ge25519_niels_base_multiples;
	public ConstDef() {
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
