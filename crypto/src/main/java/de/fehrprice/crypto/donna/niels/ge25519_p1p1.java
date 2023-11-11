package de.fehrprice.crypto.donna.niels;

public class ge25519_p1p1 extends ge25519{
	public Bignum25519 viaIndex(int i) {
		switch (i) {
			case 0 -> {
				return x;
			}
			case 1 -> {
				return y;
			}
			case 2 -> {
				return z;
			}
			case 3 -> {
				return t;
			}
		}
		throw new IllegalArgumentException("invalid index used for ge25519_p1p1.viaIndex()");
	}
}
