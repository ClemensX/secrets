package de.fehrprice.crypto.donna.niels;

public class ge25519_pniels {
	
	public Bignum25519 ysubx = new Bignum25519();
	public Bignum25519 xaddy = new Bignum25519();
	public Bignum25519 z = new Bignum25519();
	public Bignum25519 t2d = new Bignum25519();
	public Bignum25519 viaIndex(int i) {
		switch (i) {
			case 0 -> {
				return ysubx;
			}
			case 1 -> {
				return xaddy;
			}
			case 2 -> {
				return z;
			}
			case 3 -> {
				return t2d;
			}
		}
		throw new IllegalArgumentException("invalid index used for ge25519_pniels.viaIndex()");
	}
}
