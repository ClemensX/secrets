package de.fehrprice.crypto.donna.niels;

import de.fehrprice.crypto.donna.Bignum256modm;

public class ge25519 {
	
	public Bignum25519 x = new Bignum25519();
	public Bignum25519 y = new Bignum25519();
	public Bignum25519 z = new Bignum25519();
	public Bignum25519 t = new Bignum25519();
	
	
	public void memsetZero() {
		x.memsetZero();
		y.memsetZero();
		z.memsetZero();
		t.memsetZero();
	}
}
