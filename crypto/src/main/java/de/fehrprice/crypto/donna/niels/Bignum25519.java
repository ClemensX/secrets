package de.fehrprice.crypto.donna.niels;

import de.fehrprice.crypto.donna.Bignum256modm;

public class Bignum25519 extends Bignum256modm {
	
	public Bignum25519(long l, long l1, long l2, long l3, long l4) {
		super();
		m[0] = l;
		m[1] = l1;
		m[2] = l2;
		m[3] = l3;
		m[4] = l4;
	}
	public Bignum25519(Bignum25519 c) {
		this(c.m[0], c.m[1], c.m[2], c.m[3], c.m[4]);
	}
	
	public Bignum25519() {
		super();
	}
	
	public void memsetZero() {
		m[4] = m[3] = m[2] = m[1] = m[0] = 0L;
	}
}
