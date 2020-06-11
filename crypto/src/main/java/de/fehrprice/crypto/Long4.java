/**
 * 
 */
package de.fehrprice.crypto;

import java.math.BigInteger;
import java.util.Random;

/**
 * Fixed length numeric class for 256 bit unsigned arithmetics
 * All operations silently are modulo 256 bit
 *
 */
public class Long4 {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private long l0, l1, l2, l3; 
	private static BigInteger biMaxMask;

	static {
		// calculate max mask as 2 ^ 256 - 1
		BigInteger p = new BigInteger("2");
		biMaxMask = p.pow(256).subtract(BigInteger.ONE);
		System.out.println(biMaxMask.toString(16));
	}
	
	public Long4() {
		l0 = 0L; // MSB
		l1 = 0L;
		l2 = 0L;
		l3 = 0L;
	}

	public Long4(BigInteger big) {
		big = big.and(biMaxMask);
		var b = big.toByteArray(); // b[0] MSB
		l0 = toLong(b, 0);
		l1 = toLong(b, 8);
		l2 = toLong(b, 16);
		l3 = toLong(b, 24);
	}

	private long toLong(byte[] b, int startIndex) {
		byte[] b8 = new byte[8];
		int index = startIndex;
		for (int i = 0; i < 8; i++) {
			if (index + i < b.length)
				b8[i] = b[index + i];
			else
				b8[i] = 0;
		}
		return toLong(b8);
	}

	/**
	 * convert 8 consecutive bytes from an array to long
	 * most significant byte assumed to be in first position
	 * @param b
	 * @return
	 */
	private long toLong(byte[] b) {
		long l = ((long) b[0] << 56)
			       | ((long) b[1] & 0xff) << 48
			       | ((long) b[2] & 0xff) << 40
			       | ((long) b[3] & 0xff) << 32
			       | ((long) b[4] & 0xff) << 24
			       | ((long) b[5] & 0xff) << 16
			       | ((long) b[6] & 0xff) << 8
			       | ((long) b[7] & 0xff);	
		return l;
	}
}
