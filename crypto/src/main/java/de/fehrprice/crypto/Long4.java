/**
 * 
 */
package de.fehrprice.crypto;

import java.math.BigInteger;
import java.util.Random;

/**
 * Fixed length numeric class for 256 bit unsigned arithmetics
 * All operations are silently modulo 256 bit. Useful to speed up cryptographic 
 * operations usually relying on BigInteger.
 * Intended Support for: multiply, inv, mod, subtract, divide, pow, testBit, modPow, negate, add, shiftRight, and, xor
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
		//System.out.println(biMaxMask.toString(16));
	}
	
	public Long4() {
		l0 = 0L; // MSB
		l1 = 0L;
		l2 = 0L;
		l3 = 0L;
	}

	/**
	 * Initialize Long4 with MSB at p0
	 * @param p0 MSB
	 * @param p1
	 * @param p2
	 * @param p3 LSB
	 */
	public Long4(long p0, long p1, long p2, long p3) {
		l0 = p0; // MSB
		l1 = p1;
		l2 = p2;
		l3 = p3;
	}

	/**
	 * Initialize with BigInteger.
	 * Negative BigIntegers will be treatet as unsigned by removing sign.
	 * @param big
	 */
	public Long4(BigInteger big) {
//		if (big.signum() < 0) {
//			big = twosComplement32(big);
//		}
		big = big.and(biMaxMask);
		var b = big.toByteArray(); // b[0] MSB
		b = extendTo32Reverse(b);
		l0 = toLong(b, 24);
		l1 = toLong(b, 16);
		l2 = toLong(b, 8);
		l3 = toLong(b, 0);
	}

//	public static BigInteger twosComplement32(BigInteger original)
//	{
//		return biMaxMask.add(original).add(BigInteger.ONE);
//	}
	
	/**
	 * Reverse order of arbitrary length byte array from BigInteger.toByteArray() and 
	 * put into 32 length byte array such that MSB is at highest index and unused higher indexes are 0.
	 * negative sign byte will be discarded to treat byte array as unsigned. 
	 * @param b
	 * @return 32 byte array with LSB at index 0
	 */
	private byte[] extendTo32Reverse(byte[] b) {
		// throw away potential sign byte at index 0:
		if (b.length > 32) {
			byte[] s = new byte[32];
			for (int i = 0; i < 32; i++) {
				s[i] = b[i+1];
			}
			b = s;
		}
		assert (b.length <= 32);
		byte[] n = new byte[32];
		for (int i = 0; i < b.length; i++) {
			n[i] = b[b.length-1-i];
		}
		return n;
	}

	/**
	 * Convert 8 bytes from an array to long. 
	 * Array has to have LSB at lowest index
	 * @param b
	 * @param startIndex
	 * @return
	 */
	private long toLong(byte[] b, int startIndex) {
		assert(b.length == 32);
		byte[] b8 = new byte[8];
		int index = startIndex;
		for (int i = 0; i < 8; i++) {
			b8[i] = b[index + i];
		}
		return toLong(b8);
	}

	/**
	 * convert 8 consecutive bytes from an array to long
	 * least significant byte assumed to be in lowest index position
	 * @param b
	 * @return
	 */
	private long toLong(byte[] b) {
		long l = ((long) b[7] << 56)
			       | ((long) b[6] & 0xff) << 48
			       | ((long) b[5] & 0xff) << 40
			       | ((long) b[4] & 0xff) << 32
			       | ((long) b[3] & 0xff) << 24
			       | ((long) b[2] & 0xff) << 16
			       | ((long) b[1] & 0xff) << 8
			       | ((long) b[0] & 0xff);	
		return l;
	}

	private String hex(long l) {
		return String.format("0x%08X", l);		
	}
	
	@Override
	public String toString() {
		return "Long4 [l0=" + hex(l0) + ", l1=" + hex(l1) + ", l2=" + hex(l2) + ", l3=" + hex(l3) + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (l0 ^ (l0 >>> 32));
		result = prime * result + (int) (l1 ^ (l1 >>> 32));
		result = prime * result + (int) (l2 ^ (l2 >>> 32));
		result = prime * result + (int) (l3 ^ (l3 >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Long4 other = (Long4) obj;
		if (l0 != other.l0)
			return false;
		if (l1 != other.l1)
			return false;
		if (l2 != other.l2)
			return false;
		if (l3 != other.l3)
			return false;
		return true;
	}
	
	
}
