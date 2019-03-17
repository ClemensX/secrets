package de.fehrprice.crypto;

import java.math.BigInteger;

/**
 * Curve25519 implementation.
 * 
 * x25519: http://www.rfc-editor.org/info/rfc7748
 * EdDSA: http://www.rfc-editor.org/info/rfc8032
 *
 */
public class Curve25519 {

	public static BigInteger p;
	public static BigInteger p_minus2;
	public static BigInteger a24;

	public Curve25519() {
		super();
		// calculate p as 2 ^ 255 - 19
		p = new BigInteger("2");
		p = p.pow(255).subtract(new BigInteger("19"));
		p_minus2 = p.subtract(new BigInteger("2"));
		a24 = new BigInteger("121665");
	}


	/**
	 * Decode scalar by masking highest bit and lowest 3 bits,
	 * then set 2nd highest bit
	 * Input scalar has to be a 32 byte value, IllegalArgumentException thrown if not
	 * @param b
	 * @return
	 */
	public BigInteger decodeScalar25519(byte[] b) {
		if (b.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + b.length);
		}
		byte[] cloned = b.clone();
		// clear lowest 3 bits
		cloned[0] = (byte)(((int)cloned[0]) & 248);
		// clear highest bit
		cloned[31] = (byte)(((int)cloned[31]) & 127);
		// set 2nd highest bit:
		cloned[31] = (byte)(((int)cloned[31]) | 64);
		return decodeLittleEndian(cloned, 255);
	}
	
	/**
	 *
	 * python code:def decodeLittleEndian(b, bits):
	 *  return sum([b[i] << 8*i for i in range((bits+7)/8)])
     *
	 * @param b
	 * @param bits
	 * @return
	 */
	public BigInteger decodeLittleEndian( byte[] b, int bits) {
		if (b.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + b.length);
		}
		BigInteger big = new BigInteger("0");
		int range = ((bits+7)/8);  // yields 32 bytes for curve25519
		BigInteger factor = BigInteger.ONE;
		for(int i = 0; i < range; i++) {
			long v = ((int)b[i]) & 0xff; 
			BigInteger byteVal = BigInteger.valueOf(v);
			big = big.add(byteVal.multiply(factor));
			factor = factor.multiply(BigInteger.valueOf(256));
		}
		return big;
	}
	
	/**
	 * Convert 64 char hex string to byte array in big-endian (leftmost chars first in array)
	 * IllegalArgumentException when string is not 64 byte
	 * @param string
	 * @return
	 */
	public byte[] toByteArray(String string) {
		while(string.length() < 64) {
			string = "0" + string;
		}
		if (string.length() != 64) {
			throw new IllegalArgumentException("Must be 64 chars long: " + string);
		}
		byte[] bytes = new byte[string.length()/2];
		for (int i = 0; i < bytes.length; i ++) {
			String sub = string.substring(i*2, i*2 + 2);
			bytes[i] = (byte)(Integer.parseInt(sub, 16)& 0xff);
		}
		return bytes;
	}
	
	public byte[] toByteArrayLittleEndian(String string) {
		return reverse(toByteArray(string));
	}
	
	public byte[] reverse(byte[] b) {
		if (b.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + b.length);
		}
		// reverse order:
		byte[] encoded2 = new byte[b.length];
		for( int i = 0; i < b.length; i++) {
			encoded2[b.length-1-i] = b[i];
		}
		return encoded2;
	}

	public static String asString(byte[] b) {
		if (b.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + b.length);
		}
		return Conv.toString(b);
	}
	
	public byte[] decodeFromBigIntegerLittleEndian(BigInteger m) {
		byte[] encoded = m.toByteArray();
		if (encoded.length > 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + encoded.length);
		}
		encoded = Conv.prependWithZeroBytes(32, encoded);
		// reverse order:
		byte[] encoded2 = new byte[encoded.length];
		for( int i = 0; i < encoded.length; i++) {
			encoded2[encoded.length-1-i] = encoded[i];
		}
		if (encoded2.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + encoded2.length);
		}
		return encoded2;
	}

	public BigInteger decodeUCoordinate(byte[] u, int bits) {
		if (u.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + u.length);
		}
		byte[] cloned = u.clone();
		// clear highest bit
		cloned[31] = (byte)(((int)u[31]) & 0x7f);
		return decodeLittleEndian(cloned, bits);
		
	}
	
	public String encode(BigInteger u, int bits) {
		String v = u.toString(16);
		if (v.length() > 64) {
			throw new IllegalArgumentException(" BigInteger too long: " + v);
		}
		while (v.length() < 64) {
			v = "00" + v;
		}
		if (v.length() != 64) {
			throw new IllegalArgumentException(" strings for curve have to be 64 bytes: " + v.length());
		}
		return v;
	}
	
	public String encodeUCoordinate(BigInteger u, int bits) {
		u = u.mod(p);
		String v = u.toString(16);
		if (v.length() != 64) {
			throw new IllegalArgumentException(" BigInteger too long: " + v);
		}
		while (v.length() < 64) {
			v = "00" + v;
		}
		return v;
	}
	
	public BigInteger x25519( BigInteger k, BigInteger u, int bits) {
		BigInteger x_1, x_2, z_2, x_3, z_3, swap;
		x_1 = u;
		x_2 = BigInteger.ONE;
		z_2 = BigInteger.ZERO;
		x_3 = u;
		z_3 = BigInteger.ONE;
		swap = BigInteger.ZERO;
		for (int t = bits-1; t >= 0; t--) {
			//System.out.println(t);
			//out(k.shiftRight(t), "k_t shift");
			BigInteger k_t = k.shiftRight(t).and(BigInteger.ONE);
			//out(k_t, "k_t and");
			swap = swap.xor(k_t);
			//out(swap, "swap xor");
			//System.out.println("t k_t swap " + t + " " + k_t.toString(16) + " " + swap.toString(16) );
//			System.out.println("swap " + swap);
			BigInteger[] cs = cswap(swap, x_2, x_3);
			x_2 = cs[0];
			x_3 = cs[1];
			cs = cswap(swap, z_2, z_3);
			z_2 = cs[0];
			z_3 = cs[1];
			swap = k_t;
			
//			out(x_2, "x_2 ");
//			out(x_3, "x_3 ");
//			out(z_2, "z_2 ");
//			out(z_3, "z_3 ");
			BigInteger A = x_2.add(z_2);
			BigInteger AA = A.pow(2);
			BigInteger B = x_2.subtract(z_2);
			BigInteger BB = B.pow(2);
			BigInteger E = AA.subtract(BB);
			BigInteger C = x_3.add(z_3);
			BigInteger D = x_3.subtract(z_3);
			BigInteger DA = D.multiply(A);
			BigInteger CB = C.multiply(B);
			x_3 = DA.add(CB).pow(2).mod(p);
			z_3 = x_1.multiply(DA.subtract(CB).pow(2)).mod(p);
			x_2 = AA.multiply(BB).mod(p);
			z_2 = E.multiply(AA.add(a24.multiply(E))).mod(p);
//			System.out.println("k_t " + k_t);
//			
//			System.out.println("A " + A);
//			System.out.println("AA " + AA);
//			System.out.println("B " + B);
//			System.out.println("BB " + BB);
//			System.out.println("E " + E);
//			System.out.println("C " + C);
//			System.out.println("D " + D);
//			System.out.println("DA " + DA);
//			System.out.println("CB " + CB);
//			System.out.println("x_3 " + x_3);
//			System.out.println("z_3 " + z_3);
//			System.out.println("x_2 " + x_2);
//			System.out.println("z_2 " + z_2);
//			System.out.println(" t " + t);
			//if (t < 100) System.exit(0);
//			out(z_2, " z_2 ");
			}
		BigInteger[] cond2 = cswap(swap, x_2, x_3);
		x_2 = cond2[0];
		x_3 = cond2[1];
		cond2 = cswap(swap, z_2, z_3);
		z_2 = cond2[0];
		z_3 = cond2[1];
		BigInteger ret = x_2.multiply(z_2.modPow(p_minus2, p));
		ret = ret.mod(p);
		assert(p.compareTo(ret) == 1);
		assert(p.shiftRight(255).equals(BigInteger.ZERO));
		return ret;
	}
	
	private BigInteger[] cswap(BigInteger swap, BigInteger x_2, BigInteger x_3) {
		// swap is 0 or 1
		//out(x_2, "swap a");
		//out(x_3, "swap b");
		//System.out.println(swap);
		BigInteger dummy = BigInteger.ZERO.subtract(swap);
//		out(dummy, "dummy hex");
//		System.out.println("cswap x_3 " + x_3);
//		System.out.println("cswap x_2 " + x_2.toString(16));
//		System.out.println("cswap x_3 " + x_3.toString(16));
//		System.out.println("cswap x_2 xor x_3 " + x_2.xor(x_3).toString(16));
		dummy = dummy.and(x_2.xor(x_3));
		BigInteger[] r = new BigInteger[2];
		r[0] = x_2.xor(dummy);
		r[1] = x_3.xor(dummy);
//		System.out.println("cswap x_2 " + x_2.toString(16));
//		System.out.println("cswap dummy " + dummy.toString(16));
//		System.out.println("cswap a 0 " + r[0].toString(16));
		//System.out.println("cswap a 1 " + r[1].toString(16));
//		out(r[0], "r[0]");
//		out(r[1], "r[1]");
		return r;
	}


	public void out(BigInteger x, String string) {
		System.out.print(string + " ");
		System.out.println(asLittleEndianHexString(x));
	}

	public String asLittleEndianHexString(BigInteger x) {
		//byte[] r = reverse(x.toByteArray());
		byte[] r = this.toByteArrayLittleEndian(x.toString(16));
		if (r.length != 32) {
			throw new IllegalArgumentException(" arrays for curve have to be 32 bytes: " + r.length);
		}
		return asString(r);
	}

	public static void main(String[] p) {
		BigInteger b = new BigInteger("1");
		System.out.println("1 "+ asString(b.toByteArray()) );
		b = new BigInteger("-1");
		System.out.println("1 "+ asString(b.toByteArray()) );
		byte[] v = {(byte) 255, (byte)255};
		b = new BigInteger(1, v);
		System.out.println(" "+ b + " " + asString(b.toByteArray()) );
	}


	/**
	 * String parameter based curve25519 implementation
	 * Prepare BigIntegers as needed by decoding String parameters,
	 * then call the BigInteger implementation  
	 * @param scalarString
	 * @param uInString
	 * @return
	 */
	public String x25519(String scalarString, String uInString) {
		BigInteger scalar = decodeScalar25519(toByteArray(scalarString));
		BigInteger uIn = decodeUCoordinate(toByteArray(uInString), 255);
		BigInteger uOut = x25519(scalar, uIn, 255);
		return asLittleEndianHexString(uOut);
	}

}
