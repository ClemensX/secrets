package de.fehrprice.crypto;

import java.math.BigInteger;
import java.util.HashMap;

/**
 * Implementation blueprint here: http://ed25519.cr.yp.to/software.html
 *
 */
public class Ed25519 extends Curve25519 {

	public static BigInteger q;
	public static BigInteger q_minus2;
	public static BigInteger Bx;
	public static BigInteger By;
	public static BigInteger d;
	public static BigInteger I;
	public static BigInteger L;
	public static BigInteger B[];
	
	// tests:
	 HashMap<String, BigInteger> p0 = new HashMap<>();
	 HashMap<String, BigInteger> p1 = new HashMap<>();

	public class KeyPair {
		public String privateKey;
		public String publicKey;
	}

	public Ed25519() {
		super();
		q = Curve25519.p;
		q_minus2 = Curve25519.p_minus2;
		d = BigInteger.valueOf(-121665).multiply(inv(BigInteger.valueOf(121666)));
		d = d.mod(q);
		I = expmod(BigInteger.valueOf(2), q.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), q);
		By = BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5)));
		By = By.mod(q);
		Bx = xrecover(By);
		Bx = Bx.mod(q);
		B = new BigInteger[2];
		B[0] = Bx;
		B[1] = By;
		//  2^252+27742317777372353535851937790883648493
		BigInteger add = new BigInteger("27742317777372353535851937790883648493");
		L = BigInteger.valueOf(2).pow(252).add(add);
	}
	
	/**
	 * @param secretKeyString secretkey must be 64 byte hex string or null/empty
	 * @return
	 */
	public KeyPair keygen(String secretKeyString) {
		AES aes = new AES();
		KeyPair keys = new KeyPair();
		if (secretKeyString == null) {
			secretKeyString = "";
		}
		int len = secretKeyString.length();
		if (len != 0 && len != 64) {
			throw new AssertionError("keylen invalid (must be 32 bytes): " + secretKeyString);
		}
		if (len == 0) {
			// first we need a public key: (no need for prime, just a random number):
			byte[] privKeyBytes = aes.random(32);
			// convert to hex string
			secretKeyString = Conv.toString(privKeyBytes);
			System.out.println("priv key generated: " + secretKeyString);
		}
//		  h = H(sk)
//		  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
//		  A = scalarmult(B,a)

//		khash=self.H(privkey,None,None)
//		a=from_le(self.__clamp(khash[:self.b//8]))
//		#Return the key pair (public key is A=Enc(aB).
//		return privkey,(self.B*a).encode()
		
		byte[] sk = Conv.toByteArray(secretKeyString);
		byte[] h = this.h(sk);
		// we need only lower 32 bytes
		byte[] h2 = new byte[32];
		System.arraycopy(h, 0, h2, 0, 32);
		h = h2;
		//System.out.println("digest = " + aes.toString(ret));
		BigInteger a = this.decodeScalar25519(h);
		//System.out.println("a = " + a);
		// a * B
		// B = [Bx % q,By % q]
		//By = 4 * inv(5)
		//Bx = xrecover(By)
		BigInteger A[] = scalarmult(B, a);
//		System.out.println("A[0]: " + A[0]);
//		System.out.println("A[1]: " + A[1]);
		BigInteger encoded = encodepoint(A);
//		System.out.println("encoded: " + encoded);
//		System.out.println("encoded: " + asLittleEndianHexString(encoded));
//		
//		System.out.println("encoded: " + encoded.toString(16));
		keys.privateKey = secretKeyString;
		keys.publicKey = asLittleEndianHexString(encoded);
		return keys;
	}
	
	private byte[] encodepoint_to_array(BigInteger[] a) {
		byte[] encoded = decodeFromBigIntegerLittleEndian(a[1]);
		if (a[0].testBit(0)) {
			// set highest bit in lowest byte
			encoded[31] = (byte)(((int)encoded[31]) | 0x80);
		}
		return encoded;
	}

	private BigInteger encodepoint(BigInteger[] a) {
		byte[] encoded = encodepoint_to_array(a);
		return decodeLittleEndian(encoded, 255);
	}

	private BigInteger[] scalarmult(BigInteger[] P, BigInteger e) {
		String p0s = P[0].toString(16);
		if (!p0.containsKey(p0s)) {
			p0.put(p0s, P[0]);
			System.out.println("p0 contains # " + p0.size());
		}
		if (e.equals(BigInteger.ZERO)) {
			BigInteger r[] = new BigInteger[2];
			r[0] = BigInteger.ZERO;
			r[1] = BigInteger.ONE;
			return r;
		}
		BigInteger Q[] = scalarmult(P, e.divide(BigInteger.valueOf(2)));
		Q = edwards(Q, Q);
		if (e.testBit(0)) {
			Q = edwards(Q, P);
		}
		return Q;
	}

	private BigInteger[] edwards(BigInteger[] P, BigInteger[] Q) {
		BigInteger r[] = new BigInteger[2];
		//x1 = P[0]
		//y1 = P[1]
		//x2 = Q[0]
		//y2 = Q[1]
		//x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
		//y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
		//return [x3 % q,y3 % q]
		BigInteger x1 = P[0];
		BigInteger y1 = P[1];
		BigInteger x2 = Q[0];
		BigInteger y2 = Q[1];
		BigInteger m = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
		BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1));
		x3 = x3.multiply(inv(BigInteger.ONE.add(m)));
		BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2));
		y3 = y3.multiply(inv(BigInteger.ONE.subtract(m)));
		r[0] = x3.mod(q);
		r[1] = y3.mod(q);
		return r;
	}

	private BigInteger xrecover(BigInteger y) {
		BigInteger y_squared = y.multiply(y);
		BigInteger xx = y_squared.subtract(BigInteger.ONE);
		BigInteger t = d.multiply(y_squared).add(BigInteger.ONE);
		t = inv(t);
		xx = xx.multiply(t);
		BigInteger q38 = q.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8));
		BigInteger x = expmod(xx, q38, q);
		BigInteger x_squared = x.multiply(x);
		if (!x_squared.subtract(xx).mod(q).equals(BigInteger.ZERO)) {
			x = x.multiply(I).mod(q);
		}
		if (!x.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
			x = q.subtract(x);
		}
		return x;
	}

	private BigInteger expmod(BigInteger b, BigInteger e, BigInteger m) {
		//System.out.println("mod " + m.toString(16));
		return b.modPow(e, m);
	}

	private BigInteger inv(BigInteger b) {
		return expmod(b, q_minus2, q);
	}
	
	/**
	 * Decode 64 byte array to BigInteger, first byte (index 0) yields lowest bits in result  
	 * python code(b==256): sum(2**i * bit(h,i) for i in range(2*b))
    *
	 * @param b
	 * @param bits
	 * @return
	 */
	public BigInteger decodeLittleEndian64( byte[] b) {
		if (b.length != 64) {
			throw new IllegalArgumentException(" array expected to be 64 bytes: " + b.length);
		}
		BigInteger big = new BigInteger("0");
		int range = 64;
		BigInteger factor = BigInteger.ONE;
		for(int i = 0; i < range; i++) {
			long v = ((int)b[i]) & 0xff; 
			BigInteger byteVal = BigInteger.valueOf(v);
			big = big.add(byteVal.multiply(factor));
			factor = factor.multiply(BigInteger.valueOf(256));
		}
		return big;
	}

	private BigInteger h_int(byte[] message) {
		byte[] digest = h(message);
		return decodeLittleEndian64(digest);
	}
	
	private byte[] h(byte[] message) {
		SHA sha = new SHA();
		byte[] digest = sha.sha512(message);
		//System.out.println("digest = " + aes.toString(digest));
		return digest;
	}

	public String publicKey(String secretKeyString) {
		return keygen(secretKeyString).publicKey;
	}

	private byte[] concat_r_pk_m(byte[] enc_r, byte[] pk, byte[] m) {
		byte[] concat = new byte[enc_r.length + pk.length + m.length];
		System.arraycopy(enc_r, 0, concat, 0, enc_r.length);
		System.arraycopy(pk, 0, concat, enc_r.length, pk.length);
		System.arraycopy(m, 0, concat, enc_r.length + pk.length, m.length);
		return concat;
	}
	
	public String signature(String messageString, String secretKeyString, String pubk) {
		byte[] m = Conv.toByteArray(messageString);
		return signature(m, secretKeyString, pubk);
	}

	public String signature(byte[] message, String secretKeyString, String pubk) {
		byte[] sk = Conv.toByteArray(secretKeyString);
		byte[] h = this.h(sk);
		// we need only lower 32 bytes
		byte[] h_low = new byte[32];
		System.arraycopy(h, 0, h_low, 0, 32);
		BigInteger a = this.decodeScalar25519(h_low);
		//System.out.println("a = " + a);
		// create array for 2nd half of signature + message
		byte[] r_arr = new byte[32 + message.length];
		System.arraycopy(h, 32, r_arr, 0, 32);
		System.arraycopy(message, 0, r_arr, 32, message.length);
		// sign and convert to BigInteger:
		BigInteger r = h_int(r_arr);
		//System.out.println("r = " + r);
		BigInteger R[] = scalarmult(B, r);
		//  S = (r + Hint(encodepoint(R) + pk + m) * a) % l
		// concat encode(R) + pk + m
		byte[] enc_r = encodepoint_to_array(R);
		byte[] concat = concat_r_pk_m(enc_r, Conv.toByteArray(pubk), message);
		//System.out.println("concat int = " + h_int(concat));
		BigInteger S = r.add(h_int(concat).multiply(a)).mod(L);
		//System.out.println("S = " + S);
		//   enc = encodepoint(R) + encodeint(S)
		String sig = Conv.toString(enc_r) + asLittleEndianHexString(S);
		//System.out.println("sig = " + sig);
		return sig;
	}

	private BigInteger decodeint(String s) {
		byte[] b = Conv.toByteArray(s);
		BigInteger y = decodeLittleEndian(b, 255);
		return y;
	}

	private BigInteger[] decodepoint(String substring) {
/*
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P
 */
		byte[] y_arr = Conv.toByteArray(substring);
		BigInteger s = decodeLittleEndian(y_arr, 255);
		// clear high bit and save as y:
		BigInteger y = s.clearBit(255);
		BigInteger x = xrecover(y);
		boolean x_and_1 = x.testBit(0);
		boolean highbit = s.testBit(255);
		if (x_and_1 != highbit) {
			x = q.subtract(x);
		}
		BigInteger P[] = new BigInteger[2];
		P[0] = x;
		P[1] = y;
		if (!isoncurve(P)) {
			throw new IllegalArgumentException("decoding point that is not on curve");
		}
		return P;
	}
	
	private boolean isoncurve(BigInteger[] p) {
/*
def isoncurve(P):
  x = P[0]
  y = P[1]
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0
 */
		BigInteger x = p[0]; 
		BigInteger y = p[1];
		BigInteger x_square = x.multiply(x);
		BigInteger y_square = y.multiply(y);
		BigInteger b = x_square.negate().add(y_square).subtract(BigInteger.ONE).subtract(d.multiply(x_square).multiply(y_square));
		return b.mod(q).equals(BigInteger.ZERO);
	}

	public boolean checkvalid(String signature, String messageString, String publicKeyString) {
	/*
	  if len(s) != b/4: raise Exception("signature length is wrong")
	  if len(pk) != b/8: raise Exception("public-key length is wrong")
	  R = decodepoint(s[0:b/8])
	  A = decodepoint(pk)
	  S = decodeint(s[b/8:b/4])
	  h = Hint(encodepoint(R) + pk + m)
	  if scalarmult(B,S) != edwards(R,scalarmult(A,h)):
	    raise Exception("signature does not pass verification")
	 */
		byte[] m = Conv.toByteArray(messageString);
		return checkvalid(signature, m, publicKeyString);
	}

	public boolean checkvalid(String signature, byte[] message, String publicKeyString) {
		if (signature.length() != 128) {
			throw new IllegalArgumentException("signature length is wrong");
		}
		if (publicKeyString.length() != 64) {
			throw new IllegalArgumentException("public-key length is wrong");
		}
		//System.out.println("decodepoint R " + s.substring(0, 64));
		BigInteger R[] = decodepoint(signature.substring(0, 64));
		BigInteger A[] = decodepoint(publicKeyString);
		BigInteger S = decodeint(signature.substring(64));
		//System.out.println("S = " + S);
		//print_point(R, "R");
		//print_point(A, "A");
		byte[] enc_r = encodepoint_to_array(R);
		byte[] concat = concat_r_pk_m(enc_r, Conv.toByteArray(publicKeyString), message);
		BigInteger h = h_int(concat);
		//System.out.println("concat int verify = " + h);
		BigInteger[] left = scalarmult(B, S);
		BigInteger[] right = edwards(R, scalarmult(A, h));
		boolean is_equal = left[0].equals(right[0]) && left[1].equals(right[1]);  
//		if (!is_equal) {
//			throw new IllegalArgumentException("signature does not pass verification");
//		}
		return is_equal;
	}

	private void print_point(BigInteger[] p, String name) {
		System.out.println(name + " [ " + p[0] + " ] [ " + p[1] + " ]");
	}
}
