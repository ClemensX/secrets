package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.FixedPointOp;
import de.fehrprice.crypto.SHA;
import de.fehrprice.crypto.donna.niels.Bignum25519;
import de.fehrprice.crypto.donna.niels.ConstDef;
import de.fehrprice.crypto.donna.niels.ge25519_p1p1;
import de.fehrprice.crypto.fp256;
import de.fehrprice.crypto.donna.niels.ge25519;
import de.fehrprice.crypto.Long4;

public class ED25519 {
	
	private Ed25519 simpleEd = new Ed25519();
	private final de.fehrprice.crypto.donna.Curve25519 curve25519 = new de.fehrprice.crypto.donna.Curve25519();
	private final Modm modm = new Modm();
	ED25519DonnaImpl ge25519impl = new ED25519DonnaImpl(this, curve25519, modm);
	private FixedPointOp fp = new FixedPointOp();
	private Curve25519 cv = new Curve25519();
	private ConstDef constDef = new ConstDef();
	private Long4 long4 = new Long4();
	
	public static void print64(String name, byte[] b) {
		System.out.print(name + " ");
		for (int i = 0; i < 64; i++) {
			System.out.printf("%02x", b[i]);
		}
		System.out.println();
	}
	
	public static void print96(String name, byte[] b) {
		System.out.print(name + " ");
		for (int i = 0; i < 96; i++) {
			System.out.printf("%02x", b[i]);
		}
		System.out.println();
	}
	
	private void print128(String txt, fp256 f) {
		System.out.printf("%s ", txt); for (int i = 1; i >= 0; i--) printLong(f.getInternalLongArray()[i]); System.out.println();
	}
	
	public static void printBig(String txt, Bignum25519 v) {
		printB256modm(txt, v);
//		int i;
//		System.out.printf("%s ", txt);
//		System.out.printf("%016x ", v.m[0]);
//		System.out.printf("%016x ", v.m[1]);
//		System.out.printf("%016x ", v.m[2]);
//		System.out.printf("%016x ", v.m[3]);
//		System.out.printf("%016x ", v.m[4]);
//		System.out.printf("\n");
	}
	
	
	public static void printLong(long l) {
		System.out.printf("%016x ", l);
	}
	public static void print64t(String txt, long l) {
		System.out.printf("%s %016x \n", txt, l);
	}
	public static void printB256modm(String txt, Bignum256modm a) {
		int i;
		System.out.printf("%s ", txt); for (i = 0; i < 5; i++) printLong(a.m[i]); System.out.println();
	}
	
	
	public String publicKey(String secretKeyString) {
		Key secretKey = new Key();
		Key publicKey = new Key();
		Convert.toKey(secretKey, secretKeyString);
		publicKey(secretKey, publicKey);
		return Convert.fromKey(publicKey);
	}
	
	/**
	 * Create public key from secret key.
	 * @param secretKey
	 * @param publicKey
	 */
	public void publicKey(Key secretKey, Key publicKey) {
		Bignum256modm a = new Bignum256modm();
		ge25519 A = new ge25519();
		
		/* A = aB */
		//System.out.println("publickey()");
		byte[] extsk = new byte[64];
		extsk(extsk, secretKey);
		//print64("sk SHA", extsk);
		modm.expand256_modm(a, extsk, 32);
		ge25519impl.scalarmult_base_niels(A, ConstDef.ge25519_niels_base_multiples, a);
		//byte[] pk = new byte[32];
		ge25519impl.pack(publicKey.k, A);
	}
	
	/**
	 * @param messageString hex string coded message
	 * @param secretKeyString hex string coded private key
	 * @param pubk hex string coded public key
	 * @return
	 */
	public String signature(String messageString, String secretKeyString, String pubk) {
		byte[] m = Conv.toByteArray(messageString);
		Key secretKey = new Key();
		Key publicKey = new Key();
		Signature sig = new Signature();
		Convert.toKey(secretKey, secretKeyString);
		Convert.toKey(publicKey, pubk);
		signature(m, secretKey, publicKey, sig);
		return Convert.fromSignature(sig);
	}

	public void signature(byte[] m, Key sk, Key pk, Signature RS) {
		//ed25519_hash_context ctx;
		Bignum256modm r = new Bignum256modm();
		Bignum256modm S = new Bignum256modm();
		Bignum256modm a = new Bignum256modm();
		ge25519 R = new ge25519();
		
		byte[] extsk = new byte[64];
		//byte[] hashr = new byte[64];
		//byte[] hram = new byte[64];
		extsk(extsk, sk);

		/* r = H(aExt[32..64], m) */
		// create array for 2nd half of signature + message
		byte[] r_arr = new byte[32 + m.length];
		System.arraycopy(extsk, 32, r_arr, 0, 32);
		System.arraycopy(m, 0, r_arr, 32, m.length);
		byte[] hashr = h(r_arr); // digest
		//print64("hashr", hashr);
//		ed25519_hash_init(&ctx);
//		ed25519_hash_update(&ctx, extsk + 32, 32);
//		ed25519_hash_update(&ctx, m, mlen);
//		ed25519_hash_final(&ctx, hashr);
		modm.expand256_modm(r, hashr, 64);
		//printB256modm("r", r);
		
		/* R = rB */
		ge25519impl.scalarmult_base_niels(R, ConstDef.ge25519_niels_base_multiples, r);
		ge25519impl.pack(RS.k, R);
		
		/* S = H(R,A,m).. */
		//ed25519_hram(hram, RS, pk, m, mlen);
		byte[] hram = h(concat_r_pk_m(RS.k, pk.k, m));
		modm.expand256_modm(S, hram, 64);
		
		/* S = H(R,A,m)a */
		modm.expand256_modm(a, extsk, 32);
		modm.mul256_modm(S, S, a);
		
		/* S = (r + H(R,A,m)a) */
		modm.add256_modm(S, S, r);
		//printB256modm("S", S);
		
		/* S = (r + H(R,A,m)a) mod L */
		modm.contract256_modm(RS.k, 32, S);
	}
	public byte[] concat_r_pk_m(byte[] RS, byte[] pk, byte[] m) {
		byte[] concat = new byte[32 + pk.length + m.length];
		System.arraycopy(RS, 0, concat, 0, 32);
		System.arraycopy(pk, 0, concat, 32, pk.length);
		System.arraycopy(m, 0, concat, 32 + pk.length, m.length);
		return concat;
	}
	
	public boolean checkvalid(String signatureString, String messageString, String publicKeyString) {
		byte[] m = Conv.toByteArray(messageString);
		Key secretKey = new Key();
		Key publicKey = new Key();
		Signature sig = new Signature();
		Convert.toKey(publicKey, publicKeyString);
		Convert.toSignature(sig, signatureString);
		return sign_open(m, m.length, publicKey, sig) != 0;
	}
	
	public int sign_open (byte[] m, int mlen, Key pk, Signature RS) {
		ge25519 R = new ge25519();
		ge25519 A = new ge25519();
		byte[] hash = new byte[64];
		Bignum256modm hram = new Bignum256modm();
		Bignum256modm S = new Bignum256modm();
		byte[] checkR = new byte[32];
		
		if (0 != (RS.k[63] & 224) || (0 == ge25519impl.unpack_negative_vartime(A, pk.k)))
			return -1;
		
		/* hram = H(R,A,m) */
		//ed25519_hram(hash, RS, pk, m, mlen);
		//expand256_modm(hram, hash, 64);
		
		/* S */
		//expand256_modm(S, RS + 32, 32);
		
		/* SB - H(R,A,m)A */
		//ge25519_double_scalarmult_vartime(&R, &A, hram, S);
		//ge25519_pack(checkR, &R);
		
		/* check that R = SB - H(R,A,m)A */
		return -1 ;//ed25519_verify(RS, checkR, 32) ? 0 : -1;
	}

	
	
	
	private void extsk(byte[] extsk, Key secretKey) {
		byte[] b = h(secretKey.k);
		System.arraycopy(b, 0, extsk, 0, 64);
		//print64("sk SHA", extsk);
		// clear lowest 3 bits
		extsk[0] = (byte)(((int)extsk[0]) & 248);
		// clear highest bit
		extsk[31] = (byte)(((int)extsk[31]) & 127);
		// set 2nd highest bit:
		extsk[31] = (byte)(((int)extsk[31]) | 64);
	}
	
	
	private byte[] h(byte[] message) {
		SHA sha = new SHA();
		byte[] digest = sha.sha512(message);
		//System.out.println("digest = " + aes.toString(digest));
		return digest;
	}
	
	
	// donna helpers
	
	
	
	
}
