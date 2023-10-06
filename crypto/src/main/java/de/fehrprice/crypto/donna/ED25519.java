package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.SHA;
import de.fehrprice.crypto.edu25519.Field;

public class ED25519 {
	
	public static void print64(String name, byte[] b) {
		System.out.print(name + " ");
		for (int i = 0; i < 64; i++) {
			System.out.printf("%02x", b[i]);
		}
		System.out.println();
	}
	
	public class Key {
		public byte[] k = new byte[32];
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
		//bignum256modm a;
		//ge25519 ALIGN(16) A;
		//hash_512bits extsk;
		
		/* A = aB */
		System.out.println("publickey()");
		byte[] extsk = new byte[64];
		extsk(extsk, secretKey);
		//expand256_modm(a, extsk, 32);
		//ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
		//ge25519_pack(pk, &A);
	}
	
	
	private void extsk(byte[] extsk, Key secretKey) {
		byte[] b = h(secretKey.k);
		System.arraycopy(b, 0, extsk, 0, 64);
		print64("sk SHA", extsk);
		// clear lowest 3 bits
		extsk[0] = (byte)(((int)extsk[0]) & 248);
		// clear highest bit
		extsk[31] = (byte)(((int)extsk[31]) & 127);
		// set 2nd highest bit:
		extsk[31] = (byte)(((int)extsk[31]) | 64);
		print64("sk SHA", extsk);
	}
	
	
	private byte[] h(byte[] message) {
		SHA sha = new SHA();
		byte[] digest = sha.sha512(message);
		//System.out.println("digest = " + aes.toString(digest));
		return digest;
	}
	
}
