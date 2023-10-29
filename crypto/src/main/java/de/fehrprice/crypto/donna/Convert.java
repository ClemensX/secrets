package de.fehrprice.crypto.donna;

import de.fehrprice.crypto.Conv;

public class Convert {
	/**
	 * Convert 64 char hex string to Big Endian key byte array. Every two chars is considered a hex string representation of one byte.
	 * First two chars in hexstring will be the byte at position 0. Big Endian ordering if input string is considered to be one number.
	 * Will throw NumberFormatException for invalid input (odd length or invalid character)
	 * @param hexstring
	 * @return
	 */
	public static void toKey(Key k, String hexstring) {
		if (hexstring.length() != 64) {
			throw new NumberFormatException("hex string should have even length");
		}
		for (int i = 0; i < k.k.length; i ++) {
			String sub = hexstring.substring(i*2, i*2 + 2);
			// Integer.parseInt() will throw NumberFormatException on invalid input
			k.k[i] = (byte)(Integer.parseInt(sub, 16)& 0xff);
		}
		return;
	}
	
	/**
	 * Convert 128 char hex string to Big Endian key byte array. Every two chars is considered a hex string representation of one byte.
	 * First two chars in hexstring will be the byte at position 0. Big Endian ordering if input string is considered to be one number.
	 * Will throw NumberFormatException for invalid input (odd length or invalid character)
	 * @param hexstring
	 * @return
	 */
	public static void toSignature(Signature k, String hexstring) {
		if (hexstring.length() != 128) {
			throw new NumberFormatException("hex string should have even length");
		}
		for (int i = 0; i < k.k.length; i ++) {
			String sub = hexstring.substring(i*2, i*2 + 2);
			// Integer.parseInt() will throw NumberFormatException on invalid input
			k.k[i] = (byte)(Integer.parseInt(sub, 16)& 0xff);
		}
		return;
	}
	
	/**
	 * Convert Key to 64 char hex string. First byte is most significant (BigEndian).
	 * @param k
	 * @return
	 */
	public static String fromKey(Key k) {
		return Conv.toString(k.k);
	}

	/**
	 * Convert Signature to 128 char hex string. First byte is most significant (BigEndian).
	 * @param s
	 * @return
	 */
	public static String fromSignature(Signature k) {
		return Conv.toString(k.k);
	}
}
