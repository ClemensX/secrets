package de.fehrprice.crypto;

import java.nio.charset.StandardCharsets;

public class Conv {
	
	/**
	 * Convert input String to byte array using UTF_8 charset.
	 * @param plaintext
	 * @return
	 */
	public static byte[] plaintextToByteArray(String plaintext) {
		return plaintext.getBytes(StandardCharsets.UTF_8);
	}
	
	public static String toPlaintext(byte[] res_array) {
		return new String(res_array, StandardCharsets.UTF_8);
	}

	/**
	 * Extend byte array to a fixed length by appending zero bytes
	 * @param finalLength
	 * @param input
	 * @return
	 */
	public static byte[] extendWithZeroBytes(int finalLength, byte[] input) {
		if (input.length >= finalLength) {
			return input;
		}
		byte[] res = new byte[finalLength];
		System.arraycopy(input, 0, res, 0, input.length);
		for (int i = input.length; i < finalLength; i++) {
			res[i] = 0;
		}
		return res;
	}

	/**
	 * Extend byte array at beginning (low index) to a fixed length by prepending zero bytes
	 * @param finalLength
	 * @param input
	 * @return
	 */
	public static byte[] prependWithZeroBytes(int finalLength, byte[] input) {
		if (input.length >= finalLength) {
			return input;
		}
		byte[] res = new byte[finalLength];
		System.arraycopy(input, 0, res, finalLength - input.length, input.length);
		for (int i = 0; i < finalLength - input.length; i++) {
			res[i] = 0;
		}
		return res;
	}

	/**
	 * Convert hex string to Big Endian byte array. Every two chars is considered a hex string representation of one byte.
	 * First two chars in hexstring will be the byte at position 0. Big Endian ordering if input string is considered to be one number.
	 * Will throw NumberFormatException for invalid input (odd length or invalid character)
	 * @param hexstring
	 * @return
	 */
	public static byte[] toByteArray(String hexstring) {
		if (hexstring.length() % 2 == 1) {
			throw new NumberFormatException("hex string should have even length");
		}
		byte[] bytes = new byte[hexstring.length()/2];
		for (int i = 0; i < bytes.length; i ++) {
			String sub = hexstring.substring(i*2, i*2 + 2);
			// Integer.parseInt() will throw NumberFormatException on invalid input
			bytes[i] = (byte)(Integer.parseInt(sub, 16)& 0xff);
		}
		return bytes;
	}

	/**
	 * Lengthen byte array to specified length by prepending 0 bytes at end.
	 * NumberFormatException if array is already too big. 
	 * @param newLen
	 * @param oldarray
	 * @return
	 */
	public static byte[] fixByteArrayLength(int newLen, byte[] oldarray) {
		if (oldarray.length > newLen) {
			throw new NumberFormatException(" source array too big. Should be <= " + newLen + " bytes");
		}
		byte newArray[] = new byte[newLen];
		System.arraycopy(oldarray, 0, newArray, 0, oldarray.length);
		for (int i = oldarray.length; i < newLen; i++) {
			newArray[i] = 0;
		}
		return newArray;
	}

	/**
	 * Format byte array as Hex String - on byte yields 2 chars.
	 * Big Endian order: First byte will be first 2 chars of String
	 * @param bytes
	 * @return
	 */
	public static String toString(byte[] bytes) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			buf.append(String.format("%02x", bytes[i]));
		}
		return buf.toString();
	}

	/**Convert the first 8 bytes of block to an unsigned long.
	 * Big Endian order: first byte in array will contribute highest byte
	 * @param block
	 * @return
	 */
	public static long bytesToUnsignedLong(byte[] b) {
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

	public static void UnsingedLongToByteArray(long l, byte[] b) {
		b[0] = (byte) (l>>>56);
		b[1] = (byte) (l>>>48);
		b[2] = (byte) (l>>>40);
		b[3] = (byte) (l>>>32);
		b[4] = (byte) (l>>>24);
		b[5] = (byte) (l>>>16);
		b[6] = (byte) (l>>>8);
		b[7] = (byte) (l);
	}
	
	public static int byteToInt(byte b) {
		return ((int) b & 0xff);
	}
	
	public static byte intToByte(int i) {
		return (byte) (i);
	}

	public static boolean testEntropy(String keyCandidate) {
		return testEntropy(keyCandidate, 32);
	}
	
	public static boolean testEntropy(String keyCandidate, int lengthInBytes) {
		try {
			byte[] key = Conv.toByteArray(keyCandidate);
			if (key.length != 32) return false;
			// count set bits:
			int count1 = 0;
			int count0 = 0;
			for (int i = 0; i < key.length; i++) {
				byte b = key[i];
				int v = ((int) b & 0xff);
				int c = Integer.bitCount(v);
				count1 += c;
			}
			int totalbits = 8*lengthInBytes;
			count0 = totalbits - count1;
			// we do not accept disparity of 1/3 or more:
			if (count0 * 3 < totalbits || count1 * 3 < totalbits) {
				return false;
			}
		} catch (Throwable t) {
			return false;
		}
		return true;
	}

	public static void dump(byte[] array, int num) {
		System.out.print("dump array " + num + " of " + array.length + ": ");
		for (int i = 0 ; i < num; i++) {
			System.out.print("" + Conv.byteToInt(array[i]) + " ");
		}
		System.out.println();
	}
}
