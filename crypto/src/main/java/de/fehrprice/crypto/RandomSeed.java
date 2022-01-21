package de.fehrprice.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Properties;

/**
 * Provide seed values able to initialize a pseudo random number generator (PRNG).
 *
 */
public class RandomSeed {

	/**
	 * Create seed value by:
	 *  - calling Java's SecureRandom class to get 32 bytes.
	 *  - Get nano time (after waiting some time to prevent the same time value)
	 *  - use some fixed String values
	 *  - store all of the above in a message then use SHA-256 to get 32 byte of hash value and return it. 
	 * @return
	 */
	public static byte[] createSeed() {
		// ScureRandom
		byte[] secBuffer;
		try {
		    System.out.println("SecureRandom start");
	        Properties props = System.getProperties();
	        String sec = props.getProperty("securerandom.source");
	        //props.setProperty("gate.home", "http://gate.ac.uk/wiki/code-repository");
	        //System.out.println("securerandom.source: " + sec);
//	        if (sec.contains("/dev") && !sec.equalsIgnoreCase("file:/dev/urandom")) {
//	            props.setProperty("securerandom.source", "file:/dev/urandom");
//	            props.setProperty("java.security.egd", "file:/dev/urandom");
//	            props = System.getProperties();
//	            sec = props.getProperty("securerandom.source");
//	            System.out.println("securerandom.source reset: " + sec);
//	        }

	        SecureRandom secureRandom = SecureRandom.getInstance("DRBG");
//            secBuffer = SecureRandom.getInstanceStrong().generateSeed(32);
            secBuffer = secureRandom.generateSeed(32);
            System.out.println("SecureRandom end");
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
		
		// nano time
		try {
			Thread.sleep(47);
		} catch (InterruptedException e) {
			return null;
		}
		byte[] nanoBuffer = calculateNanoTimeSeed();
		byte[] ret = new byte[64];
		System.arraycopy(secBuffer, 0, ret, 0, 32);
		System.arraycopy(nanoBuffer, 0, ret, 32, 32);
		//System.out.println(Conv.toString(ret));
		SHA sha = new SHA();
		byte[] seed = sha.sha512(ret);
		System.out.println("final seed: " + Conv.toString(seed));
		return seed;
	}

	private static byte[] calculateNanoTimeSeed() {
		byte[] calc_seed = new byte[32];
		// build 32 byte hex string:
		String magic = "46454852"; // ASCII code for 'FEHR'
		long nanosec = System.nanoTime();
		String nano = String.format("%016x", nanosec);
		byte[] mn = Conv.toByteArray(magic+nano);
		System.arraycopy(mn, 0, calc_seed, 0, 12);
		String datehash = new Date().toString().hashCode() + "";
		for (int i = 0; i < 4; i++) {
			if (datehash.length() > i) {
				calc_seed[12 + i] = (byte) datehash.charAt(i);
			} else {
				calc_seed[12 + i] = (byte) 42;
			}
		}
		System.arraycopy(calc_seed, 0, calc_seed, 16, 16);
		//System.out.println(toString(calc_seed));
		return calc_seed;
	}

	
}
