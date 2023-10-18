package de.fehrprice.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * represent 256 bit unsigned integer values with 4 longs
 * Little endian order: d[3] is highest value
 */
public class fp256 {
	
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		fp256 fp256 = (fp256) o;
		return nlimbs == fp256.nlimbs && Arrays.equals(d, fp256.d);
	}
	
	
	@Override
	public int hashCode() {
		int result = Objects.hash(nlimbs);
		result = 31 * result + Arrays.hashCode(d);
		return result;
	}
	
	
	/** d stores 256 bit integer, it has four 64 bit limbs. */
	long d[] = new long[4];
	/** number of limbs used */
	int nlimbs = 0;
	
	/**
	 * Set to zero.
	 */
	public void zero() {
		d[0] = d[1] = d[2] = d[3] = 0L;
	}
	
	
	public long[] getInternalLongArray() {
		return d;
	}
}
