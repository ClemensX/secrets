package de.fehrprice.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An efficient library for 256 bit modular integer arithmetic
 * Adapted from C source code: https://github.com/piggypiggy/fp256
 * 
 * Needed for speeding up Edwards curve calculations.
 * We need: add, subtract, multiply, modulo, modular exponentiation (modPow) 
 * done and tested: add, subtract, multiply
 * 
 * https://programming.guide/java/unsigned-long.html
 *
 */


public class FP256 {
    
    /**
     * represent 256 bit unsigned integer values with 4 longs
     * Liitle endian order: d[3] is highest value
     */
    public class fp256 {

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + getEnclosingInstance().hashCode();
            result = prime * result + Arrays.hashCode(d);
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
            fp256 other = (fp256) obj;
            if (!getEnclosingInstance().equals(other.getEnclosingInstance()))
                return false;
            return Arrays.equals(d, other.d);
        }

        /** d stores 256 bit integer, it has four 64 bit limbs. */
        long d[] = new long[4];
        /** number of limbs used */
        int nlimbs = 0;
        private FP256 getEnclosingInstance() {
            return FP256.this;
        }
        /**
         * Set to zero.
         */
        public void zero() {
        	d[0] = d[1] = d[2] = d[3] = 0L;
        }
    }
    
    public fp256 fromString(String s) {
        if (s.length() != 64) {
            throw new NumberFormatException("BigInteger outside allowed range");
        }
        fp256 f = new fp256();
        var b = Conv.toByteArray(s);
        //Conv.reverseBytes(b);
        var higharr = Arrays.copyOfRange(b, 0, 8);
        var high2arr = Arrays.copyOfRange(b, 8, 16);
        var low2arr = Arrays.copyOfRange(b, 16, 24);
        var lowarr = Arrays.copyOfRange(b, 24, 32);
        f.d[0] = Conv.bytesToUnsignedLong(lowarr);
        f.d[1] = Conv.bytesToUnsignedLong(low2arr);
        f.d[2] = Conv.bytesToUnsignedLong(high2arr);
        f.d[3] = Conv.bytesToUnsignedLong(higharr);
        return f;
    }
    
    /**
     * Return Hex String representation of fp256 value with no whitespace.
     * @param f
     * @return
     */
    public String toString(fp256 f) {
        return dump(f).replaceAll("\\s","");
    }
    
    /**
     * Return Hex String representation of fp256 value.
     * Separarted into 4 parts with space in between
     * @param f
     * @return
     */
    public String dump(fp256 f) {
        String res = "";
        res += String.format("%016x ", f.d[3]);
        res += String.format("%016x ", f.d[2]);
        res += String.format("%016x ", f.d[1]);
        res += String.format("%016x", f.d[0]);
        return res;
    }
    
    public String dumpLong(long l) {
        return String.format("%016x ", l);
    }
    
    /**
     * Convert from BigInteger. Only lowest 256 bits are used.
     * NumberFormatException if negative number is passed
     * @param big
     * @return
     */
    public fp256 fromBigInteger(BigInteger big) {
        if (big.signum() < 0) {
            throw new NumberFormatException("BigInteger outside allowed range");
        }
        String hex = big.toString(16);
        if (hex.length() > 64) {
            hex = hex.substring(hex.length() - 64); // use lowest 64 chars (to the right)
        }
        // make sure we have full 64 chars in string:
        while (hex.length() < 64) {
            hex = "0" + hex;
        }
        return fromString(hex);
    }
    
    /**
     * Return BigInteger representation of fp256
     * @param f
     * @return
     */
    public BigInteger toBigInteger(fp256 f) {
        return new BigInteger(toString(f), 16);
    }
    
    public fp256 zero() {
        return new fp256();
    }

    private long getCarry(long a, long b) {
        if (Long.compareUnsigned(a, b) < 0) {
            return 1;
        } else {
            return 0;
        }
    }
    
    private long getBorrow(long a, long b) {
        if (Long.compareUnsigned(a, b) > 0) {
            return 1;
        } else {
            return 0;
        }
    }
    
    // /src/ll/ll_u256_add.c
    public void add(fp256 res, fp256 a, fp256 b) {
        //u64 t, r, carry;
        long t, r, carry;

        t = a.d[0];
        r = t + b.d[0];
        carry = getCarry(r,t);
        res.d[0] = r;

        t = a.d[1];
        t += carry;
        carry = getCarry(t,carry);
        r = t + b.d[1];
        carry |= getCarry(r,t);
        res.d[1] = r;

        t = a.d[2];
        t += carry;
        carry = getCarry(t,carry);
        r = t + b.d[2];
        carry |= getCarry(r,t);
        res.d[2] = r;

        t = a.d[3];
        t += carry;
        carry = getCarry(t,carry);
        r = t + b.d[3];
        carry |= getCarry(r,t);
        res.d[3] = r;
        
    }

    // /src/ll/ll_u256_add.c
    public void subtract(fp256 res, fp256 a, fp256 b) {
        long t, r, borrow;

        t = a.d[0];
        r = t - b.d[0];
        borrow = getBorrow(r,t);
        res.d[0] = r;

        t = a.d[1];
        t -= borrow;
        borrow = getBorrow(t,a.d[1]);
        r = t - b.d[1];
        borrow |= getBorrow(r,t);
        res.d[1] = r;

        t = a.d[2];
        t -= borrow;
        borrow = getBorrow(t,a.d[2]);
        r = t - b.d[2];
        borrow |= getBorrow(r,t);
        res.d[2] = r;

        t = a.d[3];
        t -= borrow;
        borrow = getBorrow(t,a.d[3]);
        r = t - b.d[3];
        borrow |= getBorrow(r,t);
        res.d[3] = r;
    }
    
    // unsigned 64 bit multiplication --> 128 bit result
    // https://en.wikipedia.org/wiki/Karatsuba_algorithm
    // d[0} and d[1] used for result
    // 64 bit input is divided into 32 bit parts 
    // karatsuba is applied then parts are summed and returned in lower 2 fp256 longs
    // NOTE: implementation cancelled, because I could not find a way to efficiently compute carry bit for z2 
    public void karatsuba64(fp256 res, long a, long b) {
    	throw new UnsupportedOperationException("Karatsuba not implemented due to carry bit problem");
    }
    
    // unsigned 64 bit multiplication --> 128 bit result
    // simple divide and conquer: do 32 bit mult and shift/add accordingly (schoolbook mutliplication)
    // d[0} and d[1] used for result
    // according to /crypto/src/main/java/de/fehrprice/crypto/run/PerformanceCheck.java:
    // ~ double speed of simple BigInteger multiplication
    public void umul64(fp256 res, long a, long b) {
    	long x0 = a & 0xFFFFFFFFL;
    	long x1 = a >>> 32;
    	long y0 = b & 0xFFFFFFFFL;
    	long y1 = b >>> 32;

        // high 64 bits:
        long m2 = x1 * y1;
        
        // low 64 bits:
        long m0 = x0 * y0;
        
        // middle 64 bits:
        long t1 = x0 * y1;
        long t2 = x1 * y0;
        long m1 = t1 + t2; // overflow possible
        long carry = (Long.compareUnsigned(m1, t1) < 0) ? 0x0100000000L : 0x00;
        
        // result
        long r1 = m2 + carry + (m1 >>> 32);
        long r0 = (m1 << 32) + m0;
        if (Long.compareUnsigned(r0, m0) < 0) {
        	r1++;
        }
        
    	// copy result to res
    	res.d[0] = r0;
    	res.d[1] = r1;
    }

	/**
	 * multiply 256 unsigned via 64 bit parts, reduce complexity by avoiding sub-mults outside 256 bit range
     * simple schoolbook mutliplication
     * according to /crypto/src/main/java/de/fehrprice/crypto/run/PerformanceCheck.java:
     * ~ 4x speed of simple BigInteger multiplication
	 * @param r
	 * @param a
	 * @param b
	 */
	public void umul(fp256 r, fp256 a, fp256 b) {
		// setup
		r.zero();
		fp256 m = zero();
		long a3 = a.d[3];
		long a2 = a.d[2];
		long a1 = a.d[1];
		long a0 = a.d[0];
		long b3 = b.d[3];
		long b2 = b.d[2];
		long b1 = b.d[1];
		long b0 = b.d[0];

		// a * b0:
		umul64(m, a0, b0);
		r.d[0] = m.d[0];
		r.d[1] = m.d[1];
		umul64(m, a1, b0);
		plusWithCarry(1, r, m);
		umul64(m, a2, b0);
		plusWithCarry(2, r, m);
		umul64(m, a3, b0);
		r.d[3] += m.d[0];
		
		// + a * b1 (<-- shift 64)
		umul64(m, a0, b1);
		plusWithCarry(1, r, m);
		umul64(m, a1, b1);
		plusWithCarry(2, r, m);
		umul64(m, a2, b1);
		r.d[3] += m.d[0];

		// + a * b2 (<-- shift 64)
		umul64(m, a0, b2);
		plusWithCarry(2, r, m);
		umul64(m, a1, b2);
		r.d[3] += m.d[0];
		
		// + a * b3 (<-- shift 64)
		umul64(m, a0, b3);
		r.d[3] += m.d[0];
	}

	private void plusWithCarry(int i, fp256 r, fp256 m) {
		long lo = r.d[i] + m.d[0];
		long hi = r.d[i+1] + m.d[1];
		if (Long.compareUnsigned(hi, r.d[i+1]) < 0) {
			//System.out.println("bad");
			if (i < 2) {
				r.d[i+2]++;
			}
		}
		r.d[i+1] = r.d[i+1] + m.d[1];
		if (Long.compareUnsigned(lo,  r.d[i]) < 0) {
			r.d[i+1]++;
		}
		r.d[i] = lo;
	}


}
