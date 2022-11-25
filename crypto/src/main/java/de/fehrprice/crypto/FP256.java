package de.fehrprice.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * An efficient library for 256 bit modular integer arithmetic
 * Adapted from C source code: https://github.com/piggypiggy/fp256
 * 
 * Needed for speeding up Edwards curve calculations.
 * We need: add, subtract, multiply, modulo, modular exponentiation (modPow) 
 * done and tested: add, subtract
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
}
