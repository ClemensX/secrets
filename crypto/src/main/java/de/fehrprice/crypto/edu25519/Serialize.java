package de.fehrprice.crypto.edu25519;

import static de.fehrprice.crypto.edu25519.Field.s64Array;
import static de.fehrprice.crypto.edu25519.Field.s64Array.IS_ODD;
import static de.fehrprice.crypto.edu25519.Montgomery.print_s64;

public class Serialize {
	
	private static int MASK_L25 = 0x1ffffff;
	private static int MASK_L26 = 0x3ffffff;
	
	
	/*
	 * As the serialization code is quite boring, it was taken from Adam Langleys Donna Code:
	 * https://github.com/agl/curve25519-donna/blob/master/LICENSE.md
	 */

	private static int buildIntFromBytes(byte lo, byte b2, byte b3, byte hi) {
		int r = 0;
		r |= lo & 0x000000ff;
		r |= (b2 << 8) & 0x0000ff00;
		r |= (b3 << 16) & 0x00ff0000;
		r |= (hi << 24) & 0xff000000;
		return r;
	}
/***
 * Assigns a polynomial coefficient by shuffling the byte array.
 * Helper function for deserialize.
 * @param poly Pointer to polynomial
 * @param bytes pointer to input bytes
 * @param index index of coefficient
 * @param offset offset in bytes at which to start
 * @param cutoff How many bits have to be cut off at the end of the coeff (because they were part of the previous coeff)
 * @param mask How many bits to keep (26 for even index, 25 for odd...)
 */
	private static void assign_coeff(
			s64Array poly, byte[] bytes, int index, int offset, int cutoff, int mask) {
		//print_s64("str", poly);
		poly.it[index] = buildIntFromBytes(bytes[offset + 0], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
		//poly.it[index] = ((int) bytes[offset + 0]) | ((int) bytes[offset + 1]) << 8 | ((int) bytes[offset + 2]) << 16 |
		//		((int) bytes[offset + 3]) << 24;
		poly.it[index] >>= cutoff;
		poly.it[index] &= mask;
		//print_s64("end", poly);
	}

	/***
	 * Turn a 32 byte string into polynomial form.
	 * @param poly Output Poly, array of 10 64 bit limbs
	 * @param bytes Little endian 32B byte array
	 */
	public static void deserialize(s64Array poly, byte[] bytes) {
//		System.out.print("des bytes ");
//		for (int i = 31; i >= 0; --i) {
//			byte cur_byte = bytes[i];
//			System.out.printf("%02x ", cur_byte);
//		}
//		System.out.print("\n");
		// This is hard coded, just so we don't need to compute anything at runtime
		assign_coeff(poly, bytes, 0, 0, 0, MASK_L26);
		assign_coeff(poly, bytes, 1, 3, 2, MASK_L25);
		assign_coeff(poly, bytes, 2, 6, 3, MASK_L26);
		assign_coeff(poly, bytes, 3, 9, 5, MASK_L25);
		assign_coeff(poly, bytes, 4, 12, 6, MASK_L26);
		assign_coeff(poly, bytes, 5, 16, 0, MASK_L25);
		assign_coeff(poly, bytes, 6, 19, 1, MASK_L26);
		assign_coeff(poly, bytes, 7, 22, 3, MASK_L25);
		assign_coeff(poly, bytes, 8, 25, 4, MASK_L26);
		assign_coeff(poly, bytes, 9, 28, 6, MASK_L25);
		
		//print_s64("poly", poly);
	}
	
	
	/* s32_eq returns 0xffffffff iff a == b and zero otherwise. */
	private static int s32_eq(int a, int b) {
		a = ~(a ^ b);
		a &= a << 16;
		a &= a << 8;
		a &= a << 4;
		a &= a << 2;
		a &= a << 1;
		return a >> 31;
	}

	/* s32_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
	 * both non-negative. */
	private static int s32_gte(int a, int b) {
		a -= b;
		/* a >= 0 iff a >= b. */
		return ~(a >> 31);
	}

	/***
	 * Turn a reduced polynomial into a 32 byte little endian array.
	 * @param bytes Little endian 32B byte array
	 * @param poly Reduced output Poly
	 */
	public static void serialize(byte[] bytes, s64Array poly) {
		/*
		 * This code is largely taken from Adam Langley's donna implementation.
		 * It makes sure that we evaluate the polynomial at 1 and takes care of
		 * negative coefficients in a time-invariant manner.
		 */
		int i;
		int j;
		int[] input = new int[10];
		int mask, carry;
		
		// coefficients are < 2^26, so s32 works.
		for (i = 0; i < 10; i++) {
			input[i] = (int)poly.it[i];
		}
		
		/* Make all coefficients positive, by borrowing from higher coefficients.
		 * This always works, since we can "add" the 25th (odd case) and 26th (even case)
		 * bit to a coefficient and "subtract" the equivalent bit in the higher order
		 * coefficient.
		 */
		// We need two iterations, since input[0] might be negative after the first one.
		for (j = 0; j < 2; ++j) {
			for (i = 0; i < 9; ++i) {
				if (IS_ODD(i)) {
					mask = input[i] >> 31;
					carry = -((input[i] & mask) >> 25);
					input[i] = input[i] + (carry << 25);
					input[i + 1] = input[i + 1] - carry;
				} else {
					mask = input[i] >> 31;
					carry = -((input[i] & mask) >> 26);
					input[i] = input[i] + (carry << 26);
					input[i + 1] = input[i + 1] - carry;
				}
			}
			/* input[9] is the highest used coefficient in the reduced form, so
			 * it is not possible to borrow from a higher coeff.
			 * However, since we work mod 2^255-19, we can borrow from input[0]
			 * by multiplying the carry by 19.
			 * This is possible because it would affect the highest bits in input[9],
			 * which multiplied by 19 would end up in input[10], which would affect
			 * input[0] after reduction.
			 */
			mask = input[9] >> 31;
			carry = -((input[9] & mask) >> 25);
			input[9] = input[9] + (carry << 25);
			input[0] = input[0] - (carry * 19);
		}


    /* The first borrow-propagation pass above ended with every limb
       except (possibly) input[0] non-negative.

       If input[0] was negative after the first pass, then it was because of a
       carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
       one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.

       In the second pass, each limb is decreased by at most one. Thus the second
       borrow-propagation pass could only have wrapped around to decrease
       input[0] again if the first pass left input[0] negative *and* input[1]
       through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
       and this last borrow-propagation step will leave input[1] non-negative. */
		
		mask = input[0] >> 31;
		carry = -((input[0] & mask) >> 26);
		input[0] = input[0] + (carry << 26);
		input[1] = input[1] - carry;
		
		/* All input[i] are now non-negative. However, there might be values between
		 * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide. */
		for (j = 0; j < 2; j++) {
			for (i = 0; i < 9; i++) {
				if ((i & 1) == 1) {
                int carry2 = input[i] >> 25;
					input[i] &= 0x1ffffff;
					input[i + 1] += carry2;
				} else {
                int carry2 = input[i] >> 26;
					input[i] &= 0x3ffffff;
					input[i + 1] += carry2;
				}
			}
			
			{
            int carry2 = input[9] >> 25;
				input[9] &= 0x1ffffff;
				input[0] += 19 * carry2;
			}
		}
		/* If the first carry-chain pass, just above, ended up with a carry from
		 * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
		 * < 2^26 + 2*19, because the carry was, at most, two.
		 *
		 * If the second pass carried from input[9] again then input[0] is < 2*19 and
		 * the input[9] -> input[0] carry didn't push input[0] out of bounds. */
		
		/* It still remains the case that input might be between 2^255-19 and 2^255.
		 * In this case, input[1..9] must take their maximum value and input[0] must
		 * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed. */
		mask = s32_gte(input[0], 0x3ffffed);
		for (i = 1; i < 10; i++) {
			if ((i & 1) == 1) {
				mask &= s32_eq(input[i], 0x1ffffff);
			} else {
				mask &= s32_eq(input[i], 0x3ffffff);
			}
		}
		
		/* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
		 * this conditionally subtracts 2^255-19. */
		input[0] -= mask & 0x3ffffed;
		
		for (i = 1; i < 10; i++) {
			if ((i & 1) == 1) {
				input[i] -= mask & 0x1ffffff;
			} else {
				input[i] -= mask & 0x3ffffff;
			}
		}
		
		input[1] <<= 2;
		input[2] <<= 3;
		input[3] <<= 5;
		input[4] <<= 6;
		input[6] <<= 1;
		input[7] <<= 3;
		input[8] <<= 4;
		input[9] <<= 6;
		bytes[0] = 0;
		bytes[16] = 0;
		F(bytes, input, 0, 0);
		F(bytes, input, 1, 3);
		F(bytes, input, 2, 6);
		F(bytes, input, 3, 9);
		F(bytes, input, 4, 12);
		F(bytes, input, 5, 16);
		F(bytes, input, 6, 19);
		F(bytes, input, 7, 22);
		F(bytes, input, 8, 25);
		F(bytes, input, 9, 28);
	}

	private static void F(byte[] bytes, int[] input, int i, int s) {
		bytes[s+0] |=  input[i] & 0xff;
		bytes[s+1]  = (byte) ((input[i] >> 8) & 0xff);
		bytes[s+2]  = (byte) ((input[i] >> 16) & 0xff);
		bytes[s+3]  = (byte) ((input[i] >> 24) & 0xff);
	}
	
}
