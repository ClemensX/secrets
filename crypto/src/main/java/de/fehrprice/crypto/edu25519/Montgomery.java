package de.fehrprice.crypto.edu25519;

import de.fehrprice.crypto.edu25519.Field.s64Array;
import static de.fehrprice.crypto.edu25519.Field.s64Array.COPY_ELEM;
import static de.fehrprice.crypto.edu25519.Field.s64Array.*;
public class Montgomery {

	public static void print_s64(String name, s64Array src) {
		System.out.print(name + " ");
		for (int i = 0; i < 10; i++) {
			System.out.printf("%016x ", src.it[i]);
		}
		System.out.println();
	}
	public static class point {
		public point() {
			x = new s64Array();
			z = new s64Array();
		}
		public s64Array x;
		public s64Array z;
	} ;
	
	/**
	 * Function performing on step in the montgomery ladder.
	 * See [2] and [3] for specifics.
	 * @param res_double Result of 2xa
	 * @param res_add Result of a + c
	 * @param a Operand 1 const
	 * @param c Operand 2 const
	 * @param base X value of base point const
	 */
	static void double_add(point res_double, point res_add, point a, point c, s64Array base) {
		s64Array A = new s64Array();
		s64Array B = new s64Array();
		s64Array C = new s64Array();
		s64Array D = new s64Array();
		s64Array E = new s64Array();
		s64Array F = new s64Array();
		s64Array G = new s64Array();
		s64Array H = new s64Array();
		
		s64Array.COPY_ELEM(A, a.x);
		s64Array.COPY_ELEM(B, a.z);
		s64Array.COPY_ELEM(C, c.x);
		s64Array.COPY_ELEM(D, c.z);
//		print_s64("A",A);
//		print_s64("B",B);
//		print_s64("C",C);
//		print_s64("D",D);
		
		s64Array.add(A, B);
		s64Array.sub(B, a.x);
		
		s64Array.add(C, D);
		s64Array.sub(D, c.x);
		
		s64Array.mul_reduced(E, A, D);
		s64Array.mul_reduced(F, B, C);
		
		s64Array.COPY_ELEM(D, E);
		s64Array.add(D, F);
		s64Array.sub(E, F);
		
		// Calculate result of a + c
		s64Array.square_reduced(G, D);
		s64Array.square_reduced(H, E);
		s64Array.mul_reduced(E, H, base);
		
		// Save result of a + c
		COPY_ELEM(res_add.x, G);
		COPY_ELEM(res_add.z, E);
		
		// Calculate result of 2a
		square_reduced(G, A);
		square_reduced(H, B);
		mul_reduced(A, G, H);
		COPY_ELEM(res_double.x, A);
		
		// H = G - H
		sub(H, G);
		
		// C = 121665 * (G - H)
		mul_constant(C, H);
		reduce_coefficients(C);
		add(G, C);
		// D = (G-h) * (G + 121665 * (G - H))
		mul_reduced(D, H, G);
		COPY_ELEM(res_double.z, D);
		//print_s64("r", res_double.z);
	}
	
	/**
	 * Constant time way to swap two points based on parameter.
	 * If swap is 1, a and b will be swapped. If swap is zero, they won't.
	 * See [3] for description of this.
	 * @param a Operand 1
	 * @param b Operand 2
	 * @param swap Decision Maker (has to be 0 or 1)
	 */
	static void swap_points(point a, point b, long swap) {
		int i;
		int mask = (int) -swap;
		int x;
		
		for (i = 0; i < 10; ++i) {
			x = mask & (((int) a.x.it[i]) ^ ((int) b.x.it[i]));
			a.x.it[i] = ((int) a.x.it[i]) ^ x;
			b.x.it[i] = ((int) b.x.it[i]) ^ x;
			
			x = mask & (((int) a.z.it[i]) ^ ((int) b.z.it[i]));
			a.z.it[i] = ((int) a.z.it[i]) ^ x;
			b.z.it[i] = ((int) b.z.it[i]) ^ x;
		}
	}

	/**
	 * Montgomery ladder using only X/Z coordinates. See [2] for details on the algorithm.
	 * @param result Resulting point with X/Z value. Result = scalar x basepoint
	 * @param scalar Scalar to multiply on basepoint (const)
	 * @param basepoint x value of the base point to use for scalar multiplication (const)
	 */
	public static void montgomery_ladder(point result, byte[] scalar, s64Array basepoint) {
		point A = new point();
		point B = new point();
		point C = new point();
		point D = new point();
		A.x.it[0] = 1;
		A.z.it[0] = 0;
		B.x.it[0] = 0;
		B.z.it[0] = 1;
		C.x.it[0] = 0;
		C.z.it[0] = 1;
		D.x.it[0] = 0;
		D.z.it[0] = 1;
	
		//print_s64("C.x", C.x);
		point op_a = A;
		point op_b = B;
		point res_double = C;
		point res_add = D;
		point tmp = new point();
		
		int i, j;
		byte cur_byte, cur_bit;
		
		s64Array.COPY_ELEM(B.x, basepoint);
		
		for (i = 31; i >= 0; --i) {
			cur_byte = scalar[i];
			//System.out.print("scalar %d %02x\n".formatted(i, cur_byte));
			for (j = 7; j >= 0; --j) {
				cur_bit = (byte)((cur_byte >> j) & 1);
				//System.out.print("%d".formatted(cur_bit));
				
				swap_points(op_a, op_b, cur_bit);
				double_add(res_double, res_add, op_a, op_b, basepoint);
				swap_points(res_double, res_add, cur_bit);
				
				tmp = res_double;
				res_double = op_a;
				op_a = tmp;
				
				tmp = res_add;
				res_add = op_b;
				op_b = tmp;
			}
		}
		COPY_ELEM(result.x, op_a.x);
		COPY_ELEM(result.z, op_a.z);
	}
}
