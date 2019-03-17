package de.fehrprice.crypto;

import java.util.Date;
import java.util.logging.Logger;

/**
 * AES 128/256 implementation. Pseudo Random Number Generator (PRNG) implementation based on AES.
 * http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 *
 */
public class AES {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		AES aes = new AES();
		aes.test();
	}

	private Logger logger = Logger.getLogger(AES.class.toString());
	
	private boolean weakRandomNumbers;

	public boolean isWeakRandomNumbers() {
		return weakRandomNumbers;
	}

	/**
	 * Construct AES instance with weak Pseudo Random Number Generator (PRNG).
	 * The PRNG is weak because the initial seed is calculated based on simple current time value which opens the door for 
	 * guessing the initial seed and consequently all produced random numbers.
	 * Use this constructor only for pure AES without PRNG usage or simple PRNG applications like test code.
	 */
	public AES() {
		weakRandomNumbers = true;
	}

	/**
	 * Construct AES instance with strong Pseudo Random Number Generator (PRNG).
	 * The PRNG can only be as strong as the initial seed.
	 * The seed value should be uniformly distributed, unpredictable and not repeatable.
	 * This class makes no attempt to check the seed value - that is completely up to the user of this class.
	 * As long as the initial seed is passed to the constructor the PRNG is considered strong.
	 * @param initialSeed 32 byte initial seed value
	 */
	public AES(byte[] initialSeed) {
		setSeed(initialSeed);
		weakRandomNumbers = false;
	}
	
	private void test() {
//		log.setLevel(Level.ALL);
//		log.fine("start AES test");
//		log.fine("end AES test");
//		log.severe("severe");
		//System.out.println("hi" + log.getFilter());
		int r = this.word((byte)0x80, (byte)0x90, (byte)0xa0, (byte)0xff);
		System.out.println(Integer.toHexString(r));
		r = this.word((byte)0x00, (byte)0x01, (byte)0x01, (byte)0x01);
		System.out.println(Integer.toHexString(r));
		r = this.word((byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04);
		System.out.println(Integer.toHexString(r));
		r = this.word((byte)0x10, (byte)0x20, (byte)0x30, (byte)0x40);
		System.out.println(Integer.toHexString(r));
		r = this.word((byte)0xff, (byte)0xfe, (byte)0xfd, (byte)0xfb);
		System.out.println(Integer.toHexString(r));
		
		
	}
	/*
	Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
	begin
		byte state[4,Nb]
		state = in
		AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
		for round = 1 step 1 to Nr–1
			SubBytes(state) // See Sec. 5.1.1
			ShiftRows(state) // See Sec. 5.1.2
			MixColumns(state) // See Sec. 5.1.3
			AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
		end for
		SubBytes(state)
		ShiftRows(state)
		AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
		out = state
	end

	Nb Number of state columns (32 bit words) (here: 4)
	Nk Number of 32 bit word for key (4,6,8)
	Nr Number of rounds (10,12,14)
	Rcon[] The round constant word array

	PLAINTEXT: 00112233445566778899aabbccddeeff
	KEY: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	CIPHER (ENCRYPT):
	round[ 0].input 00112233445566778899aabbccddeeff
	round[ 0].k_sch 000102030405060708090a0b0c0d0e0f
	round[ 1].start 00102030405060708090a0b0c0d0e0f0
	round[ 1].s_box 63cab7040953d051cd60e0e7ba70e18c
	round[ 1].s_row 6353e08c0960e104cd70b751bacad0e7
	round[ 1].m_col 5f72641557f5bc92f7be3b291db9f91a
	round[ 1].k_sch 101112131415161718191a1b1c1d1e1f
    *
    */

	//private byte[] key;
	
	private byte[] column = new byte[4];
	private byte[] column_copy = new byte[4];
	
	public byte[] cipher(byte[] key, byte[] in, int Nb, int Nr, int Nk, int [] waldi) {
		if (in.length != 16) {
			throw new NumberFormatException("AES requires exactly 128 bit input data length");
		}
//		if (Nk == 8) {
//			// aes 256
//			System.out.println("cipher key " + Conv.toString(key));
//			System.out.println("cipher block " + Conv.toString(in));
//		}
		byte[] state = new byte[4*Nb];
		assignToStateFromInput(state, in);
		//trace("input", in);
		int[] w = keyExpansion(key, Nk, Nb, Nr);
		addRoundKey(state, w, 0, Nb-1);
		//trace("start", state);
		for (int round = 1; round <= Nr-1; round++) {
			//System.out.println("round " + round);
			subBytes(state);
			//trace("s_box", state);
			shiftRows(state);
			//trace("s_row", state);
			mixColumns(state);
			//trace("s_mix", state);
			addRoundKey(state, w, round*Nb, (round+1)*Nb-1);
		}
		subBytes(state);
		//trace("s_box", state);
		shiftRows(state);
		//trace("s_row", state);
		addRoundKey(state, w, Nr*Nb, (Nr+1)*Nb-1);
		//trace("resul", state);
		return state;
	}

	public byte[] decipher(byte[] key, byte[] in, int Nb, int Nr, int Nk) {
		byte[] state = new byte[4*Nb];
		//assignToStateFromInput(state, in);
		System.arraycopy(in, 0, state, 0, state.length);
		//trace("input", in);
		//trace("dec input", in);
		int[] w = keyExpansion(key, Nk, Nb, Nr);
		addRoundKey(state, w, Nr*Nb, (Nr+1)*Nb-1);
		//trace("dec round key", state);
		//trace("start", state);
		for (int round = Nr-1; round >= 1; round--) {
			//System.out.println("round " + round);
			invShiftRows(state);
			//trace("s_row", state);
			invSubBytes(state);
			//trace("s_box", state);
			addRoundKey(state, w, round*Nb, (round+1)*Nb-1);
			invMixColumns(state);
			//trace("s_mix", state);
		}
		invShiftRows(state);
		//trace("s_row", state);
		invSubBytes(state);
		//trace("s_box", state);
		addRoundKey(state, w, 0, Nb-1);
		state = reorderStateToOutput(state);
		//trace("resul", state);
		return state;
	}

	public byte galoisFastMult(byte abyte, byte bbyte) {
		int a = abyte & 0xff;
		int b = bbyte & 0xff;
		return (byte)((a != 0 && b != 0) ? exptable[(logtable[a] + logtable[b]) % 255] : 0);
	}

	private void subBytes(byte[] state) {
		for (int i = 0; i < state.length; i++) {
			state[i] = (byte)sbox[0x000000ff & state[i]];
		}
		
	}

	private void invSubBytes(byte[] state) {
		for (int i = 0; i < state.length; i++) {
			state[i] = (byte)invSbox[0x000000ff & state[i]];
		}
		
	}

	private void shiftRows(byte[] state) {
		shift4BytesOne(state, 4);
		shift4BytesTwo(state, 8);
		shift4BytesThree(state, 12);
	}

	private void invShiftRows(byte[] state) {
		shift4BytesThree(state, 4);
		shift4BytesTwo(state, 8);
		shift4BytesOne(state, 12);
	}

	private void shift4BytesOne(byte[] state, int start) {
		byte s = state[start];
		state[start] = state[start+1];
		state[start+1] = state[start+2];
		state[start+2] = state[start+3];
		state[start+3] = s;
	}

	private void shift4BytesTwo(byte[] state, int start) {
		byte s1 = state[start];
		byte s2 = state[start+1];
		state[start] = state[start+2];
		state[start+1] = state[start+3];
		state[start+2] = s1;
		state[start+3] = s2;
	}

	private void shift4BytesThree(byte[] state, int start) {
		byte s = state[start+3];
		state[start+3] = state[start+2];
		state[start+2] = state[start+1];
		state[start+1] = state[start];
		state[start] = s;
	}

//	private void invShift4BytesOne(byte[] state, int start) {
//		byte s = state[start+3];
//		state[start+3] = state[start+2];
//		state[start+2] = state[start+1];
//		state[start+1] = state[start];
//		state[start] = s;
//	}
//
//	private void invShift4BytesTwo(byte[] state, int start) {
//		byte s1 = state[start];
//		byte s2 = state[start+1];
//		state[start] = state[start+2];
//		state[start+1] = state[start+3];
//		state[start+2] = s1;
//		state[start+3] = s2;
//	}
//
//	private void invShift4BytesThree(byte[] state, int start) {
//		byte s = state[start+3];
//		state[start+3] = state[start+2];
//		state[start+2] = state[start+1];
//		state[start+1] = state[start];
//		state[start] = s;
//	}

	private void mixColumns(byte[] state) {
		 
	    // Iterate over the 4 columns
	    for (int i = 0; i < 4; i++) {
	        // Construct one column by iterating over the 4 rows
	        for (int j = 0; j < 4; j++) {
	            column[j] = state[(j * 4) + i];
	        }
	 
	        // Apply the mixColumn on one column
	        mixColumn(column);
	 
	        // Put the values back into the state
	        for (int j = 0; j < 4; j++) {
	            state[(j * 4) + i] = column[j];
	        }
	    }
	}

	void mixColumn(byte[] column)
	{
	 
	    for(int i = 0; i < 4; i++) {
	        column_copy[i] = column[i];
	    }
	 
	    column[0] = (byte)(
	    	galoisFastMult(column_copy[0], (byte)2) ^
		    galoisFastMult(column_copy[1], (byte)3) ^
		    galoisFastMult(column_copy[2], (byte)1) ^
		    galoisFastMult(column_copy[3], (byte)1));
	 
	    column[1] = (byte)(
	    	galoisFastMult(column_copy[0], (byte)1) ^
		    galoisFastMult(column_copy[1], (byte)2) ^
		    galoisFastMult(column_copy[2], (byte)3) ^
		    galoisFastMult(column_copy[3], (byte)1));
	 
	    column[2] = (byte)(
	    	galoisFastMult(column_copy[0], (byte)1) ^
		    galoisFastMult(column_copy[1], (byte)1) ^
		    galoisFastMult(column_copy[2], (byte)2) ^
		    galoisFastMult(column_copy[3], (byte)3));
	 
	    column[3] = (byte)(
	    	galoisFastMult(column_copy[0], (byte)3) ^
		    galoisFastMult(column_copy[1], (byte)1) ^
		    galoisFastMult(column_copy[2], (byte)1) ^               
		    galoisFastMult(column_copy[3], (byte)2));
	}	
	
	private void invMixColumns(byte[] state) {
		 
	    // Iterate over the 4 columns
	    for (int i = 0; i < 4; i++) {
	        // Construct one column by iterating over the 4 rows
	        for (int j = 0; j < 4; j++) {
	            column[j] = state[(j * 4) + i];
	        }
	 
	        // Apply the mixColumn on one column
	        invMixColumn(column);
	 
	        // Put the values back into the state
	        for (int j = 0; j < 4; j++) {
	            state[(j * 4) + i] = column[j];
	        }
	    }
	}

	void invMixColumn(byte[] column)
	{
	 
	    for(int i = 0; i < 4; i++) {
	        column_copy[i] = column[i];
	    }
	 
	    column[0] = (byte)(
	    	galoisFastMult(column_copy[0], (byte) 0x0e) ^
		    galoisFastMult(column_copy[1], (byte) 0x0b) ^
		    galoisFastMult(column_copy[2], (byte) 0x0d) ^
		    galoisFastMult(column_copy[3], (byte) 0x09));
	 
	    column[1] = (byte)(
	    	galoisFastMult(column_copy[0], (byte) 0x09) ^
		    galoisFastMult(column_copy[1], (byte) 0x0e) ^
		    galoisFastMult(column_copy[2], (byte) 0x0b) ^
		    galoisFastMult(column_copy[3], (byte) 0x0d));
	 
	    column[2] = (byte)(
	    	galoisFastMult(column_copy[0], (byte) 0x0d) ^
		    galoisFastMult(column_copy[1], (byte) 0x09) ^
		    galoisFastMult(column_copy[2], (byte) 0x0e) ^
		    galoisFastMult(column_copy[3], (byte) 0x0b));
	 
	    column[3] = (byte)(
	    	galoisFastMult(column_copy[0], (byte) 0x0b) ^
		    galoisFastMult(column_copy[1], (byte) 0x0d) ^
		    galoisFastMult(column_copy[2], (byte) 0x09) ^               
		    galoisFastMult(column_copy[3], (byte) 0x0e));
	}	
	
	private void addRoundKey(byte[] state, int[] w, int start, int end) {
		//trace("k_sch", w, start);
		//System.out.println("state.length == [start,end]*4 " + (state.length == (end-start+1)*4));
		for (int i = 0; i <= end-start; i++ ) {
			int schedule = w[start + i];
			byte b4 = (byte)((schedule & 0xff000000) >>> 24);
			byte b3 = (byte)((schedule & 0x00ff0000) >>> 16);
			byte b2 = (byte)((schedule & 0x0000ff00) >>> 8);
			byte b1 = (byte)((schedule & 0x000000ff) );
//			state[i*4] ^= b4;
//			state[i*4 +1] ^= b3;
//			state[i*4 +2] ^= b2;
//			state[i*4 +3] ^= b1;
			state[i] ^= b4;
			state[4+i] ^= b3;
			state[8+i] ^= b2;
			state[12+i] ^= b1;
		}
	}
	/*
	KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
	begin
	word temp
	i = 0
	while (i < Nk)
	  w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
	  i = i+1
	end while
	i = Nk
	while (i < Nb * (Nr+1)]
	  temp = w[i-1]
	  if (i mod Nk = 0)
	    temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
	  else if (Nk > 6 and i mod Nk = 4)
	    temp = SubWord(temp)
	  end if
	  w[i] = w[i-Nk] xor temp
	  i = i + 1
	end while
	end
	 */
	
	public int[] keyExpansion(byte[] key, int Nk, int Nb, int Nr) {
		//byte[] key = new byte[4];
		//assignToStateFromInput(key, origkey);
		
		int w[] = new int[Nb * (Nr+1)];
		int i = 0;
		while ( i < Nk) {
			w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
			i++;
		}
		i = Nk;
		while (i < Nb * (Nr+1)) {
			int temp = w[i-1];
			if (i % Nk == 0) {
				temp = subWord(rotWord(temp)) ^ rcon(i/Nk);
			} else if (Nk > 6 && i % Nk == 4) {
				temp = subWord(temp); 
			}
			w[i] = w[i-Nk] ^ temp;
			i++;
		}
		return w;
	}
	
	private int rcon(int i) {
		int ret = 0;
		if (i <= 8) {
		  ret = 2<<(i+22);
		} else {
			ret = rcon(i-1);
			if ((ret & 0x80000000) == 0) ret = ret << 1;
			else ret = ret << 1 ^ (0x1b << 24);
		}
		//System.out.println("                  " + i + " " + Integer.toHexString(ret));
		return ret;
	}

	private int subWord(int rotWord) {
		int a,b,c,d; 
		a = (rotWord & 0xff000000) >>> 24;
		b = (rotWord & 0x00ff0000) >>> 16;
		c = (rotWord & 0x0000ff00) >>> 8;
		d = (rotWord & 0x000000ff);
		a = sbox[a];
		b = sbox[b];
		c = sbox[c];
		d = sbox[d];
		return word(a, b, c, d);
	}

	private int rotWord(int rot) {
		int movebyte = (rot & 0xff000000) >>> 24;
		return (rot << 8) | movebyte;
	}

	public int word(byte a, byte b, byte c, byte d) {
		return (a & 0xff) << 24 | (b & 0xff) << 16 | (c & 0xff) << 8 | (d & 0xff);
	}

	public int word(int a, int b, int c, int d) {
		return a << 24 | b << 16 | c << 8 | d;
	}

	private void assignToStateFromInput(byte[] state, byte[] in) {
		//System.arraycopy(in, 0, state, 0, in.length);
		for (int i = 0; i < 4; i++) {
			state[i] = in[i*4];
			state[4+i] = in[i*4+1];
			state[8+i] = in[i*4+2];
			state[12+i] = in[i*4+3];
		}
	}

	private byte[] reorderStateToOutput(byte[] state) {
		byte[] out = new byte[state.length];
		//System.arraycopy(in, 0, state, 0, in.length);
		for (int i = 0; i < 4; i++) {
			out[i] = state[i*4];
			out[4+i] = state[i*4+1];
			out[8+i] = state[i*4+2];
			out[12+i] = state[i*4+3];
		}
		return out;
	}

	public void setKey(byte[] key) {
		//this.key = key;
	}

	int[] sbox = {
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
			};
	int[] invSbox = {
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
			};

	private int[] exptable = {
			0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
			0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
			0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
			0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
			0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
			0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
			0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
			0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
			0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
			0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
			0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
			0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
			0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
			0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
			0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
			0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01
	};
	private int[] logtable = {
			0x00, 0xff, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
			0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
			0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
			0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
			0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
			0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
			0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
			0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
			0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
			0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
			0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
			0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
			0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
			0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
			0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
			0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07
	};

	private void trace(String info, byte[] arr) {
		if (true) {
			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < arr.length; i++) {
				String hex = Integer.toHexString(arr[i] & 0xff);
				if (hex.length() % 2 == 1) hex = "0" + hex;
				buf.append(/*" " + */hex);
			}
			System.out.println(info + "  " + buf);
		}
	}

	private void trace(String info, int[] arr, int start) {
		if (true) {
			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < 4; i++) {
				buf.append(String.format("%08x", arr[start + i]));
			}
			System.out.println(info + "  " + buf);
		}
	}
	
	/**
	 * Transpose hex string. Do not use.
	 * @param bytes
	 * @return
	 */
	public String toStringTransposed(byte[] bytes) {
		byte[] trans = new byte[bytes.length];
		for (int i = 0; i < trans.length; i++) {
			int x = i % 4;
			int y = i / 4;
			trans[x*4 + y] = bytes[i];
		}
		return Conv.toString(trans);
	}

	public byte[] decipher256SingleBlock(byte[] key, byte[]  input) {
		return decipher(key, input, 4, 14, 8);
	}
	
	public byte[] decipher256SingleBlock(String key, byte[]  input) {
		return decipher(Conv.toByteArray(key), input, 4, 14, 8);
	}
	
	public byte[] cipher256SingleBlock(byte[] key, byte[] message) {
		return cipher(key, message, 4, 14, 8, null);
	}

	public byte[] cipher256SingleBlock(String keyHex, byte[] message) {
		return cipher(Conv.toByteArray(keyHex), message, 4, 14, 8, null);
	}

	public byte[] cipher256SingleBlock(String keyHex, String plaintextHex) {
		return cipher(Conv.toByteArray(keyHex), Conv.toByteArray(plaintextHex), 4, 14, 8, null);
	}

	public byte[] cipher128SingleBlock(String keyHex, String plaintextHex) {
		return cipher(Conv.toByteArray(keyHex), Conv.toByteArray(plaintextHex), 4, 10, 4, null);
	}

	/**
	 * Code the block number into the first 4 bytes.
	 * 4 bytes are interpreted as little 
	 * @param key
	 * @param block
	 * @param i
	 * @return
	 */
	private byte[] cipher256SingleBlockWithNumbering(byte[] key, byte[] block, int i) {
		long block_value = Conv.bytesToUnsignedLong(block);
		block_value += i;
		Conv.UnsingedLongToByteArray(block_value, block);
		return cipher256SingleBlock(key, block);
	}

	private byte[] decipher256SingleBlockWithNumbering(byte[] key, byte[] block, int i) {
		byte[] dec = decipher256SingleBlock(key, block);
		long dec_value = Conv.bytesToUnsignedLong(dec);
		dec_value -= i;
		Conv.UnsingedLongToByteArray(dec_value, dec);
		return dec;
	}

	/**
	 * Encrypt message. Breaks input up to 16 byte chunks and encrypts them with ASE-256.
	 * Last byte of last block contain number of null bytes added to end of message.
	 * Each input block will have its block number added (beginning with 0 for first block)
	 * to prevent same input blocks to yield same cypher text.  
	 * @param key
	 * @param message
	 * @return cypher text, length is multiple of 16
	 */
	public byte[] cipher256(byte[] key, byte[] message) {
		int messageLength = message.length;
		// calc how many full blocks we have:
		int fullBlocks = messageLength / 16;
		int messageLengthInLastBlock = messageLength % 16;
		int targetBlocks = fullBlocks;
		// messageLengthInLastBlock < 15, otherwise we would have one more full block
		targetBlocks++; // add one for final block
		byte[] target = new byte[targetBlocks * 16];
		byte[] block = new byte[16];
		for (int i = 0; i < fullBlocks; i++) {
			System.arraycopy(message, i*16, block, 0, 16);
			byte[] crypt = cipher256SingleBlockWithNumbering(key, block, i);
			System.arraycopy(crypt, 0, target, i*16, 16);
		}
		// handle last block:
		System.arraycopy(message, fullBlocks * 16, block, 0, messageLengthInLastBlock);
		// fill last block with 0
		for (int i = messageLengthInLastBlock; i < 15; i++) {
			block[i] = 0;
		}
		// set number of bytes to discard in last byte of final buffer:
		int discard = 16-messageLengthInLastBlock;
		block[15] = (byte) discard;
		byte[] crypt = cipher256SingleBlockWithNumbering(key, block, targetBlocks-1);
		System.arraycopy(crypt, 0, target, fullBlocks*16, 16);
		return target;
	}
	
	public byte[] decipher256(byte[] key, byte[] enc) {
		if (enc.length % 16 != 0) {
			throw new NumberFormatException("decipher input not blocked (must be mutliple of 16 bytes");
		}
		int inputBlocks = enc.length / 16;
		byte[] block = new byte[16];
		System.arraycopy(enc, (inputBlocks-1)*16, block, 0, 16);
		byte[] decryptedLastBlock = decipher256SingleBlockWithNumbering(key, block, inputBlocks - 1);
		// we have to decipher last block first, to get the message length:
		// used bytes of last block are in last byte:
		byte last_byte = decryptedLastBlock[15];
		int messageLengthInLastBlock = 16 - ((int) last_byte);
		int messageLength = (inputBlocks-1) * 16 + messageLengthInLastBlock;
		// allocate decipher buffer for full message:
		byte[] target = new byte[messageLength]; 
		// decipher all blocks except the last one:
		for ( int i = 0; i < (inputBlocks-1); i++) {
			System.arraycopy(enc, i*16, block, 0, 16);
			byte[] decrypt = decipher256SingleBlockWithNumbering(key, block, i);
			System.arraycopy(decrypt, 0, target, i*16, 16);
		}
		// handle last block:
		System.arraycopy(decryptedLastBlock, 0, target, (inputBlocks-1)*16, messageLengthInLastBlock);
		return target;
	}

	/* random numbers
	 * based on 256 bit/32 byte seeds that are used as key and plaintext for aes128.
	 * each aes128 call generates more 128 bits/16 bytes random numbers that are used as next plaintext  
	 */
	
	private byte[] seed = null;
	private int used = 0;
	
	/**
	 * Set initial seed used for random number generator.
	 * @param myseed 32 bytes
	 */
	public void setSeed(byte[] myseed) {
		if (myseed == null || myseed.length < 32) {
			throw new NumberFormatException("invalid seed");
		}
		seed = new byte[32];
		used = 0;
		System.arraycopy(myseed, 0, seed, 0, 32);
	}
	
	/**
	 * generate 16 new random bytes and put them in the first half of the seed buffer
	 */
	private void randomRun() {
		if (seed == null) {
			seed = calculateSeed();
			logger.severe("AES PRNG cannot run without seed!");
			throw new NumberFormatException("no seed for AES");
		}
		byte[] text = new byte[16];
		byte[] key = new byte[16];
		System.arraycopy(seed, 0, text, 0, 16);
		System.arraycopy(seed, 16, key, 0, 16); // not necessary every time, but play save if someone changed seed manually
		byte[] rand = cipher(key, text, 4, 10, 4, null);
		System.arraycopy(rand, 0, seed, 0, 16);
	}

	private byte[] calculateSeed() {
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

	private byte nextRandomByte() {
		if (used == 0) {
			randomRun(); // new aes run necessary
		}
		byte randomByte = seed[used];
		used++;
		if (used == 16) used = 0;
		return randomByte;
	}
	
	public byte[] random(int length) {
		byte[] rand = new byte[length];
		for (int i = 0; i < length; i++) {
			rand[i] = nextRandomByte();
		}
		return rand;
	}

}
