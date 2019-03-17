package de.fehrprice.crypto;

/**
 * SHA-512 implementation
 * Will only work for messages <= 2GB due to int overflow for array indexing  
 * http://csrc.nist.gov/publications/drafts/fips180-4/Draft-FIPS180-4_Feb2011.pdf
 */
public class SHA {

	byte[] msg = null;
	int pos = 0; // points to next unused pos in msg
	long[] hash = new long[8];  // the hash
	long[] w = new long[80]; // message schedule
	int blocks_processed = 0; // count 128 byte blocks

	public void startSha512Feed() {
		msg = new byte[128];
		pos = 0;
		blocks_processed = 0;
		System.arraycopy(H0, 0, hash, 0, 8);  // init with predefined hash values
	}
	
	public void feed(byte[] part_msg) {
		if ((part_msg.length + pos) < 128) {
			// we are still filling up this block
			System.arraycopy(part_msg, 0, msg, pos, part_msg.length);
			pos += part_msg.length;
			return;
		}
		// we can fill at least one block now:
		int part_used = 0; // how much bytes are used from this part?
		while (true) {
			// fill one block
			int to_fill = 128 - pos;
			System.arraycopy(part_msg, part_used, msg, pos, to_fill);
			processOneBlock(msg, 128);
			blocks_processed++;
			pos = 0;
			part_used += to_fill;
			int available = part_msg.length - part_used; 
			if (available < 128) {
				// fill remainder of part_msg, then return
				System.arraycopy(part_msg, part_used, msg, pos, available);
				pos += available;
				return;
			}
		}
	}
	
	private void processOneBlock(byte[] msg, int length) {
		if (length < 128) {
			// last block: prepare with padding
			byte[] last = new byte[length];
			System.arraycopy(msg, 0, last, 0, length);
			msg = pad1024(last, blocks_processed);
		}
		// calculation phase
		long[] block = new long[16];
		long a,b,c,d,e,f,g,h;
		for (int n = 0; n < msg.length/128; n++) {
			fillBlockFromMessage(block, msg, n);
			//printBlock(block);
			// fill message schedule:
			for (int t = 0; t < 16; t++) {
				w[t] = block[t];
			}
			for (int t = 16; t < 80; t++) {
				w[t] = sigmaLow1(w[t-2]) + w[t-7] + sigmaLow0(w[t-15]) + w[t-16];
			}
			a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3]; 
			e = hash[4]; f = hash[5]; g = hash[6]; h = hash[7]; 
			for (int t = 0; t < 80; t++) {
				long t1 = h + sigmaHigh1(e) + ch(e, f, g) + K[t] + w[t];
				long t2 = sigmaHigh0(a) + maj(a, b, c);
				h = g; g = f; f = e; e = d + t1;
				d = c; c = b; b = a; a = t1 + t2;
				
				long[] z = new long[8]; z[0] = a; z[1] = b; z[2] = c; z[3] = d; z[4] = e; z[5] = f; z[6] = g; z[7] = h; 
				//printhash(z, t);
			}
			// calculate hash for this block
			hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
			hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
		}
	}

	public byte[] endSha512Feed() {
		processOneBlock(msg, pos);
		return toByteArray(hash);
	}
	
	public byte[] sha512(String message) {
		return sha512(message.getBytes());
	}

	public byte[] sha512(byte[] message) {
		long[] hash = new long[8];  // the hash
		long[] w = new long[80]; // message schedule
		System.arraycopy(H0, 0, hash, 0, 8);  // init with predefined hash values
		// prepare phase
		msg = pad1024(message);
		// calculation phase
		long[] block = new long[16];
		long a,b,c,d,e,f,g,h;
		for (int n = 0; n < msg.length/128; n++) {
			fillBlockFromMessage(block, msg, n);
			//printBlock(block);
			// fill message schedule:
			for (int t = 0; t < 16; t++) {
				w[t] = block[t];
			}
			for (int t = 16; t < 80; t++) {
				w[t] = sigmaLow1(w[t-2]) + w[t-7] + sigmaLow0(w[t-15]) + w[t-16];
			}
			a = hash[0]; b = hash[1]; c = hash[2]; d = hash[3]; 
			e = hash[4]; f = hash[5]; g = hash[6]; h = hash[7]; 
			for (int t = 0; t < 80; t++) {
				long t1 = h + sigmaHigh1(e) + ch(e, f, g) + K[t] + w[t];
				long t2 = sigmaHigh0(a) + maj(a, b, c);
				h = g; g = f; f = e; e = d + t1;
				d = c; c = b; b = a; a = t1 + t2;
				
				long[] z = new long[8]; z[0] = a; z[1] = b; z[2] = c; z[3] = d; z[4] = e; z[5] = f; z[6] = g; z[7] = h; 
				//printhash(z, t);
			}
			// calculate hash for this block
			hash[0] += a; hash[1] += b; hash[2] += c; hash[3] += d;
			hash[4] += e; hash[5] += f; hash[6] += g; hash[7] += h;
		}
		return toByteArray(hash);
	}
	
	/**
	 * Pad input message to 1024 bit (128 byte)
	 * @param message
	 * @return
	 */
	public byte[] pad1024(byte[] m) {
		return pad1024(m, 0);
	}
	
	public byte[] pad1024(byte[] m, int previous_blocks) {
		long l = m.length * 8;
		// solve l + 1 + k /// 896 mod 1024
		long k = 896 - 1 - (l%1024);
		if (k < 0) k += 1024;
		//System.out.println(" k: " + k);
		long total_bitlen = l + 1 + k + 128;
		//System.out.println(" total: " + total_bitlen + " bits " + total_bitlen/8 + " bytes");
		int bytes_total = (int)total_bitlen/8;
		//int bytes_to_append = bytes_total - m.length;
		msg = new byte[bytes_total];
		System.arraycopy(m, 0, msg, 0, m.length); // rest will already be == 0
		msg[m.length] = (byte)0x80;
		byte a,b,c,d;
		int w = (int)l;  // TODO check for possible overflow
		w += previous_blocks * 128 * 8;
		a = (byte)((w & 0xff000000) >>> 24);
		b = (byte)((w & 0x00ff0000) >>> 16);
		c = (byte)((w & 0x0000ff00) >>> 8);
		d = (byte)((w & 0x000000ff));
		msg[bytes_total - 4] = a;
		msg[bytes_total - 3] = b;
		msg[bytes_total - 2] = c;
		msg[bytes_total - 1] = d;
		return msg;
	}
	
	private byte[] toByteArray(long[] hash) {
		byte[] res = new byte[hash.length*8];
		for (int i = 0; i < hash.length; i++) {
			long l = hash[i];
			res[i*8+0] = (byte)(l >>> 56);
			res[i*8+1] = (byte)((l&0x00ff000000000000L) >>> 48);
			res[i*8+2] = (byte)((l&0x0000ff0000000000L) >>> 40);
			res[i*8+3] = (byte)((l&0x000000ff00000000L) >>> 32);
			res[i*8+4] = (byte)((l&0x00000000ff000000L) >>> 24);
			res[i*8+5] = (byte)((l&0x0000000000ff0000L) >>> 16);
			res[i*8+6] = (byte)((l&0x000000000000ff00L) >>> 8);
			res[i*8+7] = (byte)((l&0x00000000000000ffL) );
		}
		return res;
	}

	private long ch(long x, long y, long z) {
		return (x & y) ^ (~x & z);
	}

	private long maj(long x, long y, long z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}

	private long sigmaHigh0(long x) {
		return Long.rotateRight(x, 28) ^ Long.rotateRight(x, 34) ^ Long.rotateRight(x, 39);
	}

	private long sigmaHigh1(long x) {
		return Long.rotateRight(x, 14) ^ Long.rotateRight(x, 18) ^ Long.rotateRight(x, 41);
	}

	private long sigmaLow0(long x) {
		return Long.rotateRight(x, 1) ^ Long.rotateRight(x, 8) ^ (x >>> 7);
	}

	private long sigmaLow1(long x) {
		return Long.rotateRight(x, 19) ^ Long.rotateRight(x, 61) ^ (x >>> 6);
	}

	private void printhash(long[] hash, int t) {
		System.out.println("[" + t + "] hash:");
		for (int y = 0; y < 2; y++) {
			for (int x = 0; x < 4; x++) {
				System.out.print(String.format("%016x", hash[y*4+x]) + " ");
			}
			System.out.println();
		}
	}

	private void printBlock(long[] block) {
		System.out.println("Block:");
		for (int i = 0; i < 16; i++) {
			System.out.println(" [" + i + "] " + String.format("%016x", block[i]));
		}
	}

	public long dword(byte[] b, int i) {
		return (b[i+0] & 0xffL) << 56 | (b[i+1] & 0xffL) << 48 | (b[i+2] & 0xffL) << 40 | (b[i+3] & 0xffL) << 32 |
		       (b[i+4] & 0xffL) << 24 | (b[i+5] & 0xffL) << 16 | (b[i+6] & 0xffL) << 8 | (b[i+7] & 0xffL);
	}

	private void fillBlockFromMessage(long[] block, byte[] message, int blocknum) {
		for (int i = 0; i < 16; i++) {
			long b = dword(message, blocknum * (16*8) + i*8);
			block[i] = b;
		}
		//System.out.println("long " + Long.toHexString(b));
	}

	private final long[] H0 = {
		0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
		0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
	};
	private static final long[] K = {
		0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
		0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
		0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
		0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
		0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
		0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
		0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
		0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
		0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
		0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
		0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
		0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
		0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
		0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
		0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
		0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
		0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
		0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
		0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
		0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
	};
	
}
