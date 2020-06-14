package de.fehrprice.crypto;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Long4Test {

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	@Test
	void test() {
		Long4 l = new Long4();
		//System.out.println("" + l); // Long4 [l0=0x00000000, l1=0x00000000, l2=0x00000000, l3=0x00000000]
		assertEquals(new Long4(0L, 0L, 0L, 0L), l);
		//fail("Not yet implemented");
		
		BigInteger b = new BigInteger("1");
		l = new Long4(b);
		assertEquals(new Long4(0L, 0L, 0L, 1L), l);
		
		b = b.subtract(BigInteger.TWO);
		l = new Long4(b);
		assertEquals(new Long4(0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL, 0xffffffffffffffffL), l);
	}

}
