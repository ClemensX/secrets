package de.fehrprice.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Base64;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Test Base64 encoding/decoding as described in RFC: https://tools.ietf.org/html/rfc4648
 *
 */
public class Base64Test {

	@BeforeAll
	public static void setUp() throws Exception {
	    System.out.println("Base64Test");
	}

	@AfterAll
	public static void tearDown() throws Exception {
	}

	@Test
	public void testEncoding() {
		assertEquals("", Base64.getEncoder().encodeToString("".getBytes()));
		assertEquals("Zg==", Base64.getEncoder().encodeToString("f".getBytes()));
		assertEquals("Zm8=", Base64.getEncoder().encodeToString("fo".getBytes()));
		assertEquals("Zm9v", Base64.getEncoder().encodeToString("foo".getBytes()));
		assertEquals("Zm9vYg==", Base64.getEncoder().encodeToString("foob".getBytes()));
		assertEquals("Zm9vYmE=", Base64.getEncoder().encodeToString("fooba".getBytes()));
		assertEquals("Zm9vYmFy", Base64.getEncoder().encodeToString("foobar".getBytes()));
	}

	@Test
	public void testDecoding() {
		assertEquals("", new String(Base64.getDecoder().decode("")));
		assertEquals("f", new String(Base64.getDecoder().decode("Zg=="))); 
		assertEquals("fo", new String(Base64.getDecoder().decode("Zm8=")));
		assertEquals("foo", new String(Base64.getDecoder().decode("Zm9v")));
		assertEquals("foob", new String(Base64.getDecoder().decode("Zm9vYg==")));
		assertEquals("fooba", new String(Base64.getDecoder().decode("Zm9vYmE=")));
		assertEquals("foobar", new String(Base64.getDecoder().decode("Zm9vYmFy")));
	}

}
