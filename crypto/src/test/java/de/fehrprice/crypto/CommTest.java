package de.fehrprice.crypto;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;

/**
 * test data here: http://ed25519.cr.yp.to/software.html
 *
 */
/**
 * Test Secure communication over HTTP
 *
 */
public class CommTest {
	
    public static boolean disableLongRunningTest = true;
	
	private static Ed25519 ed;
	private static Curve25519 x;
	private static AES aes;
	
	@BeforeAll
	public static void setUp() throws Exception {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
	}

	@AfterAll
	public static void tearDown() throws Exception {
	}

	/**
	 * Test unsigned message exchange - no protection against man-in-the-middle-attacks 
	 */
	@Test
	void testECDH() {
		String uBasePoint     = "0900000000000000000000000000000000000000000000000000000000000000";
		String alicePrivate = Conv.toString(aes.random(32));
		String bobPrivate = Conv.toString(aes.random(32));
		
		String alicePublic = x.x25519(alicePrivate, uBasePoint);
		String bobPublic = x.x25519(bobPrivate, uBasePoint);

		// Alice acts as client and calls bob:
		ECConnection comm = new ECConnection(x, ed, aes);
		String sessionKeyAlice = comm.initiateECDH(alicePrivate, bobPublic);
		
		// Bob receives the request:
		ECConnection comm2 = new ECConnection(x, ed, aes);
		String sessionKeybob = comm2.initiateECDH(bobPrivate, alicePublic);
		assertEquals(sessionKeybob, sessionKeyAlice);
	}
	
	@Test
	void testECDSA() {
		String alicePrivate = Conv.toString(aes.random(32));
		String bobPrivate = Conv.toString(aes.random(32));

		String alicePublic = ed.publicKey(alicePrivate);
		String bobPublic = ed.publicKey(bobPrivate);
		
		// Alice acts as client and calls Bob:
		ECConnection comm = new ECConnection(x, ed, aes);
		Session aliceSession = new Session();
		String message = comm.initiateECDSA(aliceSession, alicePrivate, alicePublic, "Alice");
		System.out.println("transfer message: " + message);
		
		// Bob receives the message and verifies:
		DTO dto = DTO.fromJsonString(message);
		assertTrue(dto.isInitClientCommand());
		assertTrue(comm.validateSender(dto, alicePublic));
		dto.id += "x";
		assertFalse(comm.validateSender(dto, alicePublic));
		
		// Bob answers, after that both client and server are able to construct the session key for AES
		Session bobSession = new Session();
		String initAnswer = comm.answerInitClient(bobSession, dto, bobPrivate, bobPublic);
		System.out.println("transfer message: " + initAnswer);
		
		// Alice receives the server ok message and returns the first AES encrypted block
		dto = DTO.fromJsonString(initAnswer);
		assertTrue(comm.validateSender(dto, bobPublic));
		byte[] sessionKeyAlice = comm.computeSessionKey(aliceSession.sessionPrivateKey, bobSession.sessionPublicKey);
		aliceSession.sessionAESKey = sessionKeyAlice;
		System.out.println("session key: " + sessionKeyAlice);
		
		// continue with AES: Alice sends message to Bob
		String aesMessage = "Niklas ist der Beste!";
		//String aesMessage = "Niklas";
		byte[] encrypted = comm.encryptAES(aliceSession, aesMessage);
		System.out.println("AES encrypted: " + Conv.toString(encrypted));
		
		// Bob receives the block and decrypts:
		byte[] sessionKeyBob = comm.computeSessionKey(bobSession.sessionPrivateKey, aliceSession.sessionPublicKey);
		bobSession.sessionAESKey = sessionKeyBob;
		String decryptedMessage = comm.decryptAES(bobSession, encrypted);
		System.out.println("decrypted message received by Bob: " + decryptedMessage);
		assertEquals(aesMessage, decryptedMessage);
		
		// intermediate: check session keys
		assertArrayEquals(sessionKeyAlice, sessionKeyBob);
	
		// Bob answers:
		String answer = "You have spoken the truth!";
		encrypted = comm.encryptAES(bobSession, answer);
		
		// Alice receives answer:
		decryptedMessage = comm.decryptAES(aliceSession, encrypted);
		System.out.println("decrypted message received by Alice: " + decryptedMessage);
		assertEquals(answer, decryptedMessage);
	}
	
	// execute ECDSA test multiple times for performance analysis
	//@Test
	void multiECDSATest() {
		for ( int i = 0; i < 1000; i++) {
			testECDSA();
		}
	}
	
	@Test
	void clientServerTest() {
		//Http
	}
}

