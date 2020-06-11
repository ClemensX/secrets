package de.fehrprice.crypto;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;

class CurvePerfTest {

	private static Ed25519 ed;
	private static Curve25519 x;
	private static AES aes;
	
	public static void setUp() throws Exception {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
	}

	public static void tearDown() throws Exception {
	}
 
	void testECDSA() {
		String alicePrivate = Conv.toString(aes.random(32));
		String bobPrivate = Conv.toString(aes.random(32));

		String alicePublic = ed.publicKey(alicePrivate);
		String bobPublic = ed.publicKey(bobPrivate);
		
		// Alice acts as client and calls Bob:
		ECConnection comm = new ECConnection(x, ed, aes);
		Session aliceSession = new Session();
		String message = comm.initiateECDSA(aliceSession, alicePrivate, alicePublic, "Alice");
		//System.out.println("transfer message: " + message);
		
		// Bob receives the message and verifies:
		DTO dto = DTO.fromJsonString(message);
		dto.id += "x";
		
		// Bob answers, after that both client and server are able to construct the session key for AES
		Session bobSession = new Session();
		String initAnswer = comm.answerInitClient(bobSession, dto, bobPrivate, bobPublic);
		//System.out.println("transfer message: " + initAnswer);
		
		// Alice receives the server ok message and returns the first AES encrypted block
		dto = DTO.fromJsonString(initAnswer);
		byte[] sessionKeyAlice = comm.computeSessionKey(aliceSession.sessionPrivateKey, bobSession.sessionPublicKey);
		aliceSession.sessionAESKey = sessionKeyAlice;
		//System.out.println("session key: " + sessionKeyAlice);
		
		// continue with AES: Alice sends message to Bob
		String aesMessage = "Niklas ist der Beste!";
		//String aesMessage = "Niklas";
		byte[] encrypted = comm.encryptAES(aliceSession, aesMessage);
		//System.out.println("AES encrypted: " + Conv.toString(encrypted));
		
		// Bob receives the block and decrypts:
		byte[] sessionKeyBob = comm.computeSessionKey(bobSession.sessionPrivateKey, aliceSession.sessionPublicKey);
		bobSession.sessionAESKey = sessionKeyBob;
		String decryptedMessage = comm.decryptAES(bobSession, encrypted);
		//System.out.println("decrypted message received by Bob: " + decryptedMessage);
		
		// intermediate: check session keys
	
		// Bob answers:
		String answer = "You have spoken the truth!";
		encrypted = comm.encryptAES(bobSession, answer);
		
		// Alice receives answer:
		decryptedMessage = comm.decryptAES(aliceSession, encrypted);
		//System.out.println("decrypted message received by Alice: " + decryptedMessage);
	}
	
	// execute ECDSA test multiple times for performance analysis
	//@Test
	void multiECDSATest() {
		for ( int i = 0; i < 1000; i++) {
			testECDSA();
			System.out.print(".");
		}
		System.out.println();
	}

	public static void main(String[] args) {
		CurvePerfTest t = new CurvePerfTest();
		try {
			setUp();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//t.testECDSA();
		t.multiECDSATest();
	}
}
