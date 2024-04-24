package de.fehrprice.crypto.run;

import java.math.BigInteger;
import java.text.DecimalFormat;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.FixedPointOp;
import de.fehrprice.crypto.donna.ED25519;
import de.fehrprice.crypto.fp256;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.crypto.edu25519.Field;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;

// run ECDSH and message exchange in a main class
public class PerformanceCheck {

    public static void main(String[] args) {
        //perfX25519Compare();
        //perfECDSA();
        perfED25519Compare();
        if (false) {
            perf256ModPow();
            perf64Mult();
            perf256Mult();
        }
    }
    
    /**
     * Test performance naive X25519 impl vs. edu25519 Java port
     */
    private static void perfX25519Compare() {
        
        int count = 1000;
        // prep
        // create all arrays we need to prepare mult data
        BigInteger scalar, uIn, uOut, bobPublicKey, alicePublicKey, secretKey;
        String uBasePoint, a, b, a_pub, b_pub, secret_k;
        byte[] scalarEff;
        FixedPointOp fp = new FixedPointOp();
        
        
        uBasePoint     = "0900000000000000000000000000000000000000000000000000000000000000";
        a              = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        b              = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        var crv = new Curve25519();
        for (int i = 0; i < 100; i++) {
            scalar = crv.decodeScalar25519(crv.toByteArray(a));
            uIn = crv.decodeUCoordinate(crv.toByteArray(uBasePoint), 255);
            uOut = crv.x25519(scalar, uIn, 255);
        }
        
        System.out.println("prep done, calculating...");
        long start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            scalar = crv.decodeScalar25519(crv.toByteArray(a));
            uIn = crv.decodeUCoordinate(crv.toByteArray(uBasePoint), 255);
            uOut = crv.x25519(scalar, uIn, 255);
        }
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("Naive X25519 impl " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
        start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            scalarEff = crv.toByteArray(a);
            uIn = crv.decodeUCoordinate(crv.toByteArray(uBasePoint), 255);
            uOut = crv.x25519Eff(scalarEff, Field.s64Array.fromFP256(fp.fromBigInteger(uIn)));
        }
        
        now = System.nanoTime();
        duration = now - start;
        duration_seconds = ((double) duration) / 1E9;
        df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("edu25519 X25519 impl " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
    }
    
    /**
     * Test performance naive Ed25519 impl vs. ED25519 Donna Java port
     */
    private static void perfED25519Compare() {
        
        int count = 100;
        // prep
        Ed25519 edNaive = new Ed25519();
        ED25519 edDonna = new ED25519();
        AES aes = new AES();
        aes.setSeed(RandomSeed.createSeed());
        
        String alicePrivate = Conv.toString(aes.random(32));
        String mshHexString = Conv.plaintextToHexString("yeah");
        
        // think about warming up both implementations...
        
        System.out.println("prep done, calculating...");
        String publicKey, signature;
        long start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            publicKey = edNaive.publicKey(alicePrivate);
            signature = edNaive.signature(mshHexString, alicePrivate, publicKey);
        }
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("Naive Ed25519 impl " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
        start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            publicKey = edDonna.publicKey(alicePrivate);
            signature = edDonna.signature(mshHexString, alicePrivate, publicKey);
        }
        
        now = System.nanoTime();
        duration = now - start;
        duration_seconds = ((double) duration) / 1E9;
        df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("ED25519 Donna impl " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
    }
    
    /**
	 * Test performance of 64 bit multiplication with FP256 and BigInteger 
	 */
	private static void perf64Mult() {
        AES aes = new AES();
        aes.setSeed(RandomSeed.createSeed());
        FixedPointOp fp = new FixedPointOp();

        int count = 100000;
        // create all arrays we need to prepare mult data
        BigInteger[] bia = new BigInteger[count];
        BigInteger[] bib = new BigInteger[count];
        long[] fpa = new long[count];
        long[] fpb = new long[count];

        // create random numbers and store as multiplicants:
        for(int i = 0; i < count; i++) {
            String h = Conv.toString(aes.random(8)); 
            BigInteger big = new BigInteger(h, 16);
            bia[i] = big;
            fpa[i] = big.longValue();
            h = Conv.toString(aes.random(8)); 
            big = new BigInteger(h, 16);
            bib[i] = big;
            fpb[i] = big.longValue();
        }
		long start = System.nanoTime();
		for (int i = 0; i < count; i++) {
			BigInteger r = bia[i].multiply(bib[i]);
			//System.out.println(r);
		}

		System.out.println("prep done, calculating...");
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("BigIntegert 64 bit multipication " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));

		start = System.nanoTime();
		for (int i = 0; i < count; i++) {
			fp256 f = fp.zero();
			fp.umul64(f, fpa[i], fpb[i]);
			//System.out.println(r);
		}

        now = System.nanoTime();
        duration = now - start;
        duration_seconds = ((double) duration) / 1E9;
        df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("FP256 64 bit multipication " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
	}
	/**
	 * Test performance of 256 bit multiplication with FP256 and BigInteger 
	 */
	private static void perf256Mult() {
        AES aes = new AES();
        aes.setSeed(RandomSeed.createSeed());
        FixedPointOp fp = new FixedPointOp();

        int count = 10000;
        // create all arrays we need to prepare mult data
        BigInteger[] bia = new BigInteger[count];
        BigInteger[] bib = new BigInteger[count];
        fp256[] fpa = new fp256[count];
        fp256[] fpb = new fp256[count];

        // create random numbers and store as multiplicants:
        for(int i = 0; i < count; i++) {
            String h = Conv.toString(aes.random(32)); 
            BigInteger big = new BigInteger(h, 16);
            bia[i] = big;
            fpa[i] = fp.fromBigInteger(big);
            h = Conv.toString(aes.random(32)); 
            big = new BigInteger(h, 16);
            bib[i] = big;
            fpb[i] = fp.fromBigInteger(big);
        }
		long start = System.nanoTime();
		for (int i = 0; i < count; i++) {
			BigInteger r = bia[i].multiply(bib[i]).mod(BigInteger.TWO.pow(256));
			//System.out.println(fp.dump(fp.fromBigInteger(r)));
		}

		System.out.println("prep done, calculating...");
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("BigInteger 256 bit multipication " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));

		start = System.nanoTime();
		for (int i = 0; i < count; i++) {
			fp256 f = fp.zero();
			fp.umul(f, fpa[i], fpb[i]);
			//System.out.println(fp.dump(f));
		}

        now = System.nanoTime();
        duration = now - start;
        duration_seconds = ((double) duration) / 1E9;
        df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("FP256 256 bit multipication " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
	}

	private static void perfECDSA() {
	    final int count = 10; // 1000 ~ 40 s
//	    ECDSA 10000 iterations total time: [s] 394,5956
//	    single iteration: [s] 0,0395
	    
		long start = System.nanoTime();

        Curve25519 x = new Curve25519();
        Ed25519 ed = new Ed25519();
        AES aes = new AES();
        aes.setSeed(RandomSeed.createSeed());

        String alicePrivate = Conv.toString(aes.random(32));
        String bobPrivate = Conv.toString(aes.random(32));

        String alicePublic = ed.publicKey(alicePrivate);
        String bobPublic = ed.publicKey(bobPrivate);
        for ( int i = 0; i < count; i++) {
            doECDSACommunication(x, ed, aes, alicePrivate, alicePublic, bobPrivate, bobPublic);
        }
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("ECDSA " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single ECDSA communication:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
	}

    // do full conversation like in real world scenario, for performance tests, minimal assertions
    public static void doECDSACommunication(Curve25519 x, Ed25519 ed, AES aes, String alicePrivate, String alicePublic, String bobPrivate, String bobPublic) {
        // Alice acts as client and calls Bob:
        ECConnection comm = new ECConnection(x, ed, aes);
        Session aliceSession = new Session();
        String message = comm.initiateECDSA(aliceSession, alicePrivate, alicePublic, "Alice");
        
        // Bob receives the message and verifies:
        DTO dto = DTO.fromJsonString(message);
        
        // Bob answers, after that both client and server are able to construct the session key for AES
        Session bobSession = new Session();
        String initAnswer = comm.answerInitClient(bobSession, dto, bobPrivate, bobPublic);
        
        // Alice receives the server ok message and returns the first AES encrypted block
        dto = DTO.fromJsonString(initAnswer);
        byte[] sessionKeyAlice = comm.computeSessionKey(aliceSession.sessionPrivateKey, bobSession.sessionPublicKey);
        aliceSession.sessionAESKey = sessionKeyAlice;
        
        // continue with AES: Alice sends message to Bob
        String aesMessage = "Niklas ist der Beste!";
        //String aesMessage = "Niklas";
        byte[] encrypted = comm.encryptAES(aliceSession, aesMessage);
        
        // Bob receives the block and decrypts:
        byte[] sessionKeyBob = comm.computeSessionKey(bobSession.sessionPrivateKey, aliceSession.sessionPublicKey);
        bobSession.sessionAESKey = sessionKeyBob;
        String decryptedMessage = comm.decryptAES(bobSession, encrypted);
        
        // intermediate: check session keys
    
        // Bob answers:
        String answer = "You have spoken the truth!";
        encrypted = comm.encryptAES(bobSession, answer);
        
        // Alice receives answer:
        decryptedMessage = comm.decryptAES(aliceSession, encrypted);
        //System.out.println(decryptedMessage);
    }

    /**
     * Test performance of 256 bit modular power with FP256 and BigInteger 
     */
    private static void perf256ModPow() {
        AES aes = new AES();
        aes.setSeed(RandomSeed.createSeed());
        FixedPointOp fp = new FixedPointOp();
        Curve25519 crv = new Curve25519();
        BigInteger moduloB = Curve25519.p;
        fp256 modulo = fp.fromBigInteger(moduloB);

        int count = 40;
        // create all arrays we need to prepare mult data
        BigInteger[] bia = new BigInteger[count];
        BigInteger[] bib = new BigInteger[count];
        fp256[] fpa = new fp256[count];
        fp256[] fpb = new fp256[count];

        // create random numbers and store as base and exponent:
        for(int i = 0; i < count; i++) {
            String h = Conv.toString(aes.random(32)); 
            BigInteger big = new BigInteger(h, 16);
            bia[i] = big;
            fpa[i] = fp.fromBigInteger(big);
            h = Conv.toString(aes.random(32)); 
            big = new BigInteger(h, 16);
            bib[i] = big;
            fpb[i] = fp.fromBigInteger(big);
        }
        long start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            BigInteger r = bia[i].modPow(bib[i], moduloB);
            //System.out.println(fp.dump(fp.fromBigInteger(r)));
        }

        System.out.println("prep done, calculating...");
        long now = System.nanoTime();
        long duration = now - start;
        double duration_seconds = ((double) duration) / 1E9;
        DecimalFormat df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("BigInteger 256 bit power " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));

        start = System.nanoTime();
        for (int i = 0; i < count; i++) {
            fp256 f = fp.zero();
            fp.pow_mod(f, fpa[i], fpb[i], modulo);
            //System.out.println(fp.dump(f));
        }

        now = System.nanoTime();
        duration = now - start;
        duration_seconds = ((double) duration) / 1E9;
        df = new DecimalFormat();
        df.setMaximumFractionDigits(4);
        System.out.println("FP256 256 bit power " + count + " iterations total time: [s] " + df.format(duration_seconds));
        duration /= count; // for single mult:
        duration_seconds = ((double) duration) / 1E9;
        System.out.println("  single iteration: [s] " + df.format(duration_seconds));
        
    }
}
