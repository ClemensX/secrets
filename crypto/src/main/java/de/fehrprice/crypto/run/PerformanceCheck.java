package de.fehrprice.crypto.run;

import java.text.DecimalFormat;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;

// run ECDSH and message exchange in a main class
public class PerformanceCheck {

    final static int count = 100;
    
    public static void main(String[] args) {
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
}
