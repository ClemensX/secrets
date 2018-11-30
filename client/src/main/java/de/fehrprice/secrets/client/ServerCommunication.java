package de.fehrprice.secrets.client;

import java.util.Properties;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

public class ServerCommunication {

	private Curve25519 x;
	private Ed25519 ed;
	private AES aes;
	private Properties prop;
	private String privateKey;
	
	public ServerCommunication(Properties p, String priv) {
		prop = p;
		privateKey = priv;
	}

	public void initiate() {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		String clientPrivate = privateKey;
		String clientPublic = ed.publicKey(clientPrivate);
		ECConnection comm = new ECConnection(x, ed, aes);
		Session clientSession = new Session();
		String message = comm.initiateECDSA(clientSession, clientPrivate, clientPublic, "TestClient1");
		System.out.println("transfer message: " + message);
	}
}
