package de.fehrprice.net;

/**
 * Handle ECDSA server connection.
 * Used to manage connection to a client once his public ECDSA key is available.  
 *
 */
public class ServerConnectionHandler {

	// session keys
	private Session session;
	
	// ECDSA keys:
	private byte[] serverPrivateKey;
	private byte[] clientPublicKey;

	public ServerConnectionHandler(byte[] serverECDSAPrivateKey, byte[] clientECDSAPublicKey) {
		session = new Session();
		serverPrivateKey = serverECDSAPrivateKey;
		clientPublicKey = clientECDSAPublicKey;
	}
	
	
}
