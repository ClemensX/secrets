package de.fehrprice.net;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;

public class ECConnection {

	private Curve25519 x;
	private Ed25519 ed;
	private AES aes;

	private static String uBasePoint     = "0900000000000000000000000000000000000000000000000000000000000000";

	
	public ECConnection(Curve25519 x, Ed25519 ed, AES aes) {
		this.x = x;
		this.ed = ed;
		this.aes = aes;
	}

	/**
	 * Initiate Connection by creating a shared secret. This secret will then be used as AES session key.
	 * The keys should be new for each communication session. Generate them with Curve25519.
	 * @param clientPrivateKey
	 * @param serverPublicKey
	 * @return Shared Secret - not to be transfered!!
	 */
	public String initiateECDH(String clientPrivateKey, String serverPublicKey) {
		String sharedSecret = x.x25519(clientPrivateKey, serverPublicKey);
		return sharedSecret;
	}

	/**
	 * Create new client public key for this session. 
	 * Assemble a message with the callers id and public key. Sign the message with the static private key of the client.
	 * Append the signature to the message and call server to receive its public session key.
	 * The temporary keys should be new for each communication session. Generate them with Curve25519.
	 * The static keys for signing are created by Ed25519 and never changed.
	 * Both parties need to have the public Ed25519 key of the other party for verification. 
	 * @param clientSession 
	 * @param clientPrivateKey
	 * @param serverPublicKey
	 * @return signed message as Json string, ready to be transmitted
	 */
	public String initiateECDSA(Session clientSession, String staticClientPrivateKey, String staticClientPublicKey, String clientName) {
		String sessionClientPrivateKey = Conv.toString(aes.random(32));
		String sessionClientPublicKey = x.x25519(sessionClientPrivateKey, uBasePoint);
		DTO dto = new DTO();
		dto.command = "InitClient";
		dto.id = clientName;
		dto.key = sessionClientPublicKey;
		dto.signature = ed.signature(dto.getMessage(), staticClientPrivateKey, staticClientPublicKey);
		clientSession.sessionPrivateKey = Conv.toByteArray(sessionClientPrivateKey);
		clientSession.sessionPublicKey = Conv.toByteArray(sessionClientPublicKey);
		return DTO.asJson(dto);
	}

	public String createOpenSignedCommand(Session clientSession, String staticClientPrivateKey, String staticClientPublicKey, String commandName) {
		DTO dto = new DTO();
		dto.command = commandName;
		dto.id = null;
		dto.key = staticClientPublicKey;
		dto.signature = ed.signature(dto.getMessage(), staticClientPrivateKey, staticClientPublicKey);
		return DTO.asJson(dto);
	}

	public String computeSessionKey(String myPrivateKey, String partnerPublicKey) {
		String sharedSecret = x.x25519(myPrivateKey, partnerPublicKey);
		return sharedSecret;
	}

	public byte[] computeSessionKey(byte[] myPrivateKey, byte[] partnerPublicKey) {
		String sharedSecret = x.x25519(Conv.toString(myPrivateKey), Conv.toString(partnerPublicKey));
		return Conv.toByteArray(sharedSecret);
	}

	/**
	 * Server receives InitClient call. Create session key pair and return session public key to caller.
	 * Sign message with the static server keys.
	 * Message must have been verified before calling this method! 
	 * @param bobSession 
	 * @param dto
	 * @param serverPrivate
	 * @param clientPublic
	 * @return
	 */
	public String answerInitClient(Session serverSession, DTO dto, String staticServerPrivateKey, String staticServerPublicKey) {
		// create session keys:
		String sessionServerPrivateKey = Conv.toString(aes.random(32));
		String sessionServerPublicKey = x.x25519(sessionServerPrivateKey, uBasePoint);
		dto.command = "InitServer";
		dto.id = "SecretsServer";
		dto.key = sessionServerPublicKey;
		dto.signature = ed.signature(dto.getMessage(), staticServerPrivateKey, staticServerPublicKey);
		serverSession.sessionPrivateKey = Conv.toByteArray(sessionServerPrivateKey);
		serverSession.sessionPublicKey = Conv.toByteArray(sessionServerPublicKey);
		return DTO.asJson(dto);
	}

	/**
	 * Authenticate message sender. 
	 * @param dto
	 * @param clientPublic
	 * @return
	 */
	public boolean validateSender(DTO dto, String publicKey) {
		return ed.checkvalid(dto.signature, dto.getMessage(), publicKey);
	}

	public byte[] encryptAES(Session clientSession, String messageText) {
		return aes.cipher256(clientSession.sessionAESKey, Conv.plaintextToByteArray(messageText));
	}

	public String decryptAES(Session session, byte[] encrypted) {
		byte[] res_array = aes.decipher256(session.sessionAESKey, encrypted);
		return Conv.toPlaintext(res_array);
	}

	// secure message exchange
	// simple format: byte with length (in bytes) of id string (in plain text) followed by aes encrypted block
	
	public byte[] createAESMessage(DTO dto, Session session, String input) {
		if (dto.id == null || dto.id.length() > 255) {
			throw new IndexOutOfBoundsException("invalid sender id: " + dto.id);
		}
		byte[] idblock = Conv.plaintextToByteArray(dto.id);
		if (idblock.length > 255) {
			throw new IndexOutOfBoundsException("invalid sender, could not code name into 255 bytes: " + dto.id);
		}
		byte[] aesblock = encryptAES(session, input);
		byte[] result = new byte[idblock.length + aesblock.length + 1];
		result[0] = Conv.intToByte(idblock.length);
		System.arraycopy(idblock, 0, result, 1, idblock.length);
		System.arraycopy(aesblock, 0, result, idblock.length+1, aesblock.length);
		return result;
	}
	
	public static String getSenderIdFromAESMessage(byte[] aesMsg) {
		int len = Conv.byteToInt(aesMsg[0]);
		byte namearr[] = new byte[len];
		System.arraycopy(aesMsg, 1, namearr, 0, len);
		String name = Conv.toPlaintext(namearr);
		return name;
	}

	public String getTextFromAESMessage(byte[] aesMsg, Session session) {
		int len = Conv.byteToInt(aesMsg[0]);
		int aesTextLength = aesMsg.length - len - 1;
		byte textarr[] = new byte[aesTextLength];
		System.arraycopy(aesMsg, 1 + len, textarr, 0, aesTextLength);
		String text = decryptAES(session, textarr);
		//String text = Conv.toPlaintext(textarr);
		return text;
	}
}
