package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;

/**
 * Singleton for handling requests to the server.
 * Only one instance allowed per server running - all session lookup and wiring is done here
 *
 */
public class RestServer {

	private static RestServer instance = null;

	public static RestServer getInstance() {
		if (instance == null) {
			instance = new RestServer();
		}
		return instance;
	}

	private Curve25519 x;
	private Ed25519 ed;
	private AES aes;
	private ECConnection conn;
	// use the key list as cache for db calls or for tests
	private Map<String,String> pubKeyMap = new HashMap<>();
	
	private RestServer() {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		conn = new ECConnection(x, ed, aes);
	}
	
	public static String status() {
		return "Secrets Server is up. Status: " + DB.status();
	}

	public static String statusCrypto() {
		try {
			Curve25519 crv = new Curve25519();
			if (crv != null) {
				return "ok";
			}
		} catch (Throwable t) {
			// intentionally ignore exceptions
		}
		return "Not Available";
	}

	void addPublicKey(String id, String key) {
		pubKeyMap.put(id, key);
	}
	
	/**
	 * Consume incoming request
	 * @param recBody
	 */
	public HttpSession handleRequest(String recBody) {
		DTO dto = DTO.fromJsonString(recBody);
		if (dto.isInitClientCommand()) {
			String clientPublicKey = findClientPublicKey(dto.id);
			if (clientPublicKey != null) {
				HttpSession hs = new HttpSession();
				hs.id = dto.id;
				hs.senderValidated = conn.validateSender(dto, clientPublicKey);
				return hs;
			}
		}
		return null;
	}

	private String findClientPublicKey(String id) {
		// try to find in key map, then DB if not found
		String k = pubKeyMap.get(id);
		return k;
	}
}
