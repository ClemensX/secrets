package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;
import de.fehrprice.secrets.dto.SignupResult;
import io.vertx.core.json.JsonObject;

/**
 * Singleton for handling requests to the server.
 * Only one instance allowed per server running - all session lookup and wiring is done here
 *
 */
public class RestServer {

	private Logger logger = Logger.getLogger(RestServer.class.toString());

	private static RestServer instance = null;

	public static synchronized RestServer getInstance() {
		if (instance == null) {
			instance = new RestServer();
		}
		return instance;
	}

	private Curve25519 x;
	private Ed25519 ed;
	private AES aes;
	private ECConnection conn;
	private String serverPrivateKey;
	private String serverPublicKey;
	// use the key list as cache for db calls or for tests
	private Map<String,String> pubKeyMap = new HashMap<>();
	// map for all ongoing sessions, mapped by client id
	private Map<String, HttpSession> sessionMap = new HashMap<>();
	
	private RestServer() {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		conn = new ECConnection(x, ed, aes);
		
	}
	
	private static String readPrivateKey() {
		Path path = Paths.get("/etc/secrets/private", "keyfile_private");
		if (Files.exists(path)) {
			try {
				String privKey = Files.readString(path);
				if (privKey != null) {
					privKey = privKey.trim();
					return privKey;
				}
			} catch (IOException e) {
			}
		}
		return null;
	}

	public static String status() {
		return "Secrets Server is up. Database: " + DB.status();
	}

	private static String privateKeyStatus() {
		String privateKey = readPrivateKey();
		if (privateKey != null) {
			return "Private key file found, length: " + privateKey.length() + " chars";
		}
		return "ERROR: Private Key not found.";
	}

	public static String statusCrypto() {
		try {
			Curve25519 crv = new Curve25519();
			if (crv != null) {
				return "ok" + " (" + privateKeyStatus() + ")";
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
	 * Consume incoming init request
	 * @param recBody
	 */
	public HttpSession handleRequest(String recBody) {
		DTO dto = DTO.fromJsonString(recBody);
		if (dto.isInitClientCommand()) {
			String clientPublicKey = findClientPublicKey(dto.id);
			if (clientPublicKey != null) {
				HttpSession hs = new HttpSession();
				hs.id = dto.id;
				hs.dto = dto;
				hs.senderValidated = conn.validateSender(dto, clientPublicKey);
				return hs;
			}
		}
		return null;
	}

	public HttpSession handleAESMessage(byte[] aesmsg) {
		String sender_id = ECConnection.getSenderIdFromAESMessage(aesmsg);
		logger.info("got message from " + sender_id);
		if (sender_id == null) {
			logger.warning("no sender in message");
			return null;
		}
		HttpSession hsession = getSession(sender_id);
		if (hsession == null) {
			logger.warning("no active session for id " + sender_id);
			return null;
		}
		logger.info("session ok, key = " + Conv.toString(hsession.sessionKey));
		hsession.cryptoSession.sessionAESKey = hsession.sessionKey;
		String text = conn.getTextFromAESMessage(aesmsg, hsession.cryptoSession);
		hsession.plaintext = text;
		logger.info("received aes msg: " + text);
		return hsession;
	}

	private String findClientPublicKey(String id) {
		// try to find in key map, then DB if not found
		String k = pubKeyMap.get(id);
		return k;
	}

	public String createInitServerAnswer(HttpSession httpSession) {
		Session serverSession = new Session();
		byte[] clientPublicKey = Conv.toByteArray(httpSession.dto.key);
		String initAnswer = conn.answerInitClient(serverSession, httpSession.dto, serverPrivateKey, serverPublicKey);
		logger.info("transfer message: " + initAnswer);
		byte[] sessionKey = conn.computeSessionKey(serverSession.sessionPrivateKey, clientPublicKey);
		httpSession.sessionKey = sessionKey;
		httpSession.cryptoSession = serverSession;
		addSession(httpSession);
		return initAnswer;
	}

	/**
	 * Add session. If already existing the old one gets deleted.
	 * @param httpSession
	 */
	private void addSession(HttpSession httpSession) {
		sessionMap.remove(httpSession.id);
		sessionMap.put(httpSession.id, httpSession);
		logger.info("httpSession created for " + httpSession.id + " key = " + Conv.toString(httpSession.sessionKey));
	}

	/**
	 * Add session. If already existing the old one gets deleted.
	 * @param httpSession
	 */
	private HttpSession getSession(String id) {
		return sessionMap.get(id);
	}

	public void setServerKeys(String serverPrivate, String serverPublic) {
		this.serverPrivateKey = serverPrivate;
		this.serverPublicKey = serverPublic;
		
	}

	public static String getPublicKey() {
		if (getInstance().serverPublicKey == null) {
			// read private key and generate public key
			String hexPrivateKey = readPrivateKey();
			String hexPublicKey = getInstance().ed.publicKey(hexPrivateKey);
			getInstance().setServerKeys(hexPrivateKey, hexPublicKey);
		}
		return getInstance().serverPublicKey;
	}

	private String getFreeSlots() {
		return DB.getFreeSlots();
	}

	private String signup(JsonObject bodyj) {
		logger.info("signup call received");
		String name = bodyj.getString("name");
		String key = bodyj.getString("publickey");
		logger.info("received: " + name + " " + key);
		String res = signup(name, key);
		//return "{\"v\":\"ok\"}";
		return res;
	}

	private String signup(String name, String key) {
		SignupResult res = DB.signup(name, key);
		return res.asJsonString();
	}

	public String restCall(String path) {
		return restCall(path, null);
	}

	public String restCall(String path, JsonObject bodyj) {
		String[] p = path.split("/");
//		for (int i = 0; i < p.length; i++) {
//			System.out.println("PATH " + i + " " + p[i]);
//		}
		if (p.length < 4 || !"secretsbackend".equals(p[1]) || !"rest".equals(p[2])) {
			logger.severe("invalid request path received: " + path);
			return "error";
		}
		if ("status".equals(p[3])) {
			return status();
		}
		if ("statuscrypto".equals(p[3])) {
			return statusCrypto();
		}
		if ("getpublickey".equals(p[3])) {
			return getPublicKey();
		}
		if ("freeslots".equals(p[3])) {
			return getFreeSlots();
		}
		if ("signup".equals(p[3])) {
			return signup(bodyj);
		}
		logger.severe("invalid request path received: " + path);
		return "error";
	}

}
