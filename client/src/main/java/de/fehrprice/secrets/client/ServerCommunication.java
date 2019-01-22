package de.fehrprice.secrets.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;
import java.util.Properties;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;
import de.fehrprice.secrets.dto.GetIdResult;
import de.fehrprice.secrets.dto.SnippetDTO;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.dto.TagDTO;
import de.fehrprice.secrets.entity.Snippet;

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

	public Long getId() {
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		String clientPrivate = privateKey;
		String clientPublic = ed.publicKey(clientPrivate);
		// uncomment to force invalid key:
		//clientPublic = "e" + clientPublic.substring(1);
		ECConnection comm = new ECConnection(x, ed, aes);
		Session clientSession = new Session();
		String message = comm.createOpenSignedCommand(clientSession, clientPrivate, clientPublic, "getid");
		String body = postServer("/secretsbackend/rest/client", message);
		if (body == null) return null;
		var r = GetIdResult.fromJsonString(body);
		if (!r.validated) {
			System.out.println("Cannot get your id: public key is unknown. Did you signup?");
			return null;
		} else {
			System.out.println("Your id is " + r.id);
			return r.id;
		}
	}
	
	public String postServer(String urlPath, String message)  {
		var sendBody = BodyPublishers.ofString(message);
		return postServerInternal(urlPath, sendBody);
	}

	public String postServer(String urlPath, byte[] message)  {
		var sendBody = BodyPublishers.ofByteArray(message);
		return postServerInternal(urlPath, sendBody);
	}

	public String postServerInternal(String urlPath, BodyPublisher message)  {
		String serverConf = prop.getProperty(SecretsClient.SERVER_URL);
		try {
			URI u = new URI(serverConf);
			URI uri = new URI(u.getScheme(), null, u.getHost(), u.getPort(), urlPath, null, null );
			//System.out.println("Calling " + uri.toURL());
			//System.out.println("transfer message: " + message);
			HttpClient client = HttpClient.newBuilder()
				      .version(Version.HTTP_2)
				      .build();		
			HttpRequest request = HttpRequest.newBuilder()
				      .uri(uri)
				      .timeout(Duration.ofMinutes(1))
				      .header("Content-Type", "application/json")
				      .POST(message)
				      .build();
			HttpResponse<String> response;
			response = client.send(request, BodyHandlers.ofString());
			//System.out.println(response.statusCode());
			//System.out.println("response: " + response.body());
			return response.body();
		} catch (IOException | InterruptedException | URISyntaxException e) {
			//e.printStackTrace();
			System.out.println("Could not connect to server: " + serverConf);
			return null;
		}
	}

	public byte[] postServerBinary(String urlPath, byte[] message)  {
		var sendBody = BodyPublishers.ofByteArray(message);
		String serverConf = prop.getProperty(SecretsClient.SERVER_URL);
		try {
			URI u = new URI(serverConf);
			URI uri = new URI(u.getScheme(), null, u.getHost(), u.getPort(), urlPath, null, null );
			//System.out.println("Calling " + uri.toURL());
			//System.out.println("transfer message: " + message);
			HttpClient client = HttpClient.newBuilder()
				      .version(Version.HTTP_2)
				      .build();		
			HttpRequest request = HttpRequest.newBuilder()
				      .uri(uri)
				      .timeout(Duration.ofMinutes(1))
				      .header("Content-Type", "application/octet-stream")
				      .POST(sendBody)
				      .build();
			HttpResponse<byte[]> response;
			response = client.send(request, BodyHandlers.ofByteArray());
			//System.out.println(response.statusCode());
			//System.out.println("response: " + response.body());
			return response.body();
		} catch (IOException | InterruptedException | URISyntaxException e) {
			//e.printStackTrace();
			System.out.println("Could not connect to server: " + serverConf);
			return null;
		}
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
		String idString = prop.getProperty(SecretsClient.SIGNUP_ID);
		String message = comm.initiateECDSA(clientSession, clientPrivate, clientPublic, idString);
		//System.out.println("transfer message: " + message);
		String body = postServer("/secretsbackend/rest/client", message);
		//System.out.println("server returned: " + body);
		if (body == null) {
			System.out.println("no valid answer from server");
			return;
		}
		DTO dto = DTO.fromJsonString(body);
		String serverPublic = prop.getProperty(SecretsClient.SERVER_PUBLIC_KEY);
		if (!comm.validateSender(dto, serverPublic)) {
			System.out.println("invalid server signature");
			return;
		}
		//System.out.println("server verified");
		byte[] sessionKey = comm.computeSessionKey(clientSession.sessionPrivateKey, Conv.toByteArray(dto.key));
		clientSession.sessionAESKey = sessionKey;
		//System.out.println("session key: " + Conv.toString(sessionKey));
		dto.id = idString;
		//System.out.println("my id: " + dto.id);
		byte[] aesMsg = comm.createAESMessage(dto, clientSession, "hello");
		//logger.info("client sent aes message: " + Conv.toPlaintext(aesMsg));
		//System.out.println("name in aes msg: " + comm.getSenderIdFromAESMessage(aesMsg));
		//System.out.println("transfer message: " + message);
		byte[] aes = postServerBinary("/secretsbackend/restmsg", aesMsg);
		//System.out.println("recevied aes msg with length: " + aes.length);
		//Conv.dump(aes, aes.length);
		String text = comm.getTextFromAESMessage(aes, clientSession);
		if ("hello answer".equals(text)) {
			System.out.println("secure connection ok");
		} else {
			System.out.println("ERROR: could not verify secure connection to server");
		}
		//System.out.println("recevied aes msg: " + text);
	}

	public String sendSnippet(Snippet s) {
		// convert snippet to json
		var json = SnippetDTO.asJsonString(s);
		System.out.println("sending json: " + json);
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		String clientPrivate = privateKey;
		String clientPublic = ed.publicKey(clientPrivate);
		ECConnection comm = new ECConnection(x, ed, aes);
		Session clientSession = new Session();
		String idString = prop.getProperty(SecretsClient.SIGNUP_ID);
		String message = comm.initiateECDSA(clientSession, clientPrivate, clientPublic, idString);
		//System.out.println("transfer message: " + message);
		String body = postServer("/secretsbackend/rest/client", message);
		//System.out.println("server returned: " + body);
		if (body == null) {
			System.out.println("no valid answer from server");
			return null;
		}
		DTO dto = DTO.fromJsonString(body);
		String serverPublic = prop.getProperty(SecretsClient.SERVER_PUBLIC_KEY);
		if (!comm.validateSender(dto, serverPublic)) {
			System.out.println("invalid server signature");
			return null;
		}
		//System.out.println("server verified");
		byte[] sessionKey = comm.computeSessionKey(clientSession.sessionPrivateKey, Conv.toByteArray(dto.key));
		clientSession.sessionAESKey = sessionKey;
		//System.out.println("session key: " + Conv.toString(sessionKey));
		dto.id = idString;
		//System.out.println("my id: " + dto.id);
		byte[] aesMsg = comm.createAESMessage(dto, clientSession, json);
		//logger.info("client sent aes message: " + Conv.toPlaintext(aesMsg));
		//System.out.println("name in aes msg: " + comm.getSenderIdFromAESMessage(aesMsg));
		//System.out.println("transfer message: " + message);
		byte[] aes = postServerBinary("/secretsbackend/restmsg", aesMsg);
		//System.out.println("recevied aes msg with length: " + aes.length);
		//Conv.dump(aes, aes.length);
		String text = comm.getTextFromAESMessage(aes, clientSession);
		return text;
	}

	public void getTags() {
		// convert snippet to json
		Snippet s = new Snippet();
		s.setCommand("gettags");
		var json = SnippetDTO.asJsonString(s);
		//System.out.println("sending json: " + json);
		
		ConnectData cd = prepareConnection();
		
		byte[] aesMsg = cd.comm.createAESMessage(cd.dto, cd.clientSession, json);
		byte[] aes = postServerBinary("/secretsbackend/restmsg", aesMsg);
		String text = cd.comm.getTextFromAESMessage(aes, cd.clientSession);
		System.out.println("Your Taglist:");
		List<Tag> tags = TagDTO.fromJsonString(text);
		for (Tag t : tags) {
			System.out.println(t.getName());
		}
	}

	private ConnectData prepareConnection() {
		ConnectData cd = new ConnectData();
		x = new Curve25519();
		ed = new Ed25519();
		aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		String clientPrivate = privateKey;
		String clientPublic = ed.publicKey(clientPrivate);
		ECConnection comm = new ECConnection(x, ed, aes);
		Session clientSession = new Session();
		String idString = prop.getProperty(SecretsClient.SIGNUP_ID);
		String message = comm.initiateECDSA(clientSession, clientPrivate, clientPublic, idString);
		//System.out.println("transfer message: " + message);
		String body = postServer("/secretsbackend/rest/client", message);
		//System.out.println("server returned: " + body);
		if (body == null) {
			System.out.println("no valid answer from server");
			return null;
		}
		DTO dto = DTO.fromJsonString(body);
		String serverPublic = prop.getProperty(SecretsClient.SERVER_PUBLIC_KEY);
		if (!comm.validateSender(dto, serverPublic)) {
			System.out.println("invalid server signature");
			return null;
		}
		//System.out.println("server verified");
		byte[] sessionKey = comm.computeSessionKey(clientSession.sessionPrivateKey, Conv.toByteArray(dto.key));
		clientSession.sessionAESKey = sessionKey;
		//System.out.println("session key: " + Conv.toString(sessionKey));
		dto.id = idString;
		//System.out.println("my id: " + dto.id);
		cd.comm = comm;
		cd.dto = dto;
		cd.clientSession = clientSession;
		return cd;
	}

	public void getSnippetsForTag(String string) {
		// TODO Auto-generated method stub
		
	}
	
	private class ConnectData {

		public Session clientSession;
		public DTO dto;
		public ECConnection comm;
		
	}
}
