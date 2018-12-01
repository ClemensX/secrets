package de.fehrprice.secrets.client;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Properties;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;
import de.fehrprice.secrets.dto.GetIdResult;

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

	public void getId() {
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
		String serverConf = prop.getProperty(SecretsClient.SERVER_URL);
		try {
			URI u = new URI(serverConf);
			URI uri = new URI(u.getScheme(), null, u.getHost(), u.getPort(), "/secretsbackend/rest/client", null, null );
			//System.out.println("Calling " + uri.toURL());
			//System.out.println("transfer message: " + message);
			HttpClient client = HttpClient.newBuilder()
				      .version(Version.HTTP_2)
				      .build();		
			HttpRequest request = HttpRequest.newBuilder()
				      .uri(uri)
				      .timeout(Duration.ofMinutes(1))
				      .header("Content-Type", "application/json")
				      .POST(BodyPublishers.ofString(message))
				      .build();
			HttpResponse<String> response;
			response = client.send(request, BodyHandlers.ofString());
			//System.out.println(response.statusCode());
			//System.out.println("response: " + response.body());
			var r = GetIdResult.fromJsonString(response.body());
			if (!r.validated) {
				System.out.println("Cannot get your id: public key is unknown. Did you signup?");
			} else {
				System.out.println("Your id is " + r.id);
			}
		} catch (IOException | InterruptedException | URISyntaxException e) {
			//e.printStackTrace();
			System.out.println("Could not connect to server: " + serverConf);
		}
	}
}
