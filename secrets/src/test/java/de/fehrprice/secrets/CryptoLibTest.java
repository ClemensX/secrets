package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Curve25519;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.net.DTO;
import de.fehrprice.net.ECConnection;
import de.fehrprice.net.Session;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.codec.BodyCodec;
import io.vertx.junit5.Checkpoint;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

@ExtendWith(VertxExtension.class)
public class CryptoLibTest {

	private Logger logger = Logger.getLogger(CryptoLibTest.class.toString());

	// listening port
	private static int port = 5020;

	private String aesInputMsg = "This could be anything. Even UTF-8 chars like checkmark \u2713";

	@Test
	public void testServerStart() throws Throwable {
		AES aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		String serverPrivate = Conv.toString(aes.random(32));
		Ed25519 ed = new Ed25519();
		String serverPublic = ed.publicKey(serverPrivate);

		VertxTestContext testContext = new VertxTestContext();

		Checkpoint serverStarted = testContext.checkpoint();
		Checkpoint initClientSent = testContext.checkpoint();
		Checkpoint clientAESMessageSent = testContext.checkpoint();
		Checkpoint clientAESParsed = testContext.checkpoint();
		// Use the underlying vertx instance
		Vertx vertx = Vertx.vertx();
		Router router = Router.router(vertx);
		HttpServer server = vertx.createHttpServer(new HttpServerOptions());
		Route route1 = router.route("/").handler(routingContext -> {
			HttpServerResponse response = routingContext.response();
			// enable chunked responses because we will be adding data as
			// we execute over other handlers. This is only required once and
			// only if several handlers do output.
			response.putHeader("content-type", "text/html");
			response.setChunked(true);
			// response.putHeader("X-Content-Type-Options", "nosniff");

			response.write("<html><body>" + "<h1>Secrets Container</h1>" + "<p><h3>...this is the backend...</h3></p>");
			routingContext.response().end();

		});
		Route route2 = router.route("/rest").handler(routingContext -> {
			HttpServerResponse response = routingContext.response();
			// enable chunked responses because we will be adding data as
			// we execute over other handlers. This is only required once and
			// only if several handlers do output.
			response.putHeader("content-type", "text/plain");
			response.setChunked(true);
			// response.putHeader("X-Content-Type-Options", "nosniff");
			HttpServerRequest req = routingContext.request();
			req.bodyHandler(bodyHandler -> {
				String recBody = bodyHandler.toString();
				HttpSession session = RestServer.getInstance().handleRequest(recBody);
				// System.out.println("POST received: " + recBody + " session = " + session);
				if (session == null) {
					testContext.failNow(new NullPointerException("session null"));
				} else if (session.senderValidated == false) {
					testContext.failNow(new NullPointerException("invalid sender"));
				}
				RestServer.getInstance().setServerKeys(serverPrivate, serverPublic);
				String answer = RestServer.getInstance().createInitServerAnswer(session);
				response.write(answer).end();
			});
			// routingContext.response().end();

		});
		Route route3 = router.route("/restmsg").handler(routingContext -> {
			HttpServerResponse response = routingContext.response();
			response.putHeader("content-type", "application/octet-stream");
			response.setChunked(true);
			HttpServerRequest req = routingContext.request();
			req.bodyHandler(bodyHandler -> {
				byte[] aesmsg = bodyHandler.getBytes();
				logger.info("received aes message");
				HttpSession session = RestServer.getInstance().handleAESMessage(aesmsg);
				response.write("").end();
				if (session != null) {
					if (aesInputMsg.equals(session.plaintext)) {
						clientAESParsed.flag();
					}
				}
			});
			// routingContext.response().end();

		});

		server.requestHandler(router::accept).listen(port, ar -> {
			if (ar.failed()) {
				testContext.failNow(ar.cause());
			} else {
				serverStarted.flag();
			}
		});
		WebClient client = WebClient.create(vertx);

		Curve25519 x = new Curve25519();
//		Ed25519 ed = new Ed25519();
//		AES aes = new AES();
//		aes.setSeed(RandomSeed.createSeed());
		String clientPrivate = Conv.toString(aes.random(32));
		String clientPublic = ed.publicKey(clientPrivate);
		ECConnection comm = new ECConnection(x, ed, aes);
		Session clientSession = new Session();
		String message = comm.initiateECDSA(clientSession, clientPrivate, clientPublic, "TestClient1");
		// System.out.println("transfer message: " + message);

		RestServer.getInstance().addPublicKey("TestClient1", clientPublic);

		Buffer buffer = Buffer.buffer(message);
		client.post(port, "localhost", "/rest").as(BodyCodec.string()).sendBuffer(buffer, ar -> {
			if (ar.failed()) {
				testContext.failNow(ar.cause());
			} else {
				String initAnswer = ar.result().body();
				// logger.info("received after post:" + initAnswer);
				DTO dto = DTO.fromJsonString(initAnswer);
				if (!comm.validateSender(dto, serverPublic)) {
					logger.warning("invalide server signature");
					testContext.failNow(new NullPointerException("invalid sender"));
					return;
				}
				byte[] sessionKey = comm.computeSessionKey(clientSession.sessionPrivateKey, Conv.toByteArray(dto.key));
				clientSession.sessionAESKey = sessionKey;
				logger.info("session key: " + Conv.toString(sessionKey));
				initClientSent.flag();
				dto.id = "TestClient1";
				byte[] aesMsg = comm.createAESMessage(dto, clientSession, aesInputMsg);
				//logger.info("client sent aes message: " + Conv.toPlaintext(aesMsg));
				logger.info("name in aes msg: " + comm.getSenderIdFromAESMessage(aesMsg));
				clientAESMessageSent.flag();
				Buffer aesBuffer = Buffer.buffer(aesMsg);
				client.post(port, "localhost", "/restmsg").as(BodyCodec.buffer()).sendBuffer(aesBuffer, asyncreq -> {
					logger.info("aes sent!");;
				});
				// failing example with wrong id:
				dto.id = "TestClientNIX";
				aesMsg = comm.createAESMessage(dto, clientSession, aesInputMsg);
				aesBuffer = Buffer.buffer(aesMsg);
				client.post(port, "localhost", "/restmsg").as(BodyCodec.buffer()).sendBuffer(aesBuffer, asyncreq -> {
					logger.info("aes sent!");;
				});
			}
		});

		assertTrue(testContext.awaitCompletion(15, TimeUnit.SECONDS));
		if (testContext.failed()) {
			throw testContext.causeOfFailure();
		}
	}
}
