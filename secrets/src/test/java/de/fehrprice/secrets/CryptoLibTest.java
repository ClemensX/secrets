package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.codec.BodyCodec;
import io.vertx.junit5.Checkpoint;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

@ExtendWith(VertxExtension.class)
public class CryptoLibTest {

	// listening port
	private static int port = 5010;

	@Test
	public void testServerStart() throws Throwable {
		VertxTestContext testContext = new VertxTestContext();

		Checkpoint serverStarted = testContext.checkpoint();
		Checkpoint responseReceived = testContext.checkpoint();
		// Use the underlying vertx instance
		Vertx vertx = Vertx.vertx();
		HttpServer server = vertx.createHttpServer(new HttpServerOptions());

		server.requestHandler(req -> {
			req.response().putHeader("content-type", "text/html").end("<html><body>" + "<h1>Secrets Container</h1>"
					+ "<p>version = " + req.version() + "</p>" + "</body></html>");
		}).listen(port, ar -> {
			if (ar.failed()) {
				testContext.failNow(ar.cause());
			} else {
				serverStarted.flag();
			}
		});

		WebClient client = WebClient.create(vertx);

		client.get(port, "localhost", "/").as(BodyCodec.string())
				.send(ar -> {
					if (ar.failed()) {
						testContext.failNow(ar.cause());
					} else {
						//assertThat(response.body()).isEqualTo("Plop");
						assertTrue(ar.result().body().contains("Secrets Container"));
						System.out.println("received:" + ar.result().body());
						//testContext.completeNow();
						//testContext.failNow(null);
						responseReceived.flag();
					}
				});

		assertTrue(testContext.awaitCompletion(5, TimeUnit.SECONDS));
		if (testContext.failed()) {
			throw testContext.causeOfFailure();
		}
	}
}
