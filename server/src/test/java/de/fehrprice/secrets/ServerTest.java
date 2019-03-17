package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;

@ExtendWith(VertxExtension.class)
public class ServerTest {

	// listening port
	private static int port = 5000;

	@Test
	public void testServerStart() throws Throwable {
		VertxTestContext testContext = new VertxTestContext();

		// Use the underlying vertx instance
		Vertx vertx = Vertx.vertx();
		HttpServer server = vertx.createHttpServer(new HttpServerOptions());

		server.requestHandler(req -> {
			req.response().putHeader("content-type", "text/html").end("<html><body>" + "<h1>Secrets Container</h1>"
					+ "<p>version = " + req.version() + "</p>" + "</body></html>");
		}).listen(port, testContext.succeeding(ar -> testContext.completeNow()));
		
		assertTrue(testContext.awaitCompletion(5, TimeUnit.SECONDS));
		if (testContext.failed()) {
			throw testContext.causeOfFailure();
		}
	}
}
