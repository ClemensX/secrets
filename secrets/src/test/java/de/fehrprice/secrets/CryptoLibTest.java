package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

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

	// listening port
	private static int port = 5010;

	@Test
	public void testServerStart() throws Throwable {
		VertxTestContext testContext = new VertxTestContext();

		Checkpoint serverStarted = testContext.checkpoint();
		Checkpoint responseReceived = testContext.checkpoint();
		Checkpoint initClientSent = testContext.checkpoint();
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
		  	  //response.putHeader("X-Content-Type-Options", "nosniff");

		  	  response.write("<html><body>" +
		  	          "<h1>Secrets Container</h1>" +
		  	          "<p><h3>...this is the backend...</h3></p>");
		  	  routingContext.response().end();
			
		});
		Route route2 = router.route("/rest").handler(routingContext -> {
		  	  HttpServerResponse response = routingContext.response();
		  	  // enable chunked responses because we will be adding data as
		  	  // we execute over other handlers. This is only required once and
		  	  // only if several handlers do output.
		  	  response.putHeader("content-type", "text/plain");
		  	  response.setChunked(true);
		  	  //response.putHeader("X-Content-Type-Options", "nosniff");
			  HttpServerRequest req = routingContext.request();
			  req.bodyHandler(bodyHandler -> {
				  String recBody = bodyHandler.toString();
			  	  System.out.println("POST received: " + recBody);
			  	  response.write("ok").end();
			  });
		  	  //routingContext.response().end();
			
		});

	    server.requestHandler(router::accept).listen(port, ar -> {
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

		Buffer buffer = Buffer.buffer("this is a request body");
		client.post(port, "localhost", "/rest").as(BodyCodec.string())
		.sendBuffer(buffer, ar -> {
			if (ar.failed()) {
				testContext.failNow(ar.cause());
			} else {
				//assertThat(response.body()).isEqualTo("Plop");
				//assertTrue(ar.result().body().contains("Secrets Container"));
				System.out.println("received after post:" + ar.result().body());
				//testContext.completeNow();
				//testContext.failNow(null);
				initClientSent.flag();
			}
		});
		
		assertTrue(testContext.awaitCompletion(5, TimeUnit.SECONDS));
		if (testContext.failed()) {
			throw testContext.causeOfFailure();
		}
	}
}
