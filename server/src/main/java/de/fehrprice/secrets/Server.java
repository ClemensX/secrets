package de.fehrprice.secrets;

import de.fehrprice.crypto.Conv;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.StaticHandler;


/*
 * @author <a href="http://tfox.org">Tim Fox</a>
 */
public class Server extends AbstractVerticle {

  // listening port
  private static int port = 5000; 
	
  // Convenience method so you can run it in your IDE
  public static void main(String[] args) {
    Runner.runExample(Server.class);
  }

  @Override
  public void start() throws Exception {

    HttpServer server =
      vertx.createHttpServer(new HttpServerOptions());
    Router router = Router.router(vertx);
    
    // handle main application via static resources:
    router.route("/secrets/*").handler(StaticHandler.create().setIndexPage("/secrets/index.html"));
    
    // reroute short URL to proper start page:
    Route route1 = router.route("/secrets").handler(routingContext -> {
    	  HttpServerResponse response = routingContext.response();
    	  response.putHeader("location", "/secrets/index.html").setStatusCode(302).end();
    	});

    // handle backend calls:
    Route route2 = router.route("/secretsbackend/").handler(routingContext -> {

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

	router.route("/secretsbackend/restmsg").handler(routingContext -> {
		HttpServerResponse response = routingContext.response();
		response.putHeader("content-type", "application/octet-stream");
		response.setChunked(true);
		HttpServerRequest req = routingContext.request();
		req.bodyHandler(bodyHandler -> {
			byte[] aesmsg = bodyHandler.getBytes();
			//System.out.println("received aes message");
			HttpSession session = RestServer.getInstance().handleAESMessage(aesmsg);
			if (session != null) {
				System.out.println("received: " + session.plaintext);
			}
			if (session.aesMsg != null) {
				Buffer aesBuffer = Buffer.buffer(session.aesMsg);
				//System.out.println("writing buffer len " + aesBuffer.length());
				response.write(aesBuffer);
			}
			//response.write("").end();
			response.end();
		});
		// routingContext.response().end();

	});
    router.route("/secretsbackend/rest/*").handler(BodyHandler.create());
    router.route("/secretsbackend/rest/*").handler(routingContext -> {
      //System.out.println("path: " + routingContext.request().path());
      // look for post requests:
      HttpServerRequest request = routingContext.request();
  	  HttpServerResponse response = routingContext.response();
  	  response.setChunked(true);
      if (request.method() == HttpMethod.POST) {
//          String body = routingContext.getBodyAsString();
//          System.out.println("received body: " + body);
          JsonObject bodyj = routingContext.getBodyAsJson();
//          System.out.println("received body: " + bodyj);
      	  response.putHeader("content-type", "application/json");
      	  response.write(RestServer.getInstance().restCall(routingContext.request().path(), bodyj));
      } else {
    	  // GET requests
	  	  response.putHeader("content-type", "text/plain");
	  	  response.write(RestServer.getInstance().restCall(routingContext.request().path()));
      }
  	  routingContext.response().end();
  	});


    server.requestHandler(router::accept).listen(port);
    System.out.println("Server started and listening on " + port);
  }
}