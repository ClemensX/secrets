package de.fehrprice.secrets;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;


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
    
    Route route1 = router.route("/secrets/").handler(routingContext -> {

    	  HttpServerResponse response = routingContext.response();
    	  // enable chunked responses because we will be adding data as
    	  // we execute over other handlers. This is only required once and
    	  // only if several handlers do output.
    	  response.putHeader("content-type", "text/html");
    	  response.setChunked(true);
    	  //response.putHeader("X-Content-Type-Options", "nosniff");

    	  response.write("<html><body>" +
    	          "<h1>Secrets Container</h1>" +
    	          "<p><h3>Handle... </h3></p>");

    	  // Call the next matching route after a 5 second delay
    	  routingContext.vertx().setTimer(1000, tid -> routingContext.next());
    	});

    	Route route2 = router.route("/secrets/").handler(routingContext -> {

    	  HttpServerResponse response = routingContext.response();
    	  response.write("<p><h3>...your secrets... </h3></p>");

    	  // Call the next matching route after a 5 second delay
    	  routingContext.vertx().setTimer(1000, tid -> routingContext.next());
    	});

    	Route route3 = router.route("/secrets/").handler(routingContext -> {

    	  HttpServerResponse response = routingContext.response();
    	  response.write("<p><h3>...securely!</h3></p>" +
  	          "</body></html>");

    	  // Now end the response
    	  routingContext.response().end();
    	});   	
//    	// write response and end
//    	response.end("<html><body>" +
//          "<h1>Secrets Container</h1>" +
//          "<p>version = " + routingContext.request().version() + "</p>" +
//          "</body></html>");
//    });

    server.requestHandler(router::accept).listen(port);
    System.out.println("Server started and listening on " + port);
  }
}