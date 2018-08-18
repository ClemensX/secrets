package de.fehrprice.secrets;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
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
    router.route("/secrets/*").handler(StaticHandler.create());
    
    // handle backend calls:
    Route route1 = router.route("/secretsbackend/").handler(routingContext -> {

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

    server.requestHandler(router::accept).listen(port);
    System.out.println("Server started and listening on " + port);
  }
}