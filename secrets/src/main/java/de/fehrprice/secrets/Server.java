package de.fehrprice.secrets;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
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
    
    router.route().handler(routingContext -> {
    	// handler will be called for every request
    	HttpServerResponse response = routingContext.response();
    	response.putHeader("content-type", "text/html");
    	
    	// write response and end
    	response.end("<html><body>" +
          "<h1>Secrets Container</h1>" +
          "<p>version = " + routingContext.request().version() + "</p>" +
          "</body></html>");
    });

    server.requestHandler(router::accept).listen(port);
    System.out.println("Server started and listening on " + port);
  }
}