package de.fehrprice.secrets;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;


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

    server.requestHandler(req -> {
      req.response().putHeader("content-type", "text/html").end("<html><body>" +
          "<h1>Hello from vert.x on Kub!</h1>" +
          "<p>version = " + req.version() + "</p>" +
          "</body></html>");
    }).listen(port);
    System.out.println("Server started and listening on " + port);
  }
}