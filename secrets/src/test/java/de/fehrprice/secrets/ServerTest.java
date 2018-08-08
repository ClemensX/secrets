package de.fehrprice.secrets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import io.vertx.core.Vertx;
import io.vertx.junit5.VertxExtension;

@ExtendWith(VertxExtension.class)
public class ServerTest {

	@Test
	public void testServerStart() {
		//context.assertFalse(false);
	    // Use the underlying vertx instance
	    Vertx vertx = Vertx.vertx();
	}
}
