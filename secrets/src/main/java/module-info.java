/**
 * 
 */
/**
 * @author Clemens
 *
 */
module fehrprice.secrets {
	exports de.fehrprice.secrets;
	exports de.fehrprice.secrets.entity;
	opens de.fehrprice.secrets.entity;

	requires crypto;
	requires java.logging;
	requires java.persistence;
	requires java.sql;
	requires org.junit.jupiter.api;
	requires vertx.core;
	requires vertx.junit5;
	requires vertx.web;
	requires vertx.web.client;
	//requires vertx.web.common;
}