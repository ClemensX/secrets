/**
 * 
 */
/**
 * @author Clemens
 *
 */
open module fehrprice.common {
	exports de.fehrprice.secrets.dto;
	exports de.fehrprice.secrets.entity;

	requires fehrprice.crypto;
	requires java.logging;
	requires java.persistence;
	//requires eclipselink;
	//requires java.sql;
	requires java.json;
	//requires org.junit.jupiter.api;
}