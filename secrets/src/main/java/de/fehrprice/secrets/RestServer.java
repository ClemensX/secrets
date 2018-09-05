package de.fehrprice.secrets;

public class RestServer {

	public static String status() {
		return "Secrets Server is up. Status: " + DB.status();
	}
}
