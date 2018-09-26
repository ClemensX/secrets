package de.fehrprice.secrets;

import de.fehrprice.crypto.Curve25519;

public class RestServer {

	public static String status() {
		return "Secrets Server is up. Status: " + DB.status();
	}

	public static String statusCrypto() {
		try {
			Curve25519 crv = new Curve25519();
			if (crv != null) {
				return "ok";
			}
		} catch (Throwable t) {
			// intentionally ignore exceptions
		}
		return "Not Available";
	}
}
