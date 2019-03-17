package de.fehrprice.crypto;

import java.util.Base64;

public class JWT {

	public static final Decoder getDecoder(String token) {
		return new JWT().new Decoder(token);
	}

	public class Decoder {

		private String token;
		
		public Decoder(String token) {
			this.token = token;
		}

		public String decodeHeader() {
			// find first '.' that marks end of header:
			int headerEndPos = token.indexOf('.');
			if (headerEndPos < 0) return null;
			String header = token.substring(0, headerEndPos);
			//System.out.println(header);
			return new String(Base64.getUrlDecoder().decode(header));
		}
		
		public String decodePayload() {
			// find first '.' that marks end of header:
			int headerEndPos = token.indexOf('.');
			if (headerEndPos < 0) return null;
			// find second '.' that marks end of payload:
			int payloadEndPos = token.indexOf('.', headerEndPos + 1);
			if (payloadEndPos < 0) return null;
			
			String payload = token.substring(headerEndPos+1, payloadEndPos);
			//System.out.println(header);
			return new String(Base64.getUrlDecoder().decode(payload));
		}
		
	}
}
