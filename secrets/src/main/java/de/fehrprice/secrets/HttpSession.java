package de.fehrprice.secrets;

import de.fehrprice.net.DTO;
import de.fehrprice.net.Session;

public class HttpSession {

	public boolean senderValidated;
	public String id;
	public DTO dto;
	public byte[] sessionKey;
	// may only be available for server side
	public Session cryptoSession;
	public String plaintext; // decrypted message
	public byte[] aesMsg;
}
