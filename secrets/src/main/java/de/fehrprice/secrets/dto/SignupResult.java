package de.fehrprice.secrets.dto;

import javax.json.Json;
import javax.json.JsonObject;

public class SignupResult {
	public String result = ""; // "ok" or error message
	public String name = "";
	public String id = "";
	public String publickey = ""; 
	public boolean alreadyExisting = false;

	public String asJsonString() {
		JsonObject json = Json.createObjectBuilder()
			.add("result", result)
			.add("name", name)
			.add("id", id)
			.add("publickey", publickey)
			.add("alreadyExisting", alreadyExisting)
			.build();
		String result = json.toString();
		return result;
	}
}
