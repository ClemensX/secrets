package de.fehrprice.secrets.dto;

import java.io.StringReader;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import de.fehrprice.net.DTO;

public class GetIdResult {
	public boolean validated = false;
	public Long id = null;

	public String asJsonString() {
		var builder = Json.createObjectBuilder()
			.add("validated", validated);
			if (id != null) builder.add("id", id);
			var json = builder.build();
		String result = json.toString();
		return result;
	}

	public static GetIdResult fromJsonString(String json)  {
		//logger.severe("DTO PARSING: " + json);
		JsonReader reader = Json.createReader(new StringReader(json));
		JsonObject jobj = reader.readObject();
		GetIdResult dto = fromJsonObject(jobj);
		return dto;
	}

	public static GetIdResult fromJsonObject(JsonObject jobj)  {
		//logger.severe("DTO PARSING: " + json);
		GetIdResult dto = new GetIdResult();
		dto.validated = jobj.getBoolean("validated", false);
		var res_id = jobj.getJsonNumber("id");
		if (res_id != null) {
			dto.id = res_id.longValueExact();
		}
		return dto;
	}
}
