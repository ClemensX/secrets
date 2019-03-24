package de.fehrprice.secrets.dto;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;

public class TagDTO {

	private static Logger logger = Logger.getLogger(TagDTO.class.toString());

	public String tagname;
	public Long userid;

	public static String asJsonString(List<TagDTO> tags)  {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createArrayBuilder();
		for (TagDTO t : tags) {
			builder.add(factory.createObjectBuilder()
					.add("name", t.tagname)
					);
		}
		JsonArray json = builder.build();
		String result = json.toString();
		return result;
	}

	public static List<TagDTO> fromJsonString(String json)  {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonArray array = reader.readArray();
			List<TagDTO> tags = new ArrayList<>();
			for (int i = 0; i < array.size(); i++) {
				JsonObject jo = array.getJsonObject(i);
				TagDTO t = new TagDTO();
				t.tagname = jo.getString("name", null);
				tags.add(t);
			}
			return tags;
		} catch (JsonParsingException e) {
			// could not parse - return null
			logger.warning("tried to parse non-json string: " + json);
			return null;
		}
	}

	public static Long idLongfromString(String idString)  {
		try {
			long id = Long.decode(idString);
			return id;
		} catch (NumberFormatException e) {
			return null;
		}
	}
}
