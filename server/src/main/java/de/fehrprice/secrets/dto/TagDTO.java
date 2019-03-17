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

import de.fehrprice.secrets.entity.Snippet;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.TagId;

public class TagDTO {

	private static Logger logger = Logger.getLogger(TagDTO.class.toString());

	public static String asJsonString(List<Tag> tags)  {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createArrayBuilder();
		for (Tag t : tags) {
			builder.add(factory.createObjectBuilder()
					.add("name", t.getName())
					);
		}
		JsonArray json = builder.build();
		String result = json.toString();
		return result;
	}

	public static List<Tag> fromJsonString(String json)  {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonArray array = reader.readArray();
			List<Tag> tags = new ArrayList<>();
			for (int i = 0; i < array.size(); i++) {
				JsonObject jo = array.getJsonObject(i);
				Tag t = new Tag();
				t.setId(new TagId());
				t.setName(jo.getString("name", null));
				tags.add(t);
			}
			return tags;
		} catch (JsonParsingException e) {
			// could not parse - return null
			logger.warning("tried to parse non-json string: " + json);
			return null;
		}
	}

	public static Snippet fromJsonObject(JsonObject jobj)  {
		//logger.severe("DTO PARSING: " + json);
		Snippet s = new Snippet();
		s.setCommand(jobj.getString("command", null));
		s.setText(jobj.getString("text", null));
		s.setTitle(jobj.getString("title", null));
		var a = jobj.getJsonArray("tags");
		if (a != null) {
			var all = new ArrayList<String>();
			for (int i = 0; i < a.size(); i++) {
				all.add(a.getString(i));
			}
			var tags = new HashSet<Tag>();
			for (String tagstring : all) {
				Tag t = new Tag();
				t.setId(new TagId());
				t.setName(tagstring);
				tags.add(t);
			}
			s.setTags(tags);
		}
		return s;
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
