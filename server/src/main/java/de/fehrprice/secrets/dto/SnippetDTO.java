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
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;

import de.fehrprice.secrets.HttpSession;
import de.fehrprice.secrets.entity.Snippet;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.TagId;

public class SnippetDTO {

	private static Logger logger = Logger.getLogger(SnippetDTO.class.toString());

	public static String asJsonString(Snippet s)  {
		JsonObject json = asJsonBuilder(s).build();
		String result = json.toString();
		return result;
	}

	private static void addSnippetEncoding(JsonBuilderFactory factory, JsonObjectBuilder builder, Snippet s) {
		if (s.getId() != null) {
			builder.add("snippetid", s.getId().snippedid.toString());
			builder.add("userid", s.getId().userid.toString());
		}
		if (s.getCommand() != null) builder.add("command", s.getCommand());
		if (s.getText() != null) builder.add("text", s.getText());
		if (s.getTitle() != null) builder.add("title", s.getTitle());
		if (s.getTags() != null) {
			var arr = factory.createArrayBuilder();
			for (Tag tag : s.getTags()) {
				arr.add(tag.getName());
			}
			builder.add("tags", arr);
		}
	}
	
	private static JsonObjectBuilder asJsonBuilder(Snippet s) {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createObjectBuilder();
		addSnippetEncoding(factory, builder, s);
		return builder;
	}

	public static Snippet fromJsonString(String json)  {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonObject jobj = reader.readObject();
			Snippet s = fromJsonObject(jobj);
			return s;
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

	public static List<Snippet> fromJsonStringList(String json) {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonArray array = reader.readArray();
			List<Snippet> snippets = new ArrayList<>();
			for (int i = 0; i < array.size(); i++) {
				JsonObject jo = array.getJsonObject(i);
				Snippet s = fromJsonObject(jo);
				snippets.add(s);
			}
			return snippets;
		} catch (JsonParsingException e) {
			// could not parse - return null
			logger.warning("tried to parse non-json string: " + json);
			return null;
		}
	}

	public static String asJsonString(List<Snippet> snippets)  {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createArrayBuilder();
		for (Snippet s : snippets) {
			var b = factory.createObjectBuilder();
			addSnippetEncoding(factory, b, s);
			builder.add(b);
		}
		JsonArray json = builder.build();
		String result = json.toString();
		return result;
	}

}
