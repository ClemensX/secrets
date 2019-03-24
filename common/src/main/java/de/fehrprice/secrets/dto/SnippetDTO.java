package de.fehrprice.secrets.dto;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;

public class SnippetDTO {

	private static Logger logger = Logger.getLogger(SnippetDTO.class.toString());

	public String title;
	public String text;
	public Set<TagDTO> tags; 
	public String command;  // only used in server communication - not persisted 
	public Long snippedid;
	public Long userid;

	public static String asJsonString(SnippetDTO s)  {
		JsonObject json = asJsonBuilder(s).build();
		String result = json.toString();
		return result;
	}

	private static void addSnippetEncoding(JsonBuilderFactory factory, JsonObjectBuilder builder, SnippetDTO s) {
		if (s.snippedid != null || s.userid != null) {
			builder.add("snippetid", s.snippedid.toString());
			builder.add("userid", s.userid.toString());
		}
		if (s.command != null) builder.add("command", s.command);
		if (s.text != null) builder.add("text", s.text);
		if (s.title != null) builder.add("title", s.title);
		if (s.tags != null) {
			var arr = factory.createArrayBuilder();
			for (TagDTO tag : s.tags) {
				arr.add(tag.tagname);
			}
			builder.add("tags", arr);
		}
	}
	
	private static JsonObjectBuilder asJsonBuilder(SnippetDTO s) {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createObjectBuilder();
		addSnippetEncoding(factory, builder, s);
		return builder;
	}

	public static SnippetDTO fromJsonString(String json)  {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonObject jobj = reader.readObject();
			SnippetDTO s = fromJsonObject(jobj);
			return s;
		} catch (JsonParsingException e) {
			// could not parse - return null
			logger.warning("tried to parse non-json string: " + json);
			return null;
		}
	}

	public static SnippetDTO fromJsonObject(JsonObject jobj)  {
		//logger.severe("DTO PARSING: " + json);
		SnippetDTO s = new SnippetDTO();
		s.command = jobj.getString("command", null);
		s.text = jobj.getString("text", null);
		s.title = jobj.getString("title", null);
		var a = jobj.getJsonArray("tags");
		if (a != null) {
			var all = new ArrayList<String>();
			for (int i = 0; i < a.size(); i++) {
				all.add(a.getString(i));
			}
			var tags = new HashSet<TagDTO>();
			for (String tagstring : all) {
				TagDTO t = new TagDTO();
				t.tagname = tagstring;
				tags.add(t);
			}
			s.tags = tags;
		}
		return s;
	}

	public static List<SnippetDTO> fromJsonStringList(String json) {
		try {
			//logger.severe("DTO PARSING: " + json);
			JsonReader reader = Json.createReader(new StringReader(json));
			JsonArray array = reader.readArray();
			List<SnippetDTO> snippets = new ArrayList<>();
			for (int i = 0; i < array.size(); i++) {
				JsonObject jo = array.getJsonObject(i);
				SnippetDTO s = fromJsonObject(jo);
				snippets.add(s);
			}
			return snippets;
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
