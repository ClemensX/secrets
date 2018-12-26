package de.fehrprice.secrets.dto;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Logger;

import javax.json.Json;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonReader;

import de.fehrprice.secrets.entity.Snippet;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.TagId;

public class SnippetDTO {

	private static Logger logger = Logger.getLogger(SnippetDTO.class.toString());

	public static String asJsonString(Snippet s)  {
		JsonBuilderFactory factory = Json.createBuilderFactory(null);
		var builder = factory.createObjectBuilder();
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
		JsonObject json = builder.build();
		String result = json.toString();
		return result;
	}

	public static Snippet fromJsonString(String json)  {
		//logger.severe("DTO PARSING: " + json);
		JsonReader reader = Json.createReader(new StringReader(json));
		JsonObject jobj = reader.readObject();
		Snippet s = fromJsonObject(jobj);
		return s;
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

}
