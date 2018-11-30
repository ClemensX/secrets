package de.fehrprice.secrets;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.EntityManager;

import de.fehrprice.secrets.entity.Snippet;
import de.fehrprice.secrets.entity.SnippetId;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.TagId; 

public class SnippetManager {

	private EntityManager em;

	public SnippetManager(EntityManager em) {
		this.em = em;
	}

	public void create(Long userid, String title, String text, String[] topicStrings) {
		// get or create topic entities:
		var tags = getCreateTags(userid, topicStrings);
		var snippet = new Snippet();
		var snippetId = new SnippetId();
		snippetId.userid = userid;
		snippet.setId(snippetId);
		snippet.setTitle(title);
		snippet.setText(text);
		snippet.setTopics(tags);
		em.persist(snippet);
	}

	public List<Snippet> getEntries(Long userid, Tag tag) {
		return Snippet.getEntitiesByUserAndTag(em, userid, tag);
	}

	public List<Snippet> getEntriesByUser(Long userid) {
		return Snippet.getEntitiesByUser(em, userid);
	}

	private Set<Tag> getCreateTags(Long userid, String[] topicStrings) {
		var ret = new HashSet<Tag>();
		for ( String s : topicStrings) {
			var tid = new TagId();
			tid.userid = userid;
			tid.tagname = s;
			var t = em.find(Tag.class, tid);
			if (t != null) {
				// add existing topic
				ret.add(t);
			} else {
				// create new topic
				t = new Tag();
				t.setId(tid);
				em.persist(t);
				ret.add(t);
			}
		}
		return ret;
	}

}
