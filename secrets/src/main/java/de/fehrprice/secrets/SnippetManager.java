package de.fehrprice.secrets;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.TagId; 

public class SnippetManager {

	private EntityManager em;

	public SnippetManager(EntityManager em) {
		this.em = em;
	}

	public void create(Long userid, String title, String text, String[] topicStrings) {
		// get or create topic entities:
		var topics = getCreateTopics(userid, topicStrings);
	}

	private List<Tag> getCreateTopics(Long userid, String[] topicStrings) {
		var ret = new ArrayList<Tag>();
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
