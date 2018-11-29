package de.fehrprice.secrets.entity;

import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.TypedQuery;

import de.fehrprice.secrets.RestServer;

@Entity
@NamedQuery(name = Snippet.Query_GetAllEntities,
            query = "select u from Snippet u" 
            )
@NamedQuery(name = Snippet.Query_CountAllEntities,
			query = "select count(u) from Snippet u" 
			)
public class Snippet {

	private static Logger logger = Logger.getLogger(RestServer.class.toString());
	
	public static final String Query_GetAllEntities = "InfoSnippet.GetAllEntities";
	public static final String Query_CountAllEntities = "InfoSnippet.CountAllEntities";
	public static final String Query_GetEntitiesByKey = "InfoSnippet.GetEntitiesByKey";
	@EmbeddedId
	private SnippetId id;
	private String title;
	private String text;
	private Set<String> topics; 

	public SnippetId getId() {
		return id;
	}

	public void setId(SnippetId id) {
		this.id = id;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getText() {
		return text;
	}

	public void setText(String text) {
		this.text = text;
	}

	public Set<String> getTopics() {
		return topics;
	}

	public void setTopics(Set<String> topics) {
		this.topics = topics;
	}

	// queries:
	public static List<Snippet> getAllEntities(EntityManager em) {
		TypedQuery<Snippet> all = em.createNamedQuery(Query_GetAllEntities, Snippet.class);
		return all.getResultList();
	}

	public static long countAllEntities(EntityManager em) {
		Query query = em.createNamedQuery(Query_CountAllEntities);
		long count = (long) query.getSingleResult();
		return count;
	}
	
}
