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
@NamedQuery(name = Snippet.Query_GetEntitiesByUser,
			query = "select u from Snippet u where u.id.userid = :userid" 
			)
@NamedQuery(name = Snippet.Query_GetEntitiesByUserAndTag,
			query = "select s from Snippet s inner join s.tags t where s.id.userid = :userid and t = :tag" 
			)
public class Snippet {

	private static Logger logger = Logger.getLogger(RestServer.class.toString());
	
	public static final String Query_GetAllEntities = "InfoSnippet.GetAllEntities";
	public static final String Query_CountAllEntities = "InfoSnippet.CountAllEntities";
	public static final String Query_GetEntitiesByUser = "InfoSnippet.GetEntitiesByUser";
	public static final String Query_GetEntitiesByUserAndTag = "InfoSnippet.GetEntitiesByUserAndTag";
	@EmbeddedId
	private SnippetId id;
	private String title;
	private String text;
	private Set<Tag> tags; 

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

	public Set<Tag> getTags() {
		return tags;
	}

	public void setTopics(Set<Tag> tags) {
		this.tags = tags;
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
	
	public static List<Snippet> getEntitiesByUser(EntityManager em, Long userid) {
		TypedQuery<Snippet> q = em.createNamedQuery(Query_GetEntitiesByUser, Snippet.class);
		List<Snippet> all = q.setParameter("userid", userid).getResultList();
		return all;
	}

	public static List<Snippet> getEntitiesByUserAndTag(EntityManager em, Long userid, Tag tag) {
		TypedQuery<Snippet> q = em.createNamedQuery(Query_GetEntitiesByUserAndTag, Snippet.class);
		List<Snippet> all = q.setParameter("userid", userid).setParameter("tag", tag).getResultList();
		return all;
	}

}
