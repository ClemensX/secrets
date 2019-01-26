package de.fehrprice.secrets.entity;

import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.persistence.Column;
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
import javax.persistence.Transient;
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
			query = "select s from Snippet s inner join s.tags t where s.id.userid = :userid and t.id.tagname = :tagname" 
			)
@NamedQuery(name = Snippet.Query_GetEntitiesByUserAndKey,
			query = "select s from Snippet s where s.id.userid = :userid and s.title = :key" 
)
public class Snippet {

	private static Logger logger = Logger.getLogger(RestServer.class.toString());
	
	public static final String Query_GetAllEntities = "InfoSnippet.GetAllEntities";
	public static final String Query_CountAllEntities = "InfoSnippet.CountAllEntities";
	public static final String Query_GetEntitiesByUser = "InfoSnippet.GetEntitiesByUser";
	public static final String Query_GetEntitiesByUserAndTag = "InfoSnippet.GetEntitiesByUserAndTag";
	public static final String Query_GetEntitiesByUserAndKey = "InfoSnippet.GetEntitiesByUserAndKey";
	@EmbeddedId
	private SnippetId id;
	private String title;
	@Column(length=4096)
	private String text;
	private Set<Tag> tags; 
	@Transient
	private String command;  // only used in server communication - not persisted 

	public SnippetId getId() {
		return id;
	}

	public void setId(SnippetId id) {
		this.id = id;
	}

	public void setUserId(Long id) {
		SnippetId sid = getId();
		if (sid == null) {
			setId(new SnippetId());
			sid = getId(); 
		}
		sid.userid = id;
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

	public void setTags(Set<Tag> tags) {
		this.tags = tags;
	}

	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
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
		System.out.println(" Snippet.getEntities Tag: " + tag);
		TypedQuery<Snippet> q = em.createNamedQuery(Query_GetEntitiesByUserAndTag, Snippet.class);
		List<Snippet> all = q.setParameter("userid", userid).setParameter("tagname", tag.getName()).getResultList();
		return all;
	}

	public static Snippet getEntityByUserAndKey(EntityManager em, Long userid, String key) {
		TypedQuery<Snippet> q = em.createNamedQuery(Query_GetEntitiesByUserAndKey, Snippet.class);
		List<Snippet> all = q.setParameter("userid", userid).setParameter("key", key).getResultList();
		if (all.size() == 0) {
			return null;
		} else {
			return all.get(0);
		}
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((command == null) ? 0 : command.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((tags == null) ? 0 : tags.hashCode());
		result = prime * result + ((text == null) ? 0 : text.hashCode());
		result = prime * result + ((title == null) ? 0 : title.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Snippet other = (Snippet) obj;
		if (command == null) {
			if (other.command != null)
				return false;
		} else if (!command.equals(other.command))
			return false;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		if (tags == null) {
			if (other.tags != null)
				return false;
		} else if (!tags.equals(other.tags))
			return false;
		if (text == null) {
			if (other.text != null)
				return false;
		} else if (!text.equals(other.text))
			return false;
		if (title == null) {
			if (other.title != null)
				return false;
		} else if (!title.equals(other.title))
			return false;
		return true;
	}

	@Override
	public String toString() {
		getTags().size();  // instantiate relation
		return "Snippet [id=" + id + ", title=" + title + ", text=" + text + ", tags=" + getTags().toString() + ", command=" + command
				+ "]";
	}

}
