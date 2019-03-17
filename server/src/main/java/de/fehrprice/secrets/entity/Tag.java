package de.fehrprice.secrets.entity;

import java.util.List;
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
@NamedQuery(name = Tag.Query_GetAllEntities,
            query = "select t from Tag t" 
            )
@NamedQuery(name = Tag.Query_CountAllEntities,
			query = "select count(t) from Tag t" 
			)
@NamedQuery(name = Tag.Query_GetEntitiesByUserAndTagname,
			query = "select t from Tag t where t.id.userid = :userid and t.id.tagname = :tagname" 
			)
@NamedQuery(name = Tag.Query_GetEntitiesByUser,
			query = "select t from Tag t where t.id.userid = :userid" 
			)
public class Tag {

	private static Logger logger = Logger.getLogger(Tag.class.toString());
	
	public static final String Query_GetAllEntities = "Topic.GetAllEntities";
	public static final String Query_CountAllEntities = "Topic.CountAllEntities";
	public static final String Query_GetEntitiesByUserAndTagname = "Topic.GetEntitiesByKey";
	public static final String Query_GetEntitiesByUser = "Topic.GetEntitiesByUser";
	@EmbeddedId
	private TagId id;

	public TagId getId() {
		return id;
	}

	public void setId(TagId id) {
		this.id = id;
	}

	public String getName() {
		return id.tagname;
	}

	public void setName(String name) {
		this.id.tagname = name.toLowerCase();
	}

	@Override
	public String toString() {
		return "Tag [id=" + id + ", getId()=" + getId() + "]";
	}
	
	// queries:
	public static List<Tag> getAllEntities(EntityManager em) {
		TypedQuery<Tag> all = em.createNamedQuery(Query_GetAllEntities, Tag.class);
		return all.getResultList();
	}

	public static long countAllEntities(EntityManager em) {
		Query query = em.createNamedQuery(Query_CountAllEntities);
		long count = (long) query.getSingleResult();
		return count;
	}
	
	public static Tag findTagnameForUser(EntityManager em, Long userid, String tagname) {
		TypedQuery<Tag> q = em.createNamedQuery(Query_GetEntitiesByUserAndTagname, Tag.class);
		Tag tag = q.setParameter("userid", userid).setParameter("tagname", tagname).getSingleResult();
		return tag;
	}

	public static List<Tag> getEntitiesByUser(EntityManager em, Long userid) {
		TypedQuery<Tag> q = em.createNamedQuery(Query_GetEntitiesByUser, Tag.class);
		List<Tag> all = q.setParameter("userid", userid).getResultList();
		return all;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		Tag other = (Tag) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}

	public void setUserId(Long userid) {
		TagId tid = getId();
		if (tid == null) {
			setId(new TagId());
			tid = getId(); 
		}
		tid.userid = userid;
	}
}
