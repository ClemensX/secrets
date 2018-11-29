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
public class Tag {

	private static Logger logger = Logger.getLogger(Tag.class.toString());
	
	public static final String Query_GetAllEntities = "Topic.GetAllEntities";
	public static final String Query_CountAllEntities = "Topic.CountAllEntities";
	public static final String Query_GetEntitiesByKey = "Topic.GetEntitiesByKey";
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
		return "Topic [name=" + getName() + "]";
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
	
	public static Tag findTag(String tagName, EntityManager em) {
		TypedQuery<Tag> all = em.createNamedQuery(Query_GetEntitiesByKey, Tag.class);
		Tag tag = all.setParameter("name", tagName).getSingleResult();
		return tag;
	}

}
