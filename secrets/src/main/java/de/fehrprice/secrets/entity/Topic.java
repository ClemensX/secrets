package de.fehrprice.secrets.entity;

import java.util.List;
import java.util.logging.Logger;

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
@NamedQuery(name = Topic.Query_GetAllEntities,
            query = "select t from Topic t" 
            )
@NamedQuery(name = Topic.Query_CountAllEntities,
			query = "select count(u) from Topic t" 
			)
public class Topic {

	private static Logger logger = Logger.getLogger(Topic.class.toString());
	
	public static final String Query_GetAllEntities = "Topic.GetAllEntities";
	public static final String Query_CountAllEntities = "Topic.CountAllEntities";
	public static final String Query_GetEntitiesByKey = "Topic.GetEntitiesByKey";
	@Id
	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name.toLowerCase();
	}

	@Override
	public String toString() {
		return "Topic [name=" + name + "]";
	}
	
	// queries:
	public static List<Topic> getAllEntities(EntityManager em) {
		TypedQuery<Topic> all = em.createNamedQuery(Query_GetAllEntities, Topic.class);
		return all.getResultList();
	}

	public static long countAllEntities(EntityManager em) {
		Query query = em.createNamedQuery(Query_CountAllEntities);
		long count = (long) query.getSingleResult();
		return count;
	}
	
	public static Topic findTopic(String topicName, EntityManager em) {
		TypedQuery<Topic> all = em.createNamedQuery(Query_GetEntitiesByKey, Topic.class);
		Topic topic = all.setParameter("name", topicName).getSingleResult();
		return topic;
	}

}
