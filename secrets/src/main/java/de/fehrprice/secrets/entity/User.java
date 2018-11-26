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
@Table(name = "myuser") // user is not an allowed table name with postgresql
@NamedQuery(name = User.Query_GetAllEntities,
            query = "select u from User u" 
            )
@NamedQuery(name = User.Query_CountAllEntities,
			query = "select count(u) from User u" 
			)
@NamedQuery(name = User.Query_GetEntitiesByKey,
			query = "select u from User u where u.publicKey = :publicKey" 
)
public class User {

	private static Logger logger = Logger.getLogger(User.class.toString());
	
	public static final String Query_GetAllEntities = "GetAllEntities";
	public static final String Query_CountAllEntities = "CountAllEntities";
	public static final String Query_GetEntitiesByKey = "GetEntitiesByKey";
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String name;
	private String publicKey;

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public Long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return "User [name=" + name + "]";
	}
	
	// queries:
	public static List<User> getAllEntities(EntityManager em) {
		TypedQuery<User> all = em.createNamedQuery(Query_GetAllEntities, User.class);
		return all.getResultList();
	}

	public static long countAllEntities(EntityManager em) {
		Query query = em.createNamedQuery(Query_CountAllEntities);
		long count = (long) query.getSingleResult();
		return count;
	}
	
	public static User findUser(String publicKey, EntityManager em) {
		TypedQuery<User> all = em.createNamedQuery(Query_GetEntitiesByKey, User.class);
		List<User> users = all.setParameter("publicKey", publicKey).getResultList();
		if (users.size() == 0) {
			return null;
		}
		if (users.size() > 1) {
			logger.severe("Non unique public key in User table: " + publicKey);
			throw new NonUniqueResultException("Non unique public key in User table");
		}
		return users.get(0);
	}

}
