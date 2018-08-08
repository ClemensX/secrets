package de.fehrprice.secrets.entity;

import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQuery;
import javax.persistence.TypedQuery;

@Entity
@NamedQuery(name = User.Query_GetAllEntities,
            query = "select u from User u" 
            )
public class User {
	public static final String Query_GetAllEntities = "GetAllEntities";
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String name;

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
	
}
