package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;

import org.junit.jupiter.api.Test;

import de.fehrprice.db.EMFactory;
import de.fehrprice.secrets.entity.User;

/**
 * Unit test for simple App.
 */
public class AppTest {

	@Test
	public void testApp() {
		EntityManagerFactory emf = EMFactory.getEntityManager();
		System.out.println("emf = " + emf);
		EntityManager em = emf.createEntityManager();
		System.out.println("em = " + em);
		
		em.getTransaction().begin();
		User user = new User();
		user.setName("clemens");
		em.persist(user);
		em.getTransaction().commit();
		
		em.close();
		assertTrue(true);
	}
}
