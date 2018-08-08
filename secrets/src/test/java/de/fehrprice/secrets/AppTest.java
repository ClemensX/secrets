package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.junit.jupiter.api.Test;

import de.fehrprice.secrets.entity.User;

/**
 * Unit test for simple App.
 */
public class AppTest {

	public static final String PERSISTENCE_UNIT_NAME = "hsqldb-mem-test1";

	@Test
	public void testApp() {
		Map<String, String> props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "INFO"); // FINE, INFO, WARNING
		//props.put("javax.persistence.jdbc.url", "jdbc:hsqldb:file:target/testdb42XXX;shutdown=true");
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
		//EntityManagerFactory emf = EMFactory.getEntityManager();
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
