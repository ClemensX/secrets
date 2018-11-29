package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.User;
import de.fehrprice.secrets.SnippetManager;

/**
 * Unit test for simple App.
 */
public class JPATest {

	public static final String PERSISTENCE_UNIT_NAME = "hsqldb-mem-test1";

	@Test
	public void testJPA() {
		Map<String, String> props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "INFO"); // FINE, INFO, WARNING
		//props.put("javax.persistence.jdbc.url", "jdbc:hsqldb:file:target/testdb42XXX;shutdown=true");
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
        assertNotNull(emf);
		EntityManager em = emf.createEntityManager();
        assertNotNull(em);
		
        // write entity within new transaction
		em.getTransaction().begin();
		User user = new User();
		user.setName("clemens");
		em.persist(user);
		em.getTransaction().commit();

		// now read list of users and verify:
		List<User> users = User.getAllEntities(em);
		assertEquals(1, users.size());
		User testUser = users.get(0);
		assertEquals("clemens", testUser.getName());
		System.out.println("User has auto created id " + testUser.getId());
		
		em.close();
		assertTrue(true);
	}

	@Test
	public void testSnippetsPersistance() {
		Map<String, String> props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "INFO"); // FINE, INFO, WARNING
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
        assertNotNull(emf);
		EntityManager em = emf.createEntityManager();
        assertNotNull(em);
		
        // use fixed userid for testing
        Long userid = 101L;
        
        // write entity within new transaction
		em.getTransaction().begin();

		var sm = new SnippetManager(em);
		String tags[] = {"url", "test", "mycompany"};
		sm.create(userid, "homepage", "http://www.google.com", tags);
		var ts = Tag.getAllEntities(em);
//		for (Tag t : ts) {
//			System.out.println("TAG name / userid: " + t.getName() + " / " + t.getId().userid);
//		}
		assertEquals(3, ts.size());
		

		// now read list of users and verify:
//		List<User> users = User.getAllEntities(em);
//		assertEquals(1, users.size());
//		User testUser = users.get(0);
//		assertEquals("clemens", testUser.getName());
//		System.out.println("User has auto created id " + testUser.getId());
		
		em.getTransaction().commit();
		em.close();
		assertTrue(true);
	}
}
