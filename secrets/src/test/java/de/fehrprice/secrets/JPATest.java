package de.fehrprice.secrets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.fehrprice.secrets.dto.SnippetDTO;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.User;

/**
 * Unit test for simple App.
 */
public class JPATest {

	public static final String PERSISTENCE_UNIT_NAME = "hsqldb-mem-test1";
	private static Map<String, String> props = null;

	@BeforeAll
	public static void setup() {
		// props setting will only work once during test excecution, so we need to have
		// them at a single place because
		// we cannot predict which test method will be first
		props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "FINE"); // FINE, INFO, WARNING
		// props.put("javax.persistence.jdbc.url", // "jdbc:hsqldb:file:target/testdb42XXX;shutdown=true");
	}

	@Test
	public void testJPA() {
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
		EntityManagerFactory emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
		assertNotNull(emf);
		EntityManager em = emf.createEntityManager();
		assertNotNull(em);

		// use fixed userid for testing
		Long userid = 101L;

		// write entity within new transaction
		em.getTransaction().begin();

		var sm = new SnippetManager(em);
		String tags[] = { "url", "test", "mycompany" };
		sm.create(userid, "homepage", "http://www.google.com", tags);
		var ts = Tag.getAllEntities(em);
//		for (Tag t : ts) {
//			System.out.println("TAG name / userid: " + t.getName() + " / " + t.getId().userid);
//		}
		assertEquals(3, ts.size());
		var snippets = sm.getEntriesByUser(userid);
		assertEquals(1, snippets.size());

		snippets = sm.getEntries(userid, ts.get(0));
		assertEquals(1, snippets.size());

		String[] tags2 = { "something", "test", "another" };
		sm.create(userid, "test headline", "Make more tests!!", tags2);
		sm.create(userid, "some head", "garbage", new String[] {"taggy"});
		
		Tag t = sm.findTagnameForUser(userid, "test");
		assertNotNull(t);
		assertEquals("test", t.getName());
		
		snippets = sm.getEntries(userid, t);
		assertEquals(2, snippets.size());
		
		em.getTransaction().commit();
		em.close();
		assertTrue(true);
	}
	
	@Test
	public void testJsonMapping() {
		String jsonString = "{\"text\":\"some content\",\"title\":\"key\",\"tags\":[\"url\",\"pw\"]}";
		var snippet1 = SnippetDTO.fromJsonString(jsonString);
		var snippet2 = SnippetDTO.fromJsonString(SnippetDTO.asJsonString(snippet1));
		
		//assertEquals(jsonString, redone);
		assertEquals(snippet1, snippet2);
		var snippet3 = SnippetDTO.fromJsonString(jsonString.replaceFirst("pw", "pw2"));
		//System.out.println(SnippetDTO.asJsonString(snippet3));
		assertNotEquals(snippet1, snippet3);
	}
}
