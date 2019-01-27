package de.fehrprice.secrets;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import de.fehrprice.crypto.Conv;
import de.fehrprice.secrets.dto.SignupResult;
import de.fehrprice.secrets.dto.SnippetDTO;
import de.fehrprice.secrets.dto.TagDTO;
import de.fehrprice.secrets.entity.Config;
import de.fehrprice.secrets.entity.Snippet;
import de.fehrprice.secrets.entity.Tag;
import de.fehrprice.secrets.entity.User;

public class DB {
	
	private static final Logger logger = Logger.getLogger(DB.class.getName());

	public static final String PERSISTENCE_UNIT_NAME = "secretsdb";
	//public static final String PERSISTENCE_UNIT_NAME = "hsqldb-mem-test1";
	// 

	private static EntityManagerFactory emf = null;
	
	public static EntityManagerFactory getEntityManagerFactory() {
		if (emf != null && emf.isOpen()) {
			return emf;
		}
		// emf not open or not initialized, create new one:
		Map<String, String> props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "INFO"); // FINE, INFO, WARNING
		props.put("javax.persistence.jdbc.password", System.getenv("DEFAULT_PASSWORD"));
		logger.warning("READ PW " + System.getenv("DEFAULT_PASSWORD"));
		//props.put("javax.persistence.jdbc.url", "jdbc:hsqldb:file:target/testdb42XXX;shutdown=true");
		logger.info("initiate EntityManagerFactory for persistence unit " + PERSISTENCE_UNIT_NAME);
        emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
        logger.info("emf = " + emf);
        return emf;
	}
	
	/**
	 * Test Status by adding and removing a test user.
	 * Only if this was successful "ok" will be returned.
	 * @return
	 */
	public static String status() {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		logger.info("em  = " + em);

        // write entity within new transaction
		em.getTransaction().begin();
		User user = new User();
		user.setName("11980463587use_name_garbage_843635328");
		em.persist(user);
		em.getTransaction().commit();
		em.refresh(user);
		long id = user.getId();
		logger.info("id  = " + id);

		// now read list of users and verify:
		List<User> users = User.getAllEntities(em);
		User testUser = em.find(User.class, id);
		if (testUser != null) {
			em.getTransaction().begin();
			em.remove(testUser);
			em.getTransaction().commit();
			logger.info("user removed, id: " + id);
		} else {
			return "error";
		}
		em.close();
//		em = emf.createEntityManager();
//		logger.info("another em  = " + em);
//		long count = User.countAllEntities(em);
//		em.close();
		return "ok";
	}

	public static Config getCreateConfigEntity() {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		Config conf = em.find(Config.class, 0);
		if (conf == null) {
			em.getTransaction().begin();
			conf = new Config();
			conf.setId(0);
			conf.setNumSlots(100);
			em.persist(conf);
			em.getTransaction().commit();
			System.out.println("CREATE Config Entity");
		}
		em.detach(conf);
		em.close();
		return conf;
	}
	
	public static String getFreeSlots() {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		Config conf = getCreateConfigEntity();
		int numSLots = conf.getNumSlots(); 
		long numUsed = User.countAllEntities(em);
		return "" + (numSLots - numUsed); 
	}
	
	private static String jdbcStatus() {
		String url = "jdbc:postgresql://db:5432/secretsdb";
		Properties props = new Properties();
		props.setProperty("user","postgres");
		props.setProperty("password","geheim");
		//props.setProperty("ssl","true");
		try {
			Connection conn = DriverManager.getConnection(url, props);
			System.out.println("conn = " + conn);
		} catch (SQLException e) {
			e.printStackTrace();
			return "not ok";
		}
		return "ok";
	}

	public static SignupResult signup(String name, String key) {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		SignupResult su = new SignupResult();
		User u = User.findUser(key, em);
		if (u != null) {
			su.result = "User with this public key already exists";
			su.alreadyExisting = true;
			return su;
		} else if (Conv.testEntropy(key) == false) {
			su.result = "Invalid key provided";
			su.alreadyExisting = false;
			return su;
		} else {
			em.getTransaction().begin();
			u = new User();
			u.setName(name);
			u.setPublicKey(key);
			em.persist(u);
			em.getTransaction().commit();
			em.detach(u);
			em.close();
			su.id = u.getId().toString();
			su.name = u.getName();
			su.publickey = u.getPublicKey();
			su.result = "ok";
			return su;
		}
	}

	public static Long findId(String clientPublicKey) {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		User u = User.findUser(clientPublicKey, em);
		if (u != null) {
			return u.getId();
		}
		return null;
	}

	public static String findKey(Long id) {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		User u = em.find(User.class, id);
		if (u != null) {
			return u.getPublicKey();
		}
		return null;
	}

	/**
	 * Add snippet to db if it has a new key,
	 * change existing snippet if key already exists
	 * @param s
	 * @return
	 */
	public static String addSnippet(Snippet s) {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		em.getTransaction().begin();

		// try to find existing key:
		Snippet existing = Snippet.getEntityByUserAndKey(em, s.getId().userid, s.getTitle());
		if (existing != null) {
			System.out.println("found existing");
			//em.getTransaction().rollback();
			existing.setText(s.getText());
			existing.setTags(s.getTags());
			// merge (re-create) tags
			for (Tag tag : s.getTags()) {
				tag.setUserId(s.getId().userid);
				em.merge(tag);
			}
			em.merge(existing);
			em.getTransaction().commit();
			em.close();
			return "replaced existing snippet";
		}
		// merge tags
		for (Tag tag : s.getTags()) {
			tag.setUserId(s.getId().userid);
			em.merge(tag);
		}

		em.persist(s);
		em.getTransaction().commit();
		//em.detach(u);
		em.close();
		return "snippet added to DB";
	}

	public static String getTags(Snippet s) {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		List<Tag> tags = Tag.getEntitiesByUser(em, s.getId().userid); 
		System.out.println("Tags:");
		for (Tag t : tags) {
			System.out.println(t.getName());
		}
		String json = TagDTO.asJsonString(tags);
		System.out.println("Tags: " + json);
		return json;
	}

	public static String getSnippetsForTag(Snippet s) {
		if (s.getTags() == null || s.getTags().size() != 1) {
			//we have no tag - cannot continue
			return "error - need exactly one tag for gettag command";
		}
		Tag tag = s.getTags().iterator().next();
		System.out.println(" userid: " + s.getId().userid);
		System.out.println(" Tag: " + tag);
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		var snippets = Snippet.getEntitiesByUserAndTag(em, s.getId().userid, tag);
		String json = SnippetDTO.asJsonString(snippets);
		System.out.println("Snippets: " + json);
//		for (Snippet sn : snippets) {
//			System.out.println(sn);
//		}
		return json;
	}

}
