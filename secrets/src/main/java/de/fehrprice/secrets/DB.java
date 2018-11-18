package de.fehrprice.secrets;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import de.fehrprice.secrets.dto.SignupResult;
import de.fehrprice.secrets.entity.Config;
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
	
	public static String status() {
        EntityManagerFactory emf = getEntityManagerFactory();
		EntityManager em = emf.createEntityManager();
		logger.info("em  = " + em);

        // write entity within new transaction
		em.getTransaction().begin();
		User user = new User();
		user.setName("clemens");
		em.persist(user);
		em.getTransaction().commit();

		// now read list of users and verify:
		List<User> users = User.getAllEntities(em);
		User testUser = users.get(0);
		logger.info("User has auto created id " + testUser.getId());
		em.close();
		logger.info("em closed");
		em = emf.createEntityManager();
		logger.info("another em  = " + em);
		long count = User.countAllEntities(em);
		em.close();
		return "ok (" + count + " users)";
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
		Config conf = getCreateConfigEntity();
		return "" + conf.getNumSlots();
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

}
