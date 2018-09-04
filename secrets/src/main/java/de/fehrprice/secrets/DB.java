package de.fehrprice.secrets;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.fehrprice.secrets.entity.User;

public class DB {
	
	private static final Logger logger = LogManager.getLogger(DB.class.getName());

	public static final String PERSISTENCE_UNIT_NAME = "secretsdb";
	//public static final String PERSISTENCE_UNIT_NAME = "hsqldb-mem-test1";
	// 

	public static String status() {
		if (false) return jdbcStatus();
		Map<String, String> props = new HashMap<String, String>();
		props.put("eclipselink.logging.level", "INFO"); // FINE, INFO, WARNING
		//props.put("javax.persistence.jdbc.url", "jdbc:hsqldb:file:target/testdb42XXX;shutdown=true");
		logger.trace("initiate db");
        EntityManagerFactory emf = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, props);
        logger.trace("emf = " + emf);
		EntityManager em = emf.createEntityManager();
		logger.trace("em  = " + em);
		
        // write entity within new transaction
		em.getTransaction().begin();
		User user = new User();
		user.setName("clemens");
		em.persist(user);
		em.getTransaction().commit();

		// now read list of users and verify:
		List<User> users = User.getAllEntities(em);
		User testUser = users.get(0);
		logger.trace("User has auto created id " + testUser.getId());
		em.close();
		logger.trace("em closed");
		em = emf.createEntityManager();
		logger.trace("another em  = " + em);
		em.close();
		return "ok";
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

}
