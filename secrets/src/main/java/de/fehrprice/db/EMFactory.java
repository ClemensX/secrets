package de.fehrprice.db;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

import org.eclipse.persistence.config.PersistenceUnitProperties;

// https://nozaki.me/roller/kyle/entry/how-to-bind-lookup-a
public class EMFactory {

	//public static final String PERSISTENCE_UNIT_NAME = "de.fehrprice.unit";
	public static final String PERSISTENCE_UNIT_NAME = "hsqldb-eclipselink";

	private static EntityManagerFactory factory;

	public static synchronized EntityManagerFactory getEntityManager() {
		if (factory != null)
			return factory;

        factory = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME);
        //EntityManager em = factory.createEntityManager();
        if (true) return factory;
		// uninitialized: create factory
		InitialContext ctx = null;
		try {
			Properties prop = new Properties();
			prop.put(Context.INITIAL_CONTEXT_FACTORY, "org.jboss.naming.remote.client.InitialContextFactory");
			prop.put(Context.PROVIDER_URL, "http-remoting://localhost:8181");
			prop.put("jboss.naming.client.ejb.context", true);
			prop.put(Context.URL_PKG_PREFIXES, "org.jboss.ejb.client.naming");
			ctx = new InitialContext(prop);
			// Object o = ctx.lookup("java:comp/env/jdbc/DefaultDB");
			Object o = ctx.lookup(PERSISTENCE_UNIT_NAME);
			System.out.println("lookup class name: " + o.getClass());
		} catch (NamingException e) {
//			e.printStackTrace();
//			return null;
		}
		// DataSource ds = new Da
		Map<String, String> properties = new HashMap<String, String>();
		properties.put(PersistenceUnitProperties.JDBC_DRIVER, "org.hsqldb.jdbcDriver");// "org.postgresql.Driver");
		properties.put(PersistenceUnitProperties.JDBC_URL, "jdbc:hsqldb:mem:testpers"); // Util.buildJdbcUrl(credentials));
		properties.put(PersistenceUnitProperties.JDBC_USER, ""); //credentials.username);
		properties.put(PersistenceUnitProperties.JDBC_PASSWORD, ""); //credentials.password);
		// properties.put(PersistenceUnitProperties.NON_JTA_DATASOURCE, ds);
		factory = Persistence.createEntityManagerFactory(PERSISTENCE_UNIT_NAME, properties);
		return factory;
	}
}
