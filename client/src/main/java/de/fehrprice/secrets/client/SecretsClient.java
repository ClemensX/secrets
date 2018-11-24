package de.fehrprice.secrets.client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Properties;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.secrets.HttpSession;

public class SecretsClient {

	// entries in config file:
	private static final String VERSION = "version";
	private static final String SERVER_URL = "server_url";
	private static final String SERVER_PUBLIC_KEY = "server_public_key";
	private static final String PRIVATE_KEY_FILE = "private_key_file";
	
	public static void main(String[] args) {
		OptionHandler oh = new OptionHandler();
		if (isCommand("keygen", args)) {
			keygen(args);
			done();
		}
		if (isCommand("server", args)) {
			//server(args);
			oh.handleOption(SERVER_URL, getSetup(), getConfigFilePath(), args, "Enter server url");
			oh.handleOption(SERVER_PUBLIC_KEY, getSetup(), getConfigFilePath(), args, "Enter server public key. It is advertized at the About tab of your server.");
			done();
		}
		if (isCommand("public", args)) {
			showPublicKey();
			done();
		}
		if (isCommand("configfile", args)) {
			showConfigFilePath();
			done();
		}
		// check to see if setup is ok
		if (isCommand("setup", args) || ( args.length == 0 && getSetup() == null)) {
			setup();
			done();
		}
		if (isCommand("private", args)) {
			oh.handleOption(PRIVATE_KEY_FILE, getSetup(), getConfigFilePath(), args, "Enter full path to your public key file.");
			System.out.println("  --> NEVER distribute, send or otherwise share your private key" + 
			"\n      consider storing it on a removable device"); 
			System.out.println("  --> NOBODY can re-generate your private key if you loose it!" + 
			"\n      keep it save - but keep it"); 
			done();
		}
		if (args.length > 0) {
			System.out.println("command not found: " + args[0]);
		}
		// if we reach here no command has been found
		usage();
	}

	private static void showPublicKey() {
		if (!checkConfigFile()) return;
		if (!checkPrivateKey()) return;
		String priv = readPrivateKey();
		Ed25519 ed = new Ed25519();
		String publicKey = ed.publicKey(priv);
		System.out.println("Your public key is " + publicKey);
	}

	private static boolean checkPrivateKey() {
		String pk = readPrivateKey();
		//System.out.println("### " + pk);
		if (!Conv.testEntropy(pk)) {
			System.out.println("private key is invalid (failed entropy check)");
			return false;
		}
		return true;
	}

	private static String readPrivateKey() {
		Properties p = getSetup();
		if (p == null) return null;
		String privateKeyFile = p.getProperty(PRIVATE_KEY_FILE);
		if (privateKeyFile == null) return null;
		return readPrivateKey(privateKeyFile);
	}
	private static String readPrivateKey(String privateKeyFile) {
		Path keyPath = Paths.get(privateKeyFile);
		if (!Files.exists(keyPath)) {
			System.out.println("private key file not found");
			return null;
		}
		String key;
		try {
			key = Files.readString(keyPath);
		} catch (Throwable t) {
			System.out.println("Error reading private key file " + keyPath.toString());
			return null;
		}
		return key;
	}

	/**
	 * Check that a config file exists and can be read
	 */
	private static boolean checkConfigFile() {
		Path filePath = getConfigFilePath();
		if (getSetup() == null) {
			System.out.println("Config file not found, use setup to create one: " + filePath.toAbsolutePath());
			return false;
		} else {
			return true;
		}
	}

	private static void showConfigFilePath() {
		Path filePath = getConfigFilePath();
		if (getSetup() != null) {
			System.out.println("Your config file is here: " + filePath.toAbsolutePath());
		} else {
			System.out.println("Your config file will be created here: " + filePath.toAbsolutePath());
		}
	}

	private static void setup() {
		// setup secrets client
		if (getSetup() == null) {
			// no config file yet
			System.out.println("Create config file " + getConfigFilePath() + " ? (yes/[no])");
			String l = readLine();
			if (!"yes".equalsIgnoreCase(l) && !"y".equalsIgnoreCase(l)) {
				return;
			}
			Properties p = new Properties();
			p = fillDefaultProperties(p);
			try {
				BufferedWriter writer = Files.newBufferedWriter(getConfigFilePath(),StandardOpenOption.CREATE, StandardOpenOption.WRITE);
				p.store(writer, null);
			} catch (IOException e) {
				fail("cannot write to file " + getConfigFilePath());
			}
			System.out.println("created file " + getConfigFilePath());
		}
	}

	private static Properties fillDefaultProperties(Properties p) {
		p.clear();
		p.put(VERSION, "1.0");
		return p;
	}

	private static BufferedReader in = null;
	public static String readLine() {
		if (in == null) {
			in = new BufferedReader(new InputStreamReader(System.in));
		}
		String line = null;
		try {
			line = in.readLine();
		} catch (IOException e) {
			fail("Error reading input. Abort.");
		}
		if (line == null) {
			fail("Error reading input. Abort.");
		}
		line = line.trim();
		return line;
	}

	private static Path getConfigFilePath() {
		return Paths.get(System.getProperty("user.home"), ".secrets_profile");
	}
	
	private static Properties getSetup() {
		// read config file
		if (!Files.exists(getConfigFilePath())) {
			return null;
		}
		try (BufferedReader reader = Files.newBufferedReader(getConfigFilePath())) {
			Properties p = new Properties();
			p.load(reader);
			return p;
		} catch (IOException e) {
			fail("cannot read file " + getConfigFilePath());
		}
		return null; // cannot happen
	}

	private static void server(String[] args) {
		System.out.println("Enter server URL:");
		System.out.println(new HttpSession());
	}

	private static void keygen(String[] args) {
		AES aes = new AES();
		aes.setSeed(RandomSeed.createSeed());
		int n = 1;
		if (args.length > 1) {
			// read param
			String numString = args[1];
			try {
				n = Integer.parseInt(numString);
			} catch (Throwable t ) {
				usageError("invalid number specified.");
			}
		}
		System.out.println("Private keys for Secrets! Never transmit, publish or store in an unsecure place:");
		for (int i = 0; i < n; i++) {
			String priv = Conv.toString(aes.random(32));
			System.out.println(priv);
		}
	}
		
	/**
	 * Exit with message and usage text
	 * @param msg
	 */
	private static void usageError(String msg) {
		System.out.println(msg);
		usage();
		System.exit(1);
	}
		
	/**
	 * Exit with message due to internal error.
	 * @param msg
	 */
	private static void fail(String msg) {
		System.out.println(msg);
		System.exit(1);
	}
		
	/**
	 * Exit ok after handling a command.
	 * @param msg
	 */
	private static void done() {
		System.exit(0);
	}
		
	private static boolean isCommand(String commandName, String[] args) {
		if (commandName == null || args.length < 1)
			return false;
		String command = args[0];
		if (command != null) {
			command = command.trim();
			if (commandName.equals(command)) {
				return true;
			}
		}
		return false;
	}

	private static void usage() {
		String usageString = String.join("\n",
				"sc - The Secrets! Client. See details at http://fehrprice.de:5000/secrets",
				"", 
				"usage: sc command [<options>]", 
				"", 
				"Commands:", 
				" ",
				" keygen                generate and print one 256 bit private key", 
				" keygen <n>            generate and print n 256 bit private keys", 
				" ",
				" public                show your public key", 
				" ",
				" configfile            show location of you config file", 
				" ",
				" server                interactively add or change the url of the Secrets! server", 
				" ",
				" setup                 interactively setup your Secrets! client", 
				" ",
				" private               interactively set full path and name to your private key file", 
				" "
				);
		System.out.println(usageString);
		//System.out.println("user.home=" + System.getProperty("user.home"));
	}
}
