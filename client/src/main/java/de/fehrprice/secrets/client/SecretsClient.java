package de.fehrprice.secrets.client;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.Ed25519;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.secrets.dto.SnippetDTO;
import de.fehrprice.secrets.dto.TagDTO;

public class SecretsClient {

	// entries in config file:
	public static final String VERSION = "version";
	public static final String SERVER_URL = "server_url";
	public static final String SERVER_PUBLIC_KEY = "server_public_key";
	public static final String PRIVATE_KEY_FILE = "private_key_file";
	public static final String SIGNUP_ID = "signup_id";
	
	// error messages if config entry not found:
	private static final String ERROR_VERSION = "version";
	private static final String ERROR_SERVER_URL = "Invalid server configuration: server url missing";
	private static final String ERROR_SERVER_PUBLIC_KEY = "Invalid server configuration: server public key missing";
	private static final String ERROR_PRIVATE_KEY_FILE = "private_key_file";
	private static final String ERROR_SIGNUP_ID = "Invalid configuration: id missing, please run the id command";
	
	public static void main(String[] args) {
		OptionHandler oh = new OptionHandler();
		if (isCommand("create", args) || isCommand("c", args) || isCommand("+", args)) {
			createSnippet(args, oh);
			done();
		}
		if (isCommand("tag", args)) {
			tag(args);
			done();
		}
		if (isCommand("get", args)) {
			get(args);
			done();
		}
		if (isCommand("g", args)) {
			get(args, true);
			done();
		}
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
		if (isCommand("test", args)) {
			testConnection();
			done();
		}
		if (isCommand("id", args)) {
			getId();
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

	private static void get(String[] args) {
		get(args, false);
	}
	
	private static void get(String[] args, boolean toClipboard) {
		if (!checkConfigFile()) return;
		if (!checkPrivateKey()) return;
		Properties p = getSetup();
		if (!checkConfigExists(p, SERVER_PUBLIC_KEY, ERROR_SERVER_PUBLIC_KEY)) return;
		if (!checkConfigExists(p, SERVER_URL, ERROR_SERVER_URL)) return;
		if (!checkConfigExists(p, SIGNUP_ID, ERROR_SIGNUP_ID)) return;
		String priv = readPrivateKey();
		var server = new ServerCommunication(p, priv);
		if (args.length <= 1) {
			// no parameters: print error
			System.out.println("no key specified.");
		} else {
			System.out.println("Getting value for key " + args[1]);
			String key = server.getSnippetForKey(args[1], toClipboard);
			if (key != null && toClipboard) {
				toClipboard(key);
			}
		}
	}

	private static void toClipboard(String key) {
	    StringSelection stringSelection = new StringSelection(key);
	    Clipboard clpbrd = Toolkit.getDefaultToolkit().getSystemClipboard();
	    clpbrd.setContents(stringSelection, null);
	}

	private static void createSnippet(String[] args, OptionHandler oh) {
		SnippetDTO s = new SnippetDTO();
		String tagString = null;
		boolean complete = false;
		while (true) {
			var v = oh.interactive("Enter Key:", s.title);
			if (v != null) s.title = v;
			v = oh.interactive("Enter Value:", s.text);
			if (v!= null) s.text = v;
			tagString = oh.interactive("Enter Tags (separate with blanks):", tagString);
			if (tagString != null) {
				String[] parts = tagString.split(Pattern.quote(" "));
				Set<TagDTO> tags = new HashSet<>(); 
				for (String t : parts) {
					var tag = new TagDTO();
					tag.tagname = t;
					tags.add(tag);
				}
				s.tags = tags;
			}
			if (isAllFieldsSet(s)) {
				break;
			} else {
				String cont = oh.interactive("snippet incomplete. continue entering?", "y");
				if (cont == null || cont.startsWith("y")) {
					// re-enter cycle 
				} else {
					System.out.println("aborting...");
					return;
				}
			}
		}
		// snippet complete, send to server:
		//System.out.println("save snippet?");
		printSnippet(s);
		String saveIt = oh.interactive("\nsave snippet?", "y");
		if (saveIt == null || saveIt.startsWith("y")) {
			System.out.print("sending snippet to server...");
			s.command = "add";
			String result = sendSnippet(s);
			System.out.println(result);
		} else {
			System.out.println("aborting...");
		}
	}

	private static String sendSnippet(SnippetDTO s) {
		Properties p = getSetup();
		String priv = readPrivateKey();
		var server = new ServerCommunication(p, priv);
		return server.sendSnippet(s);
	}

	private static void printSnippet(SnippetDTO s) {
		if (s.title != null) { 
			System.out.print(s.title + "=");
			if (s.text != null) System.out.print(s.text + " ");
		}
		if (s.tags != null && !s.tags.isEmpty()) {
			System.out.print(" [");
			for (TagDTO tag : s.tags) {
				System.out.print(" " + tag.tagname);	
			}
			System.out.print(" ]");
		}
	}

	private static boolean isAllFieldsSet(SnippetDTO s) {
		if (s.title == null) return false;
		if (s.text == null) return false;
		if (s.tags == null || s.tags.isEmpty()) return false;
		return true;
	}

	private static void tag(String[] args) {
		if (!checkConfigFile()) return;
		if (!checkPrivateKey()) return;
		Properties p = getSetup();
		if (!checkConfigExists(p, SERVER_PUBLIC_KEY, ERROR_SERVER_PUBLIC_KEY)) return;
		if (!checkConfigExists(p, SERVER_URL, ERROR_SERVER_URL)) return;
		if (!checkConfigExists(p, SIGNUP_ID, ERROR_SIGNUP_ID)) return;
		String priv = readPrivateKey();
		var server = new ServerCommunication(p, priv);
		if (args.length <= 1) {
			// no parameters: get all user tags
			server.getTags();
		} else {
			server.getSnippetsForTag(args[1]);
		}
	}

	private static void testConnection() {
		if (!checkConfigFile()) return;
		if (!checkPrivateKey()) return;
		Properties p = getSetup();
		if (!checkConfigExists(p, SERVER_PUBLIC_KEY, ERROR_SERVER_PUBLIC_KEY)) return;
		if (!checkConfigExists(p, SERVER_URL, ERROR_SERVER_URL)) return;
		if (!checkConfigExists(p, SIGNUP_ID, ERROR_SIGNUP_ID)) return;
		String priv = readPrivateKey();
		var server = new ServerCommunication(p, priv);
		server.initiate();
	}

	private static void getId() {
		if (!checkConfigFile()) return;
		if (!checkPrivateKey()) return;
		Properties p = getSetup();
		if (!checkConfigExists(p, SERVER_PUBLIC_KEY, ERROR_SERVER_PUBLIC_KEY)) return;
		if (!checkConfigExists(p, SERVER_URL, ERROR_SERVER_URL)) return;
		String priv = readPrivateKey();
		var server = new ServerCommunication(p, priv);
		Long id = server.getId();
		if (id != null) {
			// we got a valid id from server, persist in config:
			Long id_config = getIdAsLong(p);
			if (id.equals(id_config)) return;
			// store new id in config:
			OptionHandler oh = new OptionHandler();
			oh.updateOption(SIGNUP_ID, id.toString(), p, getConfigFilePath());
		}
	}

	private static Long getIdAsLong(Properties p) {
		String idString = p.getProperty(SIGNUP_ID);
		if (idString == null) return null;
		idString = idString.trim();
		try {
			Long id = Long.parseLong(idString);
			return id;
		} catch (Throwable t) {
			return null;
		}
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
	
	private static boolean checkConfigExists(Properties p, String key, String error_message) {
		if (!p.containsKey(key)) {
			System.out.println(error_message);
			return false;
		} else return true;
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
			System.out.println("Config file not found in these locations:");
			printConfigFilePaths();
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

	private static String configFilename = ".secrets_profile";
	private static int parentFolderSearchLimit = 3;
	
	/**
	 * Generate list of Paths for all possible config file locations
	 * Config file should be in a parent folder of java.home.
	 * Alternatively it is also found in <current directory> or parent folders.
	 * Up to 3 parent folders will be searched.
	 * Config file name is .secrets_profile
	 * @return List of Path entities where config file is searched. 1st entry is default path
	 */
	private static List<Path> generateConfigFilePaths() {
		List<Path> paths = new ArrayList<>();
		// look in jvm location and parent chain
		String javaHome = System.getProperty("java.home");
		Path base = Paths.get(javaHome);
		Path p = Paths.get(base.toString(), configFilename);
		Path defaultPath = p.normalize();
		paths.add(defaultPath);
		for (int i = 0; i < parentFolderSearchLimit; i++) {
			base = base.getParent();
			if (base != null) {
				p = Paths.get(base.toString(), configFilename);
				paths.add(p);
			}
		}
		// look in current directory and its parent chain
		p = Paths.get(configFilename).toAbsolutePath();
		base = p.getParent();
		for (int i = 0; i < parentFolderSearchLimit; i++) {
			if (base != null) {
				p = Paths.get(base.toString(), configFilename);
				paths.add(p);
				base = base.getParent();
			}
		}
		return paths;
	}

	private static void printConfigFilePaths() {
		var paths = generateConfigFilePaths();
		var defaultPath = paths.get(0);
		for ( Path p : paths) {
			System.out.println("    " + p.toString());
		}
	}
	/**
	 * Config file should be in a parent folder of java.home.
	 * Alternatively it is also found in <current directory> or parent folders.
	 * Up to 3 parent folders will be searched.
	 * Config file name is .secrets_profile
	 * @return
	 */
	private static Path getConfigFilePath() {
		var paths = generateConfigFilePaths();
		var defaultPath = paths.get(0);
		for ( Path p : paths) {
			//System.out.println("--> " + p.toString());
			if (p.toFile().exists()) return p;
		}
		return defaultPath;
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
				" create",
				" c",
				" +                     interactively add new snippet", 
				" ",
				" tag                   get list of all your tags (CONSOLE DISPLAY)", 
				" tag <name>            get list of all key/values with tag 'name' (CONSOLE DISPLAY)", 
				" ",
				" g <key>               get snippet by key (COPY to CLIPBOARD - NO DISPLAY)", 
				" ",
				" get <key>             get snippet by key (CONSOLE DISPLAY)", 
				" ",
				" keygen                generate and print one 256 bit private key", 
				" keygen <n>            generate and print n 256 bit private keys", 
				" ",
				" public                show your public key", 
				" ",
				" test                  test connection to Secrets! server", 
				" ",
				" id                    get your id from Secrets! server and store in config file", 
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
