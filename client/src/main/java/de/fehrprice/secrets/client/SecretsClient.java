package de.fehrprice.secrets.client;

import de.fehrprice.crypto.AES;
import de.fehrprice.crypto.Conv;
import de.fehrprice.crypto.RandomSeed;
import de.fehrprice.secrets.HttpSession;

public class SecretsClient {

	public static void main(String[] args) {
		if (args.length < 1) {
			usage();
			System.exit(0);
		}
		if (isCommand("keygen", args)) {
			keygen(args);
		}
		if (isCommand("server", args)) {
			server(args);
		}
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
				error("invalid number specified.");
			}
		}
		System.out.println("Private keys for Secrets! Never transmit, publish or store in an unsecure place:");
		for (int i = 0; i < n; i++) {
			String priv = Conv.toString(aes.random(32));
			System.out.println(priv);
		}
	}
		
	private static void error(String msg) {
		System.out.println(msg);
		usage();
		System.exit(0);
	}
		
	private static boolean isCommand(String commandName, String[] args) {
		if (commandName == null)
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
				" server                interactively add or change the url of the Secrets! server", 
				" "
				);
		System.out.println(usageString);
	}
}
