package de.fehrprice.secrets.client;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Properties;

/**
 * handle arbitrary option in properties file
 *
 */
public class OptionHandler {

	public void handleOption(String optionName, Properties p, Path configFilePath, String[] args, String infoText) {
		String v = (String) p.get(optionName);
		if (v == null || v.trim().length() == 0) {
			System.out.println(optionName + " currently not set");
		} else {
			System.out.println("currently " + optionName + " is set to " + v);
		}
		System.out.println("new value: (empty line to abort)");
		String newValue = SecretsClient.readLine();
		if (newValue == null || newValue.isBlank()) {
			return;
		}
		p.put(optionName, newValue);
		saveOptions(p, configFilePath);
	}
	
	public void updateOption(String optionName, String optionText, Properties p, Path configFilePath) {
		p.put(optionName, optionText);
		saveOptions(p, configFilePath);
	}
	
	public void saveOptions(Properties p, Path configFilePath) {
		try (BufferedWriter writer = Files.newBufferedWriter(configFilePath,StandardOpenOption.CREATE, StandardOpenOption.WRITE);) {
			p.store(writer, null);
		} catch (IOException e) {
			System.out.println("cannot write to file " + configFilePath);
		}
		System.out.println("updated file " + configFilePath);
	}

	/**
	 * Interactive questioning with descriptive text and default value.
	 * Returning null means 'keep current/default value'
	 * @param description
	 * @param current
	 * @return
	 */
	public String interactive(String description, String current) {
		if (current != null) {
			description = description + " ["  + current + "]";
		}
		System.out.println(description);
		String newValue = SecretsClient.readLine();
		if (newValue == null || newValue.isBlank()) {
			return null;
		}
		return newValue.trim();
	}

}
