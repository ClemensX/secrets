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
		try (BufferedWriter writer = Files.newBufferedWriter(configFilePath,StandardOpenOption.CREATE, StandardOpenOption.WRITE);) {
			p.store(writer, null);
		} catch (IOException e) {
			System.out.println("cannot write to file " + configFilePath);
		}
		System.out.println("updated file " + configFilePath);
	}

}
