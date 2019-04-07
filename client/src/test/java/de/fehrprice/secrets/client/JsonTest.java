package de.fehrprice.secrets.client;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import de.fehrprice.net.DTO;

@DisplayName("Test Json Conversions")
class JsonTest {

	@Test
	void accessJsonConverter() {
		//Assertions.assertEquals("de.fehrprice.secrets.client", OptionHandler.class.getPackageName());
		Assertions.assertTrue(true);
		
		// create DTO instance:
		DTO dto = new DTO();
		Assertions.assertNotNull(dto);
		dto.command = "test";
		dto.id = "test01";
		dto.key = "ff";
		dto.signature = "f0";
		//System.out.println(dto);
		String json = DTO.asJson(dto);
		//System.out.println("as JSON: " + json);
		Assertions.assertNotNull(json);
		Assertions.assertTrue(json.length() > 10);
	}
}
