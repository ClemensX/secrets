package de.fehrprice.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import de.fehrprice.net.DTO;

@DisplayName("Modular White Box Patch Runtime Tests // main -> 'module crypto' | test -> _no module_")
class ModularWhiteBoxPatchRuntimeTests {
//	@Test - we only have public classes, so this test is omitted
//	void accessPackageFoo() {
//		Assertions.assertEquals("de.fehrprice.net", DTO.class.getPackageName());
//		Assertions.assertEquals("crypto", DTO.class.getModule().getName());
//	}

	@Test
	void accessPublicClass() {
        System.out.println("ModularWhiteBoxPatchRuntimeTests");
		Assertions.assertEquals("de.fehrprice.net", DTO.class.getPackageName());
		var module_name = DTO.class.getModule().getName();
		if (module_name != null) Assertions.assertEquals("fehrprice.crypto", module_name);
		else System.out.println("Could not get module name!!!");
	}
}
