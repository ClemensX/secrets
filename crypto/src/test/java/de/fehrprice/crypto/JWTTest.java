package de.fehrprice.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.StringReader;
import java.util.Arrays;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.fehrprice.crypto.JWT;

public class JWTTest {

	String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMSIsImV4dF9hdHRyIjp7ImVuaGFuY2VyIjoiWFNVQUEifSwic3ViIjoiMTExMTExMTEtMjIyMi0zMzMzLTMzMzMtNDQ0NDQ0NDQ0NDQ0Iiwic2NvcGUiOlsicmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyLkRlbGV0ZSIsIm9wZW5pZCIsInJic19yZWdzZXJ2aWNlX2JhY2tlbmQhdDc2Mi5EaXNwbGF5IiwicmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyLkVkaXQiXSwiY2xpZW50X2lkIjoic2ItcmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyIiwiY2lkIjoic2ItcmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyIiwiYXpwIjoic2ItcmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyIiwiZ3JhbnRfdHlwZSI6ImF1dGhvcml6YXRpb25fY29kZSIsInVzZXJfaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJvcmlnaW4iOiJsZGFwIiwidXNlcl9uYW1lIjoiY2xlbWVuc2ZlaHJAZ214LmRlIiwiZW1haWwiOiJjbGVtZW5zZmVockBnbXguZGUiLCJnaXZlbl9uYW1lIjoiIiwiZmFtaWx5X25hbWUiOiIiLCJhdXRoX3RpbWUiOjE1MTIxMjc5OTcsInJldl9zaWciOiI0YjEyNjE3ZiIsImlhdCI6MTUxMjEyOTI3NCwiZXhwIjoxNTEyMTcyNDc0LCJpc3MiOiJodHRwOi8vcmVnc2VydmljZS5sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iLCJ6aWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJhdWQiOlsic2ItcmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyIiwicmJzX3JlZ3NlcnZpY2VfYmFja2VuZCF0NzYyIiwib3BlbmlkIl19.FiKLK_kTyD7FZpHGpf063iIYWdHl9Mp7n58MJZSZ7W0";
	String decoded_header1 = "{\\r\\n" + 
			"  \"alg\": \"RS256\",\\r\\n" + 
			"  \"typ\": \"JWT\"\\r\\n" + 
			"}";
	String decoded_payload1 = "{\r\n" + 
			"  \"jti\": \"11111111111111111111111111111111\",\r\n" + 
			"  \"ext_attr\": {\r\n" + 
			"    \"enhancer\": \"XSUAA\"\r\n" + 
			"  },\r\n" + 
			"  \"sub\": \"11111111-2222-3333-3333-444444444444\",\r\n" + 
			"  \"scope\": [\r\n" + 
			"    \"rbs_regservice_backend!t762.Delete\",\r\n" + 
			"    \"openid\",\r\n" + 
			"    \"rbs_regservice_backend!t762.Display\",\r\n" + 
			"    \"rbs_regservice_backend!t762.Edit\"\r\n" + 
			"  ],\r\n" + 
			"  \"client_id\": \"sb-rbs_regservice_backend!t762\",\r\n" + 
			"  \"cid\": \"sb-rbs_regservice_backend!t762\",\r\n" + 
			"  \"azp\": \"sb-rbs_regservice_backend!t762\",\r\n" + 
			"  \"grant_type\": \"authorization_code\",\r\n" + 
			"  \"user_id\": \"11111111-2222-3333-4444-555555555555\",\r\n" + 
			"  \"origin\": \"ldap\",\r\n" + 
			"  \"user_name\": \"clemensfehr@gmx.de\",\r\n" + 
			"  \"email\": \"clemensfehr@gmx.de\",\r\n" + 
			"  \"given_name\": \"\",\r\n" + 
			"  \"family_name\": \"\",\r\n" + 
			"  \"auth_time\": 1512127997,\r\n" + 
			"  \"rev_sig\": \"4b12617f\",\r\n" + 
			"  \"iat\": 1512129274,\r\n" + 
			"  \"exp\": 1512172474,\r\n" + 
			"  \"iss\": \"http://regservice.localhost:8080/uaa/oauth/token\",\r\n" + 
			"  \"zid\": \"11111111-2222-3333-4444-555555555555\",\r\n" + 
			"  \"aud\": [\r\n" + 
			"    \"sb-rbs_regservice_backend!t762\",\r\n" + 
			"    \"rbs_regservice_backend!t762\",\r\n" + 
			"    \"openid\"\r\n" + 
			"  ]\r\n" + 
			"}";
	
	@BeforeAll
	public static void setUp() throws Exception {
        System.out.println("JWTTest");
	}

	@AfterAll
	public static void tearDown() throws Exception {
	}

	@Test
	public void test() {
		// ROLES testing
		String decodeHeader = JWT.getDecoder(token).decodeHeader();
		//System.out.println("Decoded Header: " + decodeHeader);
		String decodePayload = JWT.getDecoder(token).decodePayload();
		//System.out.println("Decoded Payload: " + decodePayload);
		//fail("Not yet implemented");
		JsonReader reader = Json.createReader(new StringReader(decodePayload));
		JsonObject jobj = reader.readObject();
		//System.out.println(jobj);
		JsonArray scopes = jobj.getJsonArray("scope");
		//System.out.println(scopes);
		String[] roles = new String[scopes.size()];
		for (int i = 0; i < scopes.size(); i++) {
			roles[i] = scopes.getString(i);
		}
		for (String s : roles)
			System.out.println(s);
		// get roles as list:
		List<String> rolesList = Arrays.asList(roles);
		assertTrue(rolesList.contains("rbs_regservice_backend!t762.Delete"));
		assertTrue(rolesList.contains("rbs_regservice_backend!t762.Display"));
		assertTrue(rolesList.contains("rbs_regservice_backend!t762.Edit"));
		
		// USER name and email testing
		String username = jobj.getString("user_name");
		assertEquals("clemensfehr@gmx.de", username);
		
		String email = jobj.getString("email");
		assertEquals("clemensfehr@gmx.de", email);
	}

}
