/*
 * Copyright 2023 Frank Werres (https://github.com/FrankWerres/molos)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.fwerres.molos.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.cxf.endpoint.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import com.fwerres.molos.Molos;
import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;
import com.fwerres.molos.config.SaveLocations;
import com.fwerres.molos.config.UserConfig;
import com.fwerres.testsupport.JaxRSHelper;

public class MolosConfigTest {
	private static JaxRSHelper jaxrs = new JaxRSHelper();
	
	private static String wsUrl;

	private static Server theServer;
	
	@BeforeAll
	public static void setUp() throws Exception {
		if (theServer == null) {
			theServer = jaxrs.createLocalCXFServer("/oidcMock", Molos.class, new com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider(), new Object[] { });
			wsUrl = jaxrs.getActualUrl(theServer);
			System.out.println("Started server on " + wsUrl);
		}
	}

	@AfterAll
	public static void tearDown() {
		if (theServer != null) {
			theServer.stop();
			theServer = null;
		}
	}

	@Test
	public void testConfig() {
		MolosConfig setup = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
		
		OpenIdConfig config = setup.getOIDCConfig();
		
		assertTrue(config != null);
		assertFalse(config.getIssuer().isEmpty());
		assertFalse(config.getAuthorization_endpoint().isEmpty());
		assertFalse(config.getIntrospection_endpoint().isEmpty());
		assertFalse(config.getToken_endpoint().isEmpty());
	}

	@Test
	public void testClient() {
		MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
		
		MolosResult result = config.clear();
		
		assertTrue(result.isSuccess());
		
		List<ClientConfig> clients = config.getClients();
		
		assertTrue(clients != null && clients.isEmpty());
		
		result = config.client("arbitraryClientId").clientSecret("arbitraryClientSecret").scope("openid").add();
		
		assertTrue(result.isSuccess());
		
		clients = config.getClients();
		
		assertTrue(clients != null && clients.size() == 1);
		
		ClientConfig client = clients.get(0);
		
		assertEquals("arbitraryClientId", client.getClientId());
		assertEquals("arbitraryClientSecret", client.getClientSecret());
		assertEquals("openid", client.getScopes().iterator().next());
	}

	@Test
	public void testUser() {
		MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
		
		MolosResult result = config.clear();
		
		assertTrue(result.isSuccess());
		
		List<UserConfig> users = config.getUsers();
		
		assertTrue(users != null && users.isEmpty());
		
		result = config.user("theuser").password("arbitraryPassword").add();
		
		assertTrue(result.isSuccess());
		
		users = config.getUsers();

		assertTrue(users != null && users.size() == 1);
		
		UserConfig user = users.get(0);
		
		assertEquals("theuser", user.getUserName());
		assertEquals("arbitraryPassword", user.getPassword());
	}

	@Test
	public void testConfigDir() {
		MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
		
		MolosResult result = config.clear();
		
		assertTrue(result.isSuccess());
		
		result = config.configDir("configDir");
		
		assertTrue(result.isSuccess());

		String msg = result.getMessages().get(0);
		assertTrue(msg.startsWith("mock-setup_saveLocations result - "));
		
		File d = new File("configDir");
		File f = new File(d, "molos.realm");
		
		SaveLocations sl = result.getResultObject(SaveLocations.class);

		assertEquals(d.getAbsolutePath(), sl.getConfigDir());
		assertEquals(f.getAbsolutePath(), sl.getConfigFile());
		assertEquals(d.getAbsolutePath(), sl.getProtocolDir());
	}

	@Test
	public void testConfigFile() {
		MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());//, new JacksonJaxbJsonProvider());
		
		MolosResult result = config.clear();
		
		assertTrue(result.isSuccess());
		
		result = config.configFile("configFile");
		
		assertTrue(result.isSuccess());

		String msg = result.getMessages().get(0);
		assertTrue(msg.startsWith("mock-setup_saveLocations result - "));
		
		File d = new File("./.molos");
		File f = new File("configFile");
		
		SaveLocations sl = result.getResultObject(SaveLocations.class);

		assertEquals(d.getAbsolutePath(), sl.getConfigDir());
		assertEquals(f.getAbsolutePath(), sl.getConfigFile());
		assertEquals(d.getAbsolutePath(), sl.getProtocolDir());
	}

	@Test
	public void testProtocolDir() {
		MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
		
		MolosResult result = config.clear();
		
		assertTrue(result.isSuccess());
		
		result = config.protocolDir("protocolDir");
		
		assertTrue(result.isSuccess());

		String msg = result.getMessages().get(0);
		assertTrue(msg.startsWith("mock-setup_saveLocations result - "));
		
		File d = new File("./.molos");
		File f = new File(d, "molos.realm");
		File p = new File("protocolDir");
		
		SaveLocations sl = result.getResultObject(SaveLocations.class);

		assertEquals(d.getAbsolutePath(), sl.getConfigDir());
		assertEquals(f.getAbsolutePath(), sl.getConfigFile());
		assertEquals(p.getAbsolutePath(), sl.getProtocolDir());
	}

}
