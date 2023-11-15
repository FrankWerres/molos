package com.fwerres.molos.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.HashSet;
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
import com.fwerres.testsupport.JaxRSHelper;

public class MolosSetupTest {
	private static JaxRSHelper jaxrs = new JaxRSHelper();
	
	private static String wsUrl;

	private static Server theServer;
	
	@BeforeAll
	public static void setUp() throws Exception {
		if (theServer == null) {
			theServer = jaxrs.createLocalCXFServer("/oidcMock", Molos.class, new Object[] { new JacksonJsonProvider() } , new Object[] { });
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
		MolosSetup setup = MolosSetup.createTestSetup(wsUrl);
		
		OpenIdConfig config = setup.getOIDCConfig();
		
		assertTrue(config != null);
		assertFalse(config.getIssuer().isEmpty());
		assertFalse(config.getIntrospection_endpoint().isEmpty());
		assertFalse(config.getToken_endpoint().isEmpty());
	}

	@Test
	public void test() {
		MolosSetup setup = MolosSetup.createTestSetup(wsUrl);
		
		MolosResult result = setup.clear();
		
		assertTrue(result.isSuccess());
		
		List<ClientConfig> clients = setup.getClients();
		
		assertTrue(clients != null && clients.isEmpty());
		
		ClientConfig client = new ClientConfig();
		client.setClientId("arbitraryClientId");
		client.setClientSecret("arbitraryClientSecret");
		client.setScopes(new HashSet<>(Arrays.asList("openid")));
		
		result = setup.addClient(client);
		
		assertTrue(result.isSuccess());
	}

}
