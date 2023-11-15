package com.fwerres.molos.client;

import java.util.Collections;
import java.util.List;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

public class MolosSetup {

	private final String url;
	
	private MolosSetup(String url) {
		this.url = url;
	}
	
	public static MolosSetup createTestSetup(String url) {
		return new MolosSetup(url);
	}
	
	public MolosResult clear() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + "/mock-setup/clear").request().post(null);
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	public OpenIdConfig getOIDCConfig() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + OpenIdConfig.PATH_CONFIG_ENDPOINT ).request().get();
		
		OpenIdConfig result = response.readEntity(OpenIdConfig.class);
		
		return result;
	}
	
	public List<ClientConfig> getClients() {
		return Collections.EMPTY_LIST;
	}

	public MolosResult addClient(ClientConfig clientConfig) {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + "/mock-setup/client").request().post(Entity.json(clientConfig));
		
		MolosResult result = response.readEntity(MolosResult.class);
		
		return result;
	}
}
