package com.fwerres.molos.client;

import java.util.Collections;
import java.util.List;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;

import jakarta.json.bind.Jsonb;
import jakarta.json.bind.spi.JsonbProvider;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

public class MolosSetup {

	private final String url;
	private Jsonb jsonb = JsonbProvider.provider().create().build();
	
	private MolosSetup(String url) {
		this.url = url;
	}
	
	public static MolosSetup createTestSetup(String url) {
		return new MolosSetup(url);
	}
	
	public MolosResult clear() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + "/mock-setup/clear").request().post(null);
		
		String resultString = response.readEntity(String.class);
		
		JsonbProvider provider = JsonbProvider.provider();
		MolosResult result = provider.create().build().fromJson(resultString, MolosResult.class);
		
		return result;
	}
	
	public OpenIdConfig getOIDCConfig() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + OpenIdConfig.PATH_CONFIG_ENDPOINT ).request().get();
		
		String resultString = response.readEntity(String.class);
		
		JsonbProvider provider = JsonbProvider.provider();
		OpenIdConfig result = provider.create().build().fromJson(resultString, OpenIdConfig.class);
		
		return result;
	}
	
	public List<ClientConfig> getClients() {
		return Collections.EMPTY_LIST;
	}

	public MolosResult addClient(ClientConfig clientConfig) {
		Client client = ClientBuilder.newClient();
		
		String clientConfigString = jsonb.toJson(clientConfig);
		Response response = client.target(url + "/mock-setup/client").request().post(Entity.json(clientConfigString));
		
		String resultString = response.readEntity(String.class);
		
		MolosResult result = jsonb.fromJson(resultString, MolosResult.class);
		
		return result;
	}
}
