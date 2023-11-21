package com.fwerres.molos.client;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;

public class MolosConfig {

	public class ClientConfigurator {
		private final MolosConfig mc;
		private final String clientId;
		private String clientSecret = null;
		private Set<String> scopes = null;
		
		private ClientConfigurator(MolosConfig mc, String clientId) {
			this.mc = mc;
			this.clientId = clientId;
		}
		
		public ClientConfigurator clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}
		
		public ClientConfigurator scope(String scope) {
			if (scopes == null) {
				scopes = new HashSet<>();
			}
			if (scope != null && !scope.isEmpty()) {
				String[] splits = scope.split(" ");
				for (String split : splits) {
					scopes.add(split);
				}
			}
			return this;
		}
		
		public MolosResult add() {
			ClientConfig cc = new ClientConfig();
			cc.setClientId(clientId);
			cc.setClientSecret(clientSecret);
			cc.setScopes(scopes);
			return mc.addClient(cc);
		}
		
		public void remove() {
		}
	}
	
	
	private final String url;
	
	private MolosConfig(String url) {
		this.url = url;
	}
	
	public static MolosConfig getConfigurator(String url) {
		return new MolosConfig(url);
	}
	
	public MolosResult clear() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + "/mock-setup/clear").request().post(null);
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	public OpenIdConfig getOIDCConfig() {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + OpenIdConfig.PATH_CONFIG_ENDPOINT).request().get();
		
		OpenIdConfig result = response.readEntity(OpenIdConfig.class);
		
		return result;
	}
	
	public List<ClientConfig> getClients() {
		return Collections.EMPTY_LIST;
	}

	private MolosResult addClient(ClientConfig clientConfig) {
		Client client = ClientBuilder.newClient();
		
		Response response = client.target(url + "/mock-setup/client").request().post(Entity.json(clientConfig));
		
		MolosResult result = response.readEntity(MolosResult.class);
		
		return result;
	}
	
	public ClientConfigurator client(String clientId) {
		return new ClientConfigurator(this, clientId);
	}
}
