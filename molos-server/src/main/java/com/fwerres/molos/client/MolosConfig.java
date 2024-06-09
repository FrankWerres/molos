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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.ClientContainer;
import com.fwerres.molos.config.SaveLocations;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;
import com.fwerres.molos.config.SaveBehaviour;
import com.fwerres.molos.config.UserConfig;
import com.fwerres.molos.config.UserContainer;

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
			return mc.client(cc);
		}
		
		public void remove() {
		}
	}

	public class UserConfigurator {
		private final MolosConfig mc;
		private final String userName;
		private String password = null;
		private Set<String> roles;
		
		private UserConfigurator(MolosConfig mc, String userName) {
			this.mc = mc;
			this.userName = userName;
		}
		
		public UserConfigurator password(String password) {
			this.password = password;
			return this;
		}
		
		public UserConfigurator role(String role) {
			if (roles == null) {
				roles = new HashSet<>();
			}
			if (role != null && !role.isEmpty()) {
				String[] splits = role.split(" ");
				for (String split : splits) {
					roles.add(split);
				}
			}
			return this;
		}

		public MolosResult add() {
			UserConfig uc = new UserConfig();
			uc.setUserName(userName);
			uc.setPassword(password);
			uc.setRoles(roles);
			return mc.addUser(uc);
		}
		
		public void remove() {
		}
	}
	
	
	private final String url;
	private final Object provider;
	
	private MolosConfig(String url, Object provider) {
		this.url = url;
		this.provider = provider;
	}

	public static MolosConfig getConfigurator(String url) {
		return new MolosConfig(url, null);
	}
	
	public static MolosConfig getConfigurator(String url, Object provider) {
		return new MolosConfig(url, provider);
	}

	public Client getRsClient() {
		Client client = ClientBuilder.newClient();
		if (provider != null) {
			client.register(provider);
		}
		return client;
	}
	
	public MolosResult configDir(String configDir) {
		Client client = getRsClient();
		
		SaveLocations configLocation = new SaveLocations();
		configLocation.setConfigDir(configDir);
		
		Response response = client.target(url + "/mock-setup/saveLocations").request().post(Entity.json(configLocation));
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	public MolosResult protocolDir(String protocolDir) {
		Client client = getRsClient();
		
		SaveLocations configLocation = new SaveLocations();
		configLocation.setProtocolDir(protocolDir);
		
		Response response = client.target(url + "/mock-setup/saveLocations").request().post(Entity.json(configLocation));
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	public MolosResult startProtocol() {
		return setProtocol(true);
	}
	
	public MolosResult stopProtocol() {
		return setProtocol(false);
	}
	
	private MolosResult setProtocol(boolean state) {
		Client client = getRsClient();
		
		SaveBehaviour saveBehaviour = new SaveBehaviour();
		saveBehaviour.setSaveActionProtocol(state);
		
		Response response = client.target(url + "/mock-setup/saveBehaviour").request().post(Entity.json(saveBehaviour));
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	
	public MolosResult configFile(String configFile) {
		Client client = getRsClient();
		
		SaveLocations configLocation = new SaveLocations();
		configLocation.setConfigFile(configFile);
		System.err.println("Calling /mock-setup/saveLocations");
		Response response = client.target(url + "/mock-setup/saveLocations").request().post(Entity.json(configLocation));
		System.err.println("returned /mock-setup/saveLocations");

		MolosResult result = response.readEntity(MolosResult.class);
		System.err.println("returned result");
		return result;
	}

	public MolosResult clear() {
		Client client = getRsClient();
		
		Response response = client.target(url + "/mock-setup/clear").request().post(null);
		
		MolosResult result = response.readEntity(MolosResult.class);
		return result;
	}
	
	public OpenIdConfig getOIDCConfig() {
		Client client = getRsClient();
		
		Response response = client.target(url + OpenIdConfig.PATH_CONFIG_ENDPOINT).request().get();
		
		OpenIdConfig result = response.readEntity(OpenIdConfig.class);
		
		return result;
	}
	
	public List<ClientConfig> getClients() {
		Client client = getRsClient();
		
		Response response = client.target(url + "/mock-setup/clients").request().get();
		
		ClientContainer clients = response.readEntity(ClientContainer.class);
		
		return clients.getClients();
	}
	
	public List<UserConfig> getUsers() {
		Client client = getRsClient();
		
		Response response = client.target(url + "/mock-setup/users").request().get();
		
		UserContainer users = response.readEntity(UserContainer.class);
		
		return users.getUsers();
	}

	public MolosResult client(ClientConfig clientConfig) {
		Client client = getRsClient();
		
		Response response = client.target(url + "/mock-setup/clients").request().post(Entity.json(clientConfig));
		
		MolosResult result = response.readEntity(MolosResult.class);
		
		return result;
	}
	
	public MolosResult addUser(UserConfig userConfig) {
		Client client = getRsClient();
		
		Response response = client.target(url + "/mock-setup/users").request().post(Entity.json(userConfig));
		
		MolosResult result = response.readEntity(MolosResult.class);
		
		return result;
	}
	
	public ClientConfigurator client(String clientId) {
		return new ClientConfigurator(this, clientId);
	}
	
	public UserConfigurator user(String userName) {
		return new UserConfigurator(this, userName);
	}
}
