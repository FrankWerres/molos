package com.fwerres.molos.setup;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.data.Token;

import jakarta.json.bind.Jsonb;
import jakarta.json.bind.spi.JsonbProvider;

//@ApplicationScoped
public class State {
	
//	private Jsonb jsonb = JsonbProvider.provider().create().build();

	private final Map<String, ClientConfig> clients = new HashMap<>();
	private final Map<String, Set<String>> tokens = new HashMap<>();

	public synchronized boolean registerClient(ClientConfig cc, List<String> msgs) {
		boolean failed = false;
		
		if (cc.getClientId() == null || cc.getClientId().isEmpty()) {
			msgs.add("InvalidArgument: no clientId!");
			failed = true;
		}
		if (cc.getClientSecret() == null || cc.getClientSecret().isEmpty()) {
			msgs.add("InvalidArgument: no clientSecret!");
			failed = true;
		}
		if (cc.getScopes() == null || cc.getScopes().isEmpty()) {
			msgs.add("InvalidArgument: no scope!");
			failed = true;
		}
		if (failed) {
			return false;
		}
		if (clients.containsKey(cc.getClientId())) {
			msgs.add("Replacing content for clientId '" + cc.getClientId() + "'");
		}
		clients.put(cc.getClientId(), cc);
		
		return true;
	}

	public synchronized ClientConfig getClient(String clientId) {
		return clients.get(clientId);
	}
	
	public synchronized void registerToken(String clientId, Token token) {
		if (!tokens.containsKey(clientId)) {
			tokens.put(clientId, new HashSet<>());
		}
		tokens.get(clientId).add(token.getAccess_token());
	}
	
	public synchronized boolean isRegisteredToken(String clientId, String token) {
		return tokens.containsKey(clientId) && tokens.get(clientId).contains(token);
	}
}
