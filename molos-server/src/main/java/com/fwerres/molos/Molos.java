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
package com.fwerres.molos;



import java.io.File;
import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;
import com.fwerres.molos.data.Token;
import com.fwerres.molos.data.TokenIntrospection;
import com.fwerres.molos.setup.KeyGenerator;
import com.fwerres.molos.setup.State;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonValue.ValueType;
import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbBuilder;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriInfo;


public class Molos {
	
	private static final String SIGNED_JWT_WITH_CLIENT_SECRET = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";

	private final static Map<String, JWK> keys = new HashMap<>();
	private final static Map<String, JWK> pubKeys = new HashMap<>();
	private static JWK signKey;
	
	@Context
	private UriInfo uriInfo;
	
//	@Inject 
	private final static State state = new State();
	
	public Molos() {
		checkConfiguration();
	}
	
	public void checkConfiguration() { 
		synchronized(Molos.class) {
			System.err.println("Check environment ...");
			File confDir = ensureConfigDir();
			ensureCertificates();
		}
	}
	
	private void ensureCertificates() {
		if (keys.isEmpty()) {
			String kid1 = "enc:" + UUID.randomUUID();
			JWK jwk = KeyGenerator.generateRSAKey(2048, KeyUse.ENCRYPTION, Algorithm.parse("RSA-OAEP"), kid1); 
			keys.put(kid1, jwk);
			pubKeys.put(kid1, jwk.toPublicJWK());
			System.out.println(kid1 + " - " + jwk.toPublicJWK().toJSONString());

			String kid2 = "sig:" + UUID.randomUUID();
			jwk = KeyGenerator.generateRSAKey(2048, KeyUse.SIGNATURE, Algorithm.parse("RS256"), kid2);
			signKey = jwk;
			keys.put(kid2, jwk);
			pubKeys.put(kid2, jwk.toPublicJWK());
			System.out.println(kid2 + " - " + jwk.toPublicJWK().toJSONString());
		}
	}

	private File ensureConfigDir() {
		String molosDir = System.getenv("MOLOS_DIR");
		if (molosDir == null || molosDir.isEmpty()) {
			molosDir = "./.molos";
		}
		File confDir = new File(molosDir);
		if (!confDir.exists()) {
			System.out.println("confDir " + confDir.getAbsolutePath() + " doesn't exist");
			confDir.mkdirs();
			System.out.println("confDir " + confDir.getAbsolutePath() + " created");
		}
		return confDir;
	}

	@GET
	@Path("/.well-known/openid-configuration")
    @Produces({ "application/json" })
    public Response openIdConfiguration() {
        return Response.ok().entity(new OpenIdConfig(uriInfo.getBaseUri().toString())).build();
    }
	
	@GET
	@Path("/protocol/openid-connect/auth")
	@Produces({ "application/html" })
	public Response getAuthorization() {
		return Response.ok().entity("magic value").build();
	}
	
	@GET
	@Path("/protocol/openid-connect/certs")
	@Produces({ "application/json" })
	public Response certificates() {
		String certs = "{\"keys\":[";
		String separator = "";
		for (JWK jwk : pubKeys.values()) {
			certs = certs.concat(separator).concat(jwk.toJSONString());
			separator = ",";
		}
		certs = certs.concat("]}");
		return Response.ok().entity(certs).build();
	}
	
	@POST
	@Path("/protocol/openid-connect/token")
    @Produces({ "application/json" })
	public Response getToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);
		
		System.err.println("Request: " + values);
		
		if (values.containsKey(CLIENT_ASSERTION_TYPE) && values.get(CLIENT_ASSERTION_TYPE).equals(SIGNED_JWT_WITH_CLIENT_SECRET)) {
			String clientId = "";
			ClientConfig client = null;
			boolean verificationSuccess = false;
			try {
				SignedJWT jwt = SignedJWT.parse(values.get("client_assertion"));
				String assertion = jwt.getPayload().toString();
//				System.err.println("Assertion: " + assertion);
				Map<String, Object> tokenMap = parseJson(assertion);
				clientId = (String) tokenMap.get("iss");
				
				client = state.getClient(clientId);
				if (client != null) {
					JWSVerifier verifier = new MACVerifier(client.getClientSecret());
					verificationSuccess = jwt.verify(verifier);
				}
			} catch (JOSEException | ParseException e) {
				e.printStackTrace();
			}
			
			if (verificationSuccess) {
				Token token = new Token(uriInfo.getBaseUri(), client, (RSAKey) signKey);
				state.registerToken(clientId, token);
				return Response.ok().entity(token).build();
			} else {
				return Response.status(Status.FORBIDDEN).entity("Client authentication with client secret signed JWT failed: Signature on JWT token by client secret  failed validation").build();
			}
			
		}
		
		String clientId = values.get("client_id");
		String clientSecret = values.get("client_secret");
		
		ClientConfig clientConfig = state.getClient(clientId);
		if (clientConfig != null && clientConfig.getClientSecret().equals(clientSecret) && clientConfig.getScopes().contains(values.get("scope"))) {
			Token token = new Token(uriInfo.getBaseUri(), clientConfig, (RSAKey) signKey);
			state.registerToken(clientId, token);
			return Response.ok().entity(token).build();
		} else {
			return Response.serverError().build();
		}
		
//		{
//			"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxZmU3NzNlZS0zOWUzLTQ0MzItYjcyNi0xMWQxMWJiMDJkYzYifQ.eyJleHAiOjE2OTk4NjU0NDEsImlhdCI6MTY5OTg2NTE0MSwianRpIjoiNzdkNmNlZjUtYWU3My00ZmYwLTk5YTEtN2UxMzY2MDJkYTMxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3JlYWxtcy9iaWdfZGV2IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImRhM2JiMjQyLTE2MzYtNDkyMi05NzM4LWIxMDRmNTQyNDM5ZiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImJpZ0JhY2tlbmRQRCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3BkLmJpZy5jb20iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWJpZ19kZXYiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiY2xpZW50SG9zdCI6IjE3Mi4xNy4wLjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1iaWdiYWNrZW5kcGQiLCJjbGllbnRBZGRyZXNzIjoiMTcyLjE3LjAuMSIsImNsaWVudF9pZCI6ImJpZ0JhY2tlbmRQRCJ9.OLd-u7kGI51fo89YJ4ocUagpWsLSc4D0_kymohVlTAY",
//			"expires_in":300,
//			"refresh_expires_in":0,
//			"token_type":"Bearer",
//			"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0ZjZlNWhwVEVKN3lGT2dYSUZBNU82UGEweDMxSnB6c1NfUThRSHk1Rjg4In0.eyJleHAiOjE2OTk4NjU0NDEsImlhdCI6MTY5OTg2NTE0MSwiYXV0aF90aW1lIjowLCJqdGkiOiJkYTIxMDk3MC1mZThlLTRkOWUtYjVkNi0zMzIyYThhNDI4N2MiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvcmVhbG1zL2JpZ19kZXYiLCJhdWQiOiJiaWdCYWNrZW5kUEQiLCJzdWIiOiJkYTNiYjI0Mi0xNjM2LTQ5MjItOTczOC1iMTA0ZjU0MjQzOWYiLCJ0eXAiOiJJRCIsImF6cCI6ImJpZ0JhY2tlbmRQRCIsImF0X2hhc2giOiJmLWp2ZUpOeXZwUDhPakE2R2xSLXZBIiwiYWNyIjoiMSIsImNsaWVudEhvc3QiOiIxNzIuMTcuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtYmlnYmFja2VuZHBkIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4xNy4wLjEiLCJjbGllbnRfaWQiOiJiaWdCYWNrZW5kUEQifQ.NVPCaEKQDgIE6Cj2fNkL9AL4k61zKAsosKo25EbLTs5EIDkmwSdjKGdmSIVkoiyULafHzpciMjMAjZY9XICujF_L6J0ksi5xxWIVNRIWxkTToLKCOqXKBxOAxfEbpjq59_IcSbO5ha5aBb-F9rloZOOUen3T_aro7R9YyZuvlweuFbDh1R4fL2sKmeQBnHmkwowHaVs2HQ_5DabYbSkHRyZkXxRPS9Z-Afpbq_370tf6yTIGSgHgMLF3N2JJFK2FWMEpI_lwEcDLJwsk1hDP6VJliGWdxX8lMDLvwh-L6UoQqJ5-sOE-4xeQNRDQ7bHS7CHP9TvOFhDhZcIWEUn5OA",
//			"not-before-policy":0,
//			"scope":"openid profile email"
//		}
		
    }

	private Map<String, Object> parseJson(String json) {
		JsonObject jsonValue = null;
		JsonParserFactory parserFactory = Json.createParserFactory(null);
		JsonParser parser = parserFactory.createParser(new StringReader(json));
		
		if (parser.hasNext()) {
			parser.next();
			jsonValue = parser.getObject();
		}
		Map<String, Object> result = new HashMap<>();
		for (Entry<String, JsonValue> entry : jsonValue.entrySet()) {
			if (ValueType.STRING == entry.getValue().getValueType()) {
				String stringValue = entry.getValue().toString();
				result.put(entry.getKey(), stringValue.toString().substring(1, stringValue.length() - 1));
			} else {
				result.put(entry.getKey(), entry.getValue().toString());
			}
		}
		return result;
	}

	private Map<String, String> parseRequest(String request, HttpHeaders headers, Map<String, String> values) {
		String[] requestParts = request.split("&");
		for (String requestPart : requestParts) {
			String part = URLDecoder.decode(requestPart, Charset.defaultCharset());
			String[] split = part.split("=");
			values.put(split[0],  split[1]);
		}
		
		List<String> authHeaders = headers.getRequestHeader(HttpHeaders.AUTHORIZATION);
		if (authHeaders != null && !authHeaders.isEmpty()) {
			String authorization64 = authHeaders.get(0).substring("Basic ".length());
			String authorization = new String(Base64.getDecoder().decode(authorization64));
			values.put("_authorization", authorization);
			
			String clientId = authorization.substring(0, authorization.indexOf(":"));
			String clientSecret = authorization.substring(authorization.indexOf(":") + 1);
			
			values.put("client_id", clientId);
			values.put("client_secret", clientSecret);
		}
		
		return values;
	}
	
	@POST
	@Path("/protocol/openid-connect/token/introspect")
    @Produces({ "application/json" })
	public Response introspectToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);
		
		String clientId = "";
		boolean verificationSuccess = false;
		if (values.containsKey(CLIENT_ASSERTION_TYPE) && values.get(CLIENT_ASSERTION_TYPE).equals(SIGNED_JWT_WITH_CLIENT_SECRET)) {
			try {
				SignedJWT jwt = SignedJWT.parse(values.get("client_assertion"));
				String assertion = jwt.getPayload().toString();
//				System.err.println("Assertion: " + assertion);
				Map<String, Object> tokenMap = parseJson(assertion);
				clientId = (String) tokenMap.get("iss");
				
				ClientConfig client = state.getClient(clientId);
				if (client != null) {
					JWSVerifier verifier = new MACVerifier(client.getClientSecret());
					verificationSuccess = jwt.verify(verifier);
				}
			} catch (JOSEException | ParseException e) {
				e.printStackTrace();
			}
		} else {
			clientId = values.get("client_id");
			verificationSuccess = true;
		}

		if (verificationSuccess) {
			String token = values.get("token");
			
			TokenIntrospection tokenIntrospection = new TokenIntrospection();
	
			tokenIntrospection.setActive(state.isRegisteredToken(clientId, token));
				
			return Response.ok().entity(tokenIntrospection).build();
		} else {
			return Response.status(Status.FORBIDDEN).entity("Client authentication with client secret signed JWT failed: Signature on JWT token by client secret  failed validation").build();
		}
	}

	// mock configuration stuff ...
	
	@POST
	@Path("/mock-setup/clear")
	@Produces({ "application/json" })
	public Response clear(String request, @Context HttpHeaders headers) {
		MolosResult result = new MolosResult();
		result.setSuccess(true);
		
		return Response.ok().entity(result).build();
	}
	
	@POST
	@Path("/mock-setup/client")
	@Consumes({ "application/json" })
	@Produces({ "application/json" })
	public Response mockSetupClient(ClientConfig cc) {
		MolosResult result = new MolosResult();

		System.out.println("Registering #" + cc.getClientId());
		
		result.setSuccess(state.registerClient(cc, result.getMessages()));
		
		return Response.ok().entity(result).build();
	}
}
