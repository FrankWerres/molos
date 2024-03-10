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
package com.fwerres.molos.sample.securedapp.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Properties;

import org.apache.cxf.endpoint.Server;
import org.glassfish.jersey.client.oauth2.OAuth2ClientSupport;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fwerres.molos.Molos;
import com.fwerres.molos.client.MolosConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.testsupport.JaxRSHelper;
import com.fwerres.testsupport.JsonHelper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Feature;
import jakarta.ws.rs.core.Response;

public class ConsumeSecuredAppIT {

	private String targetUrl = "http://localhost:9080/LibertyProject/backend/properties";

	private static final String OIDC_CLIENT_ID = "OIDC_CLIENT_ID";

	private static final String OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRETOIDC_CLIENT_SECRET";

	private static final String OIDC_TOKEN_URL = "/protocol/openid-connect/token";

	private static final String OIDC_JWKS_URI = "/protocol/openid-connect/certs";
	
	private static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";

	private static JaxRSHelper jaxrs = new JaxRSHelper();
	
	private static String wsUrl;

	private static Server theServer;
	
	@BeforeAll
	public static void setUp() throws Exception {
		if (theServer == null) {
			theServer = jaxrs.createLocalCXFServer("/oidcMock", Molos.class, new JacksonJsonProvider(), new Object[] { });
			wsUrl = jaxrs.getActualUrl(theServer);
			System.out.println("Started server on " + wsUrl);
			
			MolosConfig config = MolosConfig.getConfigurator(wsUrl, new JacksonJsonProvider());
			MolosResult result = config.client(OIDC_CLIENT_ID).clientSecret(OIDC_CLIENT_SECRET).scope("openid").add();
			for (String msg : result.getMessages()) {
				System.err.println(msg);
			}
			assertTrue(result.isSuccess());
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
	public void testRetrieveProperties() {
		Client client = ClientBuilder.newClient();
		Response response = client
				// Needed because cxf takes over when present ...
				.register(new JacksonJsonProvider())
				.target(targetUrl + "/unsecure").request().get(); 
		
		assertEquals(200, response.getStatus(), "Unexpected HTTP status");
		
		Properties properties = response.readEntity(Properties.class);
		
		response.close();
		client.close();
		
		assertNotNull(properties);
		
		assertTrue(properties.containsKey("java.specification.version"));
		
		System.out.println("Server running Java " + properties.getProperty("java.specification.version"));
	}

	@Test
	public void testIllegitimateAccess() throws Exception {
		Client client = ClientBuilder.newClient();
		Response response = client
				// Needed because cxf takes over when present ...
				.register(new JacksonJsonProvider())
				.target(targetUrl + "/secured").request().get(); 
		
		assertEquals(401, response.getStatus(), "Unexpected HTTP status");
		
		response.close();
		client.close();
	}

	@Test
	public void testRetrieveSecuredProperties() throws Exception {
		// retrieve IDToken with ClientSecretJWT grant
		String tokenValue = retrieveIDToken(
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET)));
		
		System.out.println("Got token: " + tokenValue);
		
		validateIDTokenLocally(tokenValue);

		Client client = ClientBuilder.newClient();
		
		Feature feature = OAuth2ClientSupport.feature(tokenValue);
		client.register(feature);
		
		Response response = client
				// Needed because cxf takes over when present ...
				.register(new JacksonJsonProvider())
				.target(targetUrl + "/secured").request().get(); 
		
		assertEquals(200, response.getStatus(), "Unexpected HTTP status");
		
		Properties properties = response.readEntity(Properties.class);
		
		response.close();
		client.close();
		
		assertNotNull(properties);
		
		assertTrue(properties.containsKey("java.specification.version"));
		
		System.out.println("Securely transferred: server running Java " + properties.getProperty("java.specification.version"));
	}
	

	private String retrieveIDToken(ClientAuthentication clientAuth) throws Exception {
		return retrieveTokens(clientAuth).getAccessToken().getValue();
	}

	private OIDCTokens retrieveTokens(ClientAuthentication clientAuth) throws Exception {
		AuthorizationGrant clientGrant = new ClientCredentialsGrant();
		
		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// The request scope for the token
		Scope scope = new Scope("openid");

		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.getErrorObject().getDescription());
		    fail(errorResponse.getErrorObject().getDescription());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();
		
		return successResponse.getOIDCTokens();
	}

	private void validateIDTokenLocally(String tokenString) throws Exception {
		SignedJWT jwt = SignedJWT.parse(tokenString);
		Map<String, Object> tokenValues = JsonHelper.parseJson(jwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		Issuer iss = new Issuer((String) tokenValues.get("iss"));
		ClientID clientId = new ClientID((String) tokenValues.get("aud"));
		IDTokenValidator srvValidator = new IDTokenValidator(iss, clientId, JWSAlgorithm.RS256, new URL(wsUrl + OIDC_JWKS_URI));

		IDTokenClaimsSet claimsSet = srvValidator.validate(jwt, null);
		
		System.out.println("claimsSet: " + claimsSet);
	}

}
