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


import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.Scanner;

import org.apache.cxf.endpoint.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fwerres.molos.client.MolosConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.testsupport.JaxRSHelper;
import com.fwerres.testsupport.JsonHelper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;

import jakarta.json.Json;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;
import jakarta.json.stream.JsonParser.Event;

public class MolosTest {

	private static final String OIDC_CLIENT_ID = "OIDC_CLIENT_ID";

	private static final String OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRET_IS2SHORT_OIDC_CLIENT_SECRET";

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
			
			MolosConfig config = MolosConfig.getConfigurator(wsUrl);
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
	
//	@Test
//	public void testWhileThisRuns() {
//		System.out.println("Waiting for <Enter>");
//		try (Scanner scanner = new Scanner(System.in)) {
//			scanner.nextLine();
//		}
//		System.out.println("Terminating.");
//	}
	
	@Test
	public void testRequestVerifyTokenClientSecretBasic() throws Exception {

		// Client side: retrieve accessToken with ClientSecretBasic authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretBasic(new ClientID(OIDC_CLIENT_ID), new Secret(OIDC_CLIENT_SECRET)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretBasic authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretBasic(new ClientID(OIDC_CLIENT_ID), new Secret(OIDC_CLIENT_SECRET)), 
				// The token
				tokenValue));
	}
	
	@Test
	public void testRequestVerifyTokenClientSecretPost() throws Exception {
		// Client side: retrieve accessToken with ClientSecretPost authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretPost(new ClientID(OIDC_CLIENT_ID), new Secret(OIDC_CLIENT_SECRET)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretPost authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretPost(new ClientID(OIDC_CLIENT_ID), new Secret(OIDC_CLIENT_SECRET)), 
				// The token
				tokenValue));
	}

	@Test
	public void testRequestVerifyTokenClientSecretJWT() throws Exception {

		// Client side: retrieve accessToken with ClientSecretJWT authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretJWT authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET)), 
				// The token
				tokenValue));
	}
	
	
	@Test
	public void testRequestVerifyIDToken() throws Exception {
		
		// Client side: retrieve IDToken with ClientSecretJWT grant
		String tokenValue = retrieveIDToken(
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		SignedJWT idToken = SignedJWT.parse(tokenValue);
		assertTrue(idToken != null);
		
		// Server side: verify token signature
		assertTrue(validateIDTokenLocally(tokenValue));
	}

	private String retrieveAccessToken(ClientAuthentication clientAuth) throws Exception {
		return retrieveTokens(clientAuth).getAccessToken().getValue();
	}

	private String retrieveIDToken(ClientAuthentication clientAuth) throws Exception {
		return retrieveTokens(clientAuth).getIDToken().serialize();
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

	private boolean validateTokenWithIntrospection(ClientAuthentication clientAuth, String tokenString) throws Exception {
		
		URI introspectionEndpoint = new URI(wsUrl + OIDC_TOKEN_INTROSPECT_URL);

		// Token to validate
		AccessToken inspectedToken = new BearerAccessToken(tokenString);

		// Compose the introspection call
		HTTPRequest httpRequest = new TokenIntrospectionRequest(
		    introspectionEndpoint,
		    clientAuth,
		    inspectedToken)
		    .toHTTPRequest();

		// Make the introspection call
		HTTPResponse httpResponse = null;
		try {
			httpResponse = httpRequest.send();
		} catch (IOException e) {
			e.printStackTrace();
			fail("Got exception!");
		}
		String body = httpResponse.getBody();
		System.out.println(body);

		return responseContainsActiveTrue(body);
	}

	private boolean validateIDTokenLocally(String tokenString) throws Exception {
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
		
		return true;
	}

	
	private boolean responseContainsActiveTrue(String body) {
		JsonValue jsonValue = null;
		JsonParserFactory parserFactory = Json.createParserFactory(null);
		JsonParser parser = parserFactory.createParser(new StringReader(body));
		
		if (parser.hasNext()) {
			Event next = parser.next();
			jsonValue = parser.getObjectStream().filter(e->e.getKey().equals("active"))
        		.map(e->e.getValue()).findFirst().get();
		}
		return JsonValue.TRUE.equals(jsonValue);
	}
	
}
