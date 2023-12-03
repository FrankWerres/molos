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

public class MolosTestbase {

	protected static final String OIDC_CLIENT_ID = "OIDC_CLIENT_ID";

	protected static final String OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRET_IS2SHORT_OIDC_CLIENT_SECRET";

	protected static final String OIDC_TOKEN_URL = "/protocol/openid-connect/token";

	protected static final String OIDC_JWKS_URI = "/protocol/openid-connect/certs";
	
	protected static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";
	
	protected static final String OIDC_AUTHORIZATION_URL = "/protocol/openid-connect/auth";

	protected static JaxRSHelper jaxrs = new JaxRSHelper();
	
	protected static String wsUrl;

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
	

	protected boolean validateTokenWithIntrospection(ClientAuthentication clientAuth, String tokenString) throws Exception {
		
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

	protected boolean validateIDTokenLocally(String tokenString) throws Exception {
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

	
	protected boolean responseContainsActiveTrue(String body) {
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
