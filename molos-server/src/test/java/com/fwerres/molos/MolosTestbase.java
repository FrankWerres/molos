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

public abstract class MolosTestbase extends IPTestbase {

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
			
			// FIXME Scope 'openid' not necessary with real KeyCloak
			MolosResult result = config.client(OIDC_CLIENT_ID_4CLIENT).clientSecret(OIDC_CLIENT_SECRET_4CLIENT).scope("openid").add();
			for (String msg : result.getMessages()) {
				System.err.println(msg);
			}
			assertTrue(result.isSuccess());

			result = config.client(OIDC_CLIENT_ID_4SERVER).clientSecret(OIDC_CLIENT_SECRET_4SERVER).scope("openid").add();
			for (String msg : result.getMessages()) {
				System.err.println(msg);
			}
			assertTrue(result.isSuccess());

			result = config.user("theuser").password("secretPassword").add();
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
	
	@Override
	protected String getBaseUrl() {
		return wsUrl;
	}

}
