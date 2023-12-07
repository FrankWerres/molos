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

import java.net.URI;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * This class tests molos handling of OAuth2-like client requests for tokens. 
 */
public class OAuthClientTest extends MolosTestbase {
	@Test
	public void testRequestVerifyTokenClientSecretBasic() throws Exception {

		// Client side: retrieve accessToken with ClientSecretBasic authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretBasic(new ClientID(OIDC_CLIENT_ID_4CLIENT), new Secret(OIDC_CLIENT_SECRET_4CLIENT)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretBasic authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretBasic(new ClientID(OIDC_CLIENT_ID_4CLIENT), new Secret(OIDC_CLIENT_SECRET_4CLIENT)), 
				// The token
				tokenValue));
	}
	
	@Test
	public void testRequestVerifyTokenClientSecretPost() throws Exception {
		// Client side: retrieve accessToken with ClientSecretPost authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretPost(new ClientID(OIDC_CLIENT_ID_4CLIENT), new Secret(OIDC_CLIENT_SECRET_4CLIENT)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretPost authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretPost(new ClientID(OIDC_CLIENT_ID_4CLIENT), new Secret(OIDC_CLIENT_SECRET_4CLIENT)), 
				// The token
				tokenValue));
	}

	@Test
	public void testRequestVerifyTokenClientSecretJWT() throws Exception {

		// Client side: retrieve accessToken with ClientSecretJWT authorization
		String tokenValue = retrieveAccessToken(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID_4CLIENT), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET_4CLIENT)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		// Server side: have server verify accessToken for ClientSecretJWT authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID_4CLIENT), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET_4CLIENT)), 
				// The token
				tokenValue));
		
		// Server side: have server verify accessToken for ClientSecretJWT authorization
		assertTrue(validateTokenWithIntrospection(
				// The credentials to authenticate the client at the token endpoint
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID_4SERVER), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET_4SERVER)), 
				// The token
				tokenValue));
	}
	
	
	@Test
	public void testRequestVerifyIDToken() throws Exception {
		
		// Client side: retrieve IDToken with ClientSecretJWT grant
		String tokenValue = retrieveIDToken(
				new ClientSecretJWT(new ClientID(OIDC_CLIENT_ID_4CLIENT), new URI(wsUrl + OIDC_TOKEN_URL), JWSAlgorithm.HS256, new Secret(OIDC_CLIENT_SECRET_4CLIENT)));
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		System.out.println("Got token: " + tokenValue);
		
		SignedJWT idToken = SignedJWT.parse(tokenValue);
		assertTrue(idToken != null);
		
		// Server side: verify token signature
		assertTrue(validateIDTokenLocally(tokenValue));
	}

}
