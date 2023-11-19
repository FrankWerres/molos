package com.fwerres.molos;


import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import org.apache.cxf.endpoint.Server;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import jakarta.json.Json;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;
import jakarta.json.stream.JsonParser.Event;

public class MolosTest {

	private static final String OIDC_CLIENT_ID = "OIDC_CLIENT_ID";

	private static final String OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRETOIDC_CLIENT_SECRET";

	private static String OIDC_TOKEN_URL = "/protocol/openid-connect/token";
	
	private static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";

	private static JaxRSHelper jaxrs = new JaxRSHelper();
	
	private static String wsUrl;

	private static Server theServer;
	
	@BeforeAll
	public static void setUp() throws Exception {
		if (theServer == null) {
			theServer = jaxrs.createLocalCXFServer("/oidcMock", Molos.class, new Object[] { new JacksonJsonProvider() }, new Object[] { });
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
	public void testRequestVerifyTokenClientSecretBasicGrant() throws Exception {
		// Client side: retrieve accessToken with ClientSecretBasic grant
		
		ClientID clientID = new ClientID(OIDC_CLIENT_ID);

		AuthorizationGrant clientGrant = new ClientCredentialsGrant();

		// The credentials to authenticate the client at the token endpoint
		Secret clientSecret = new Secret(OIDC_CLIENT_SECRET);
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		// The request scope for the token
		Scope scope = new Scope("openid");

		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.toString());
		    fail(errorResponse.toString());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		// Get the ID and access token, the server may also return a refresh token
		JWT idToken = successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		String tokenValue = accessToken.getValue();
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		
		// Server side: have server verify accessToken for ClientSecretBasic grant
		
		System.out.println("Got token: " + tokenValue);
		
		URI introspectionEndpoint = null;
		try {
			introspectionEndpoint = new URI(wsUrl + OIDC_TOKEN_INTROSPECT_URL);
		} catch (URISyntaxException e) {
			//NOSONAR this URL is not malformed
		}

		// Token to validate
		AccessToken inspectedToken = new BearerAccessToken(tokenValue);

		// Compose the introspection call
		HTTPRequest httpRequest = new TokenIntrospectionRequest(
		    introspectionEndpoint,
		    new ClientSecretBasic(clientID, clientSecret),
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

		assertTrue(responseContainsActiveTrue(body));
	}
	
	@Test
	public void testRequestVerifyTokenClientSecretPostGrant() throws Exception {
		// Client side: retrieve accessToken with ClientSecretPost grant
		
		ClientID clientID = new ClientID(OIDC_CLIENT_ID);

		AuthorizationGrant clientGrant = new ClientCredentialsGrant();

		// The credentials to authenticate the client at the token endpoint
		Secret clientSecret = new Secret(OIDC_CLIENT_SECRET);
		ClientAuthentication clientAuth = new ClientSecretPost(clientID, clientSecret);

		// The request scope for the token
		Scope scope = new Scope("openid");

		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.toString());
		    fail(errorResponse.toString());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		// Get the ID and access token, the server may also return a refresh token
		SignedJWT idToken = (SignedJWT) successResponse.getOIDCTokens().getIDToken();
		System.out.println(idToken.getParsedString());
		Map<String, Object> tokenValues = JsonHelper.parseJson((idToken).getPayload().toString(), false);
		for (String tokenValue : tokenValues.keySet()) {
			System.out.println("IDToken: " + tokenValue + " - " + tokenValues.get(tokenValue));
		}
		JWSVerifier verifier = new MACVerifier(OIDC_CLIENT_SECRET);
		assertTrue(idToken.verify(verifier));
		
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		String tokenValue = accessToken.getValue();
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		
		// Server side: have server verify accessToken for ClientSecretBasic grant
		
		System.out.println("Got token: " + tokenValue);
		
		URI introspectionEndpoint = null;
		try {
			introspectionEndpoint = new URI(wsUrl + OIDC_TOKEN_INTROSPECT_URL);
		} catch (URISyntaxException e) {
			//NOSONAR this URL is not malformed
		}

		// Token to validate
		AccessToken inspectedToken = new BearerAccessToken(tokenValue);

		// Compose the introspection call
		HTTPRequest httpRequest = new TokenIntrospectionRequest(
		    introspectionEndpoint,
		    new ClientSecretPost(clientID, clientSecret),
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

		assertTrue(responseContainsActiveTrue(body));
	}

	@Test
	public void testRequestVerifyTokenClientSecretJWT() throws Exception {
		// Client side: retrieve accessToken with ClientSecretBasic grant
		
		ClientID clientID = new ClientID(OIDC_CLIENT_ID);

		AuthorizationGrant clientGrant = new ClientCredentialsGrant();
		
		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// The credentials to authenticate the client at the token endpoint
		Secret clientSecret = new Secret(OIDC_CLIENT_SECRET);
		ClientAuthentication clientAuth = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, clientSecret);

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

		// Get the ID and access token, the server may also return a refresh token
		JWT idToken = successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		String tokenValue = accessToken.getValue();
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
		
		// Server side: have server verify accessToken for ClientSecretBasic grant
		
		System.out.println("Got token: " + tokenValue);
		
		URI introspectionEndpoint = null;
		try {
			introspectionEndpoint = new URI(wsUrl + OIDC_TOKEN_INTROSPECT_URL);
		} catch (URISyntaxException e) {
			//NOSONAR this URL is not malformed
		}

		// Token to validate
		AccessToken inspectedToken = new BearerAccessToken(tokenValue);

		// Compose the introspection call
		HTTPRequest httpRequest = new TokenIntrospectionRequest(
		    introspectionEndpoint,
		    new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, clientSecret),
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

		assertTrue(responseContainsActiveTrue(body));
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
