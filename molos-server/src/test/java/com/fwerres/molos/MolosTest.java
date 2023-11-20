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
	
	private String retrieveAccessToken(ClientAuthentication clientAuth) throws Exception {
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

		// Get the ID and access token, the server may also return a refresh token
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
		
		return accessToken.getValue();
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
