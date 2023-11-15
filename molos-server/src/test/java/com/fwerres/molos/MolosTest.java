package com.fwerres.molos;


import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashSet;

import org.apache.cxf.endpoint.Server;
import org.eclipse.yasson.JsonBindingProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fwerres.molos.client.MolosSetup;
import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.testsupport.JaxRSHelper;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

public class MolosTest {

	private static final String OIDC_CLIENT_ID = "OIDC_CLIENT_ID";

	private static final String OIDC_CLIENT_SECRET = "OIDC_CLIENT_SECRET";

	private static String OIDC_TOKEN_URL = "/protocol/openid-connect/token";
	
	private static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";

	private JaxRSHelper jaxrs = new JaxRSHelper();
	
	private static String wsUrl;

	private static Server theServer;
	
	@BeforeEach
	public void setUp() throws Exception {
		if (theServer == null) {
			theServer = jaxrs.createLocalCXFServer("/oidcMock", Molos.class, new Object[] { new JsonBindingProvider() }, new Object[] { });
			wsUrl = jaxrs.getActualUrl(theServer);
			System.out.println("Started server on " + wsUrl);
			
			MolosSetup setup = MolosSetup.createTestSetup(wsUrl);
			ClientConfig cc = new ClientConfig();
			cc.setClientId(OIDC_CLIENT_ID);
			cc.setClientSecret(OIDC_CLIENT_SECRET);
			cc.setScopes(new HashSet<>(Arrays.asList("openid")));
			MolosResult result = setup.addClient(cc);
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
	public void requestVerifyToken() throws Exception {
		ClientID clientID = new ClientID(OIDC_CLIENT_ID);

		AuthorizationGrant passwordGrant = new ClientCredentialsGrant();

		// The credentials to authenticate the client at the token endpoint
		Secret clientSecret = new Secret(OIDC_CLIENT_SECRET);
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		// The request scope for the token
		Scope scope = new Scope("openid");

		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, passwordGrant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		if (! tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.toString());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		// Get the ID and access token, the server may also return a refresh token
		JWT idToken = successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		String tokenValue = accessToken.getValue();
		
		assertTrue(tokenValue != null && !tokenValue.isBlank());
		
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
		System.out.println(httpResponse.getBody());
		
		// TODO Replace with JsonB solution
//		ObjectMapper mapper = new ObjectMapper();
//		JsonNode active = null;
//	    try {
//	    	active = mapper.readTree(httpResponse.getBody()).get("active");
//		} catch (JsonProcessingException e) {
//			e.printStackTrace();
//			fail("Got exception!");
//		}
//	    if (active != null && active.asBoolean()) {
//	    	System.err.println("JWTTokenNeededFilter: Token successfully validated!");
//	    } else {
//	    	System.err.println("JWTTokenNeededFilter: Token invalid!");
//			fail("JWTTokenNeededFilter: Token invalid!");
//	    }


	}
	
}
