package com.fwerres.molos;


import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fwerres.testsupport.JsonHelper;
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
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

public class MolosTestWIthKC {

	private static final String OIDC_CLIENT_ID = "myClient";

	private static final String OIDC_CLIENT_SECRET = "75ViJfL6vkDuNPx21SBZtcC09WKCAd7J";

	private static String OIDC_TOKEN_URL = "/protocol/openid-connect/token";
	
	private static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";

	private static String wsUrl = "http://localhost:8081/realms/myRealm";

	
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

		if (!tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.getErrorObject().getDescription());
		    fail(errorResponse.getErrorObject().getDescription());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		// Get the ID and access token, the server may also return a refresh token
		SignedJWT idToken = (SignedJWT) successResponse.getOIDCTokens().getIDToken();
//		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		assertTrue(idToken != null);
		
		
		// Verify id token
		
		Map<String, Object> tokenValues = JsonHelper.parseJson(idToken.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		
		Issuer iss = new Issuer((String) tokenValues.get("iss"));

		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(iss);
		URI jwkSetURI = opMetadata.getJWKSetURI();
		
		assertTrue(jwkSetURI != null && jwkSetURI.toString().startsWith(iss.getValue()));
		
		// ClientID also comes with the token, variable already exists
		
		IDTokenValidator validator = new IDTokenValidator(iss, clientID, JWSAlgorithm.RS256, jwkSetURI.toURL());

		IDTokenClaimsSet claimsSet = validator.validate(idToken, null);
		
		System.out.println("claimsSet: " + claimsSet);
		
		String tokenString = idToken.serialize();
		
		// Server side: verify token signature
		SignedJWT srvJwt = SignedJWT.parse(tokenString);
		tokenValues = JsonHelper.parseJson(srvJwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		Issuer srvIss = new Issuer((String) tokenValues.get("iss"));
		ClientID srvClientId = new ClientID((String) tokenValues.get("aud"));
		IDTokenValidator srvValidator = new IDTokenValidator(srvIss, srvClientId, JWSAlgorithm.RS256, jwkSetURI.toURL());

		claimsSet = srvValidator.validate(idToken, null);
		
		System.out.println("claimsSet: " + claimsSet);
		
	}
	
	
}
