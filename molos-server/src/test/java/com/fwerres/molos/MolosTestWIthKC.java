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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.spi.HttpServerProvider;

import java.io.IOException;
import java.io.OutputStream;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Version;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.http.ClientConfig;

import com.fwerres.testsupport.JsonHelper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.TokenTypeURI;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import jakarta.json.JsonArray;
import jakarta.ws.rs.core.HttpHeaders;
import net.minidev.json.JSONArray;

public class MolosTestWIthKC {

	private static final String OIDC_CLIENT_ID = "myClient";

	private static final String OIDC_CLIENT_SECRET = "75ViJfL6vkDuNPx21SBZtcC09WKCAd7J";

	private static String OIDC_TOKEN_URL = "/protocol/openid-connect/token";
	
	private static final String OIDC_TOKEN_INTROSPECT_URL = "/protocol/openid-connect/token/introspect";

	private static String wsUrl = "http://localhost:8081/realms/myRealm";

	private static final String OIDC_AUTHORIZATION_URL = "/protocol/openid-connect/auth";
	
	@Test
	@Disabled
	public void testRequestVerifyIDToken() throws Exception {
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
		
		
		// Required for jwt security in backend service
		
		String keyID = idToken.getHeader().getKeyID();
		assertTrue(keyID != null && !keyID.isEmpty());
		
		String upn = (String) claimsSet.getClaim("upn");
		assertTrue(upn != null && !upn.isEmpty(), "Claim 'upn' missing or empty!");
		
		JSONArray groups = (JSONArray) claimsSet.getClaim("groups");
		assertTrue(groups != null && !groups.isEmpty(), "Claim 'groups' missing or empty!");
	}
	
	
	@Test
	@Disabled
	public void testRequestVerifyAccessToken() throws Exception {
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
//		SignedJWT idToken = (SignedJWT) successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		assertTrue(accessToken != null);
		
//		System.out.println("TokenType: " + accessToken.getIssuedTokenType().toString());
		
		SignedJWT jwt = SignedJWT.parse(accessToken.getValue());
		
		// Verify id token
		
		Map<String, Object> tokenValues = JsonHelper.parseJson(jwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		
		Issuer iss = new Issuer((String) tokenValues.get("iss"));

		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(iss);
		URI jwkSetURI = opMetadata.getJWKSetURI();
		
		assertTrue(jwkSetURI != null && jwkSetURI.toString().startsWith(iss.getValue()));
		
		// ClientID also comes with the token, variable already exists

		String tokenString = jwt.serialize();
		
		// Server side: verify token signature
		SignedJWT srvJwt = SignedJWT.parse(tokenString);
		
		tokenValues = JsonHelper.parseJson(srvJwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		Issuer srvIss = new Issuer((String) tokenValues.get("iss"));
		ClientID srvClientId = new ClientID((String) tokenValues.get("aud"));

//		IDTokenValidator srvValidator = new IDTokenValidator(srvIss, srvClientId, JWSAlgorithm.RS256, jwkSetURI.toURL());

//		claimsSet = srvValidator.validate(jwt, null);
		
		JWTClaimsSet claimsSet = srvJwt.getJWTClaimsSet();
		System.out.println("claimsSet: " + claimsSet);
		
		
		// Required for jwt security in backend service
		
		String keyID = jwt.getHeader().getKeyID();
		assertTrue(keyID != null && !keyID.isEmpty());
		
		String upn = (String) claimsSet.getClaim("upn");
		assertTrue(upn != null && !upn.isEmpty(), "Claim 'upn' missing or empty!");
		
		String[] groups = claimsSet.getStringArrayClaim("groups");
		assertTrue(groups != null && groups.length > 0, "Claim 'groups' missing or empty!");
	}

	
	@Test
	@Disabled
	public void testRequestVerifyAccessToken4User() throws Exception {
		// Client side: retrieve accessToken with ClientSecretBasic grant
		
		ClientID clientID = new ClientID(OIDC_CLIENT_ID);

		AuthorizationGrant clientGrant = new ResourceOwnerPasswordCredentialsGrant("theuser", new Secret("secretPassword"));
		
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
//		SignedJWT idToken = (SignedJWT) successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		assertTrue(accessToken != null);
		
//		System.out.println("TokenType: " + accessToken.getIssuedTokenType().toString());
		
		SignedJWT jwt = SignedJWT.parse(accessToken.getValue());
		
		// Verify id token
		
		Map<String, Object> tokenValues = JsonHelper.parseJson(jwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		
		Issuer iss = new Issuer((String) tokenValues.get("iss"));

		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(iss);
		URI jwkSetURI = opMetadata.getJWKSetURI();
		
		assertTrue(jwkSetURI != null && jwkSetURI.toString().startsWith(iss.getValue()));
		
		// ClientID also comes with the token, variable already exists

		String tokenString = jwt.serialize();
		
		// Server side: verify token signature
		SignedJWT srvJwt = SignedJWT.parse(tokenString);
		
		tokenValues = JsonHelper.parseJson(srvJwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
		Issuer srvIss = new Issuer((String) tokenValues.get("iss"));
		ClientID srvClientId = new ClientID((String) tokenValues.get("aud"));

//		IDTokenValidator srvValidator = new IDTokenValidator(srvIss, srvClientId, JWSAlgorithm.RS256, jwkSetURI.toURL());

//		claimsSet = srvValidator.validate(jwt, null);
		
		JWTClaimsSet claimsSet = srvJwt.getJWTClaimsSet();
		System.out.println("claimsSet: " + claimsSet);
		
		
		// Required for jwt security in backend service
		
		String keyID = jwt.getHeader().getKeyID();
		assertTrue(keyID != null && !keyID.isEmpty());
		
		String upn = (String) claimsSet.getClaim("upn");
		assertTrue(upn != null && !upn.isEmpty(), "Claim 'upn' missing or empty!");
		
		String[] groups = claimsSet.getStringArrayClaim("groups");
		assertTrue(groups != null && groups.length > 0, "Claim 'groups' missing or empty!");
	}

	private class CallbackHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			// TODO Auto-generated method stub
			System.err.println("Handling HttpExchange " + exchange.getRequestMethod() + " " + exchange.getRequestURI().toString());
			Map<String, String> parameters = retrieveQueryParameters(exchange.getRequestURI().toString());
			codeRcvd = parameters.get("code");
			stateRcvd = parameters.get("state");
			handleResponse(exchange, "");
		}

		public Map<String, String> retrieveQueryParameters(String uri) {
			return Arrays.asList(uri.split("\\?")[1].split("&"))
					.stream()
					.map(parameter -> parameter.split("="))
					.collect(Collectors.toMap(p -> p[0], p -> p[1]));
		}

		private void handleResponse(HttpExchange httpExchange, String requestParamValue) throws IOException {
			OutputStream outputStream = httpExchange.getResponseBody();
			httpExchange.sendResponseHeaders(200, 0);
			outputStream.flush();
			outputStream.close();
		}
	}

	private String codeRcvd = null;
	private String stateRcvd = null;
	
	@Test
	public void loginUser() throws Exception {
		ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
		HttpServer server = HttpServerProvider.provider().createHttpServer(new InetSocketAddress("localhost", 8001), 0);
		server.createContext("/callback", new  CallbackHandler());
		server.setExecutor(threadPoolExecutor);
		server.start();
		
		System.err.println("Started " + server.toString());

		ClientID clientId = new ClientID(OIDC_CLIENT_ID);
		
		URI callback = new URI("http://localhost:8001/callback");
		
		State state = new State();
		
		Nonce nonce = new Nonce();
		
//		AuthorizationRequest request = new AuthorizationRequest.Builder(
//												new ResponseType("id_token"), clientId)
//											.endpointURI(new URI(wsUrl + OIDC_AUTHORISATION_URL))
//											.redirectionURI(callback)
//											.state(state)
//											.build();

		AuthenticationRequest request = new AuthenticationRequest.Builder(
				new ResponseType("code"), new Scope("openid"), clientId, callback)
			.endpointURI(new URI(wsUrl + OIDC_AUTHORIZATION_URL))
			.state(state)
			.nonce(nonce)
			.build();
		
		System.out.println(request.toURI().toString());
		
		
	    ChromeOptions options = new ChromeOptions();
	    
	    // If SeleniumManager needs to use a proxy to reach chrome download
//	    Proxy proxy = new Proxy();
//	    proxy.setHttpProxy("<host>:<port>");
//	    options.setCapability("proxy", proxy);
	    
	    WebDriver driver = new ChromeDriver(options);
		
	    driver.manage().timeouts().implicitlyWait(Duration.ofMillis(500));

	    driver.get(request.toURI().toString());

		WebElement userIdBox = driver.findElement(By.name("username"));
		userIdBox.sendKeys("theuser");
		WebElement passwordBox = driver.findElement(By.name("password"));
		passwordBox.sendKeys("secretPassword");
        WebElement submitButton = driver.findElement(By.name("login"));
        submitButton.click();
        
        assertTrue(driver.getCurrentUrl().startsWith(callback.toString()));
        
//        Thread.sleep(500);
        driver.close();
        server.stop(0);
        System.out.println("");
		
        assertNotNull(codeRcvd);
        assertEquals(state.getValue(), stateRcvd);
        
        
		AuthorizationGrant authCodeGrant = new AuthorizationCodeGrant(new AuthorizationCode(codeRcvd), callback);
		
		// The token endpoint
		URI tokenEndpoint = new URI(wsUrl + OIDC_TOKEN_URL);

		// The credentials to authenticate the client at the token endpoint
		Secret clientSecret = new Secret(OIDC_CLIENT_SECRET);
		ClientAuthentication clientAuth = new ClientSecretJWT(clientId, tokenEndpoint, JWSAlgorithm.HS256, clientSecret);

		// The request scope for the token
		Scope scope = new Scope("openid");

		// Make the token request
		TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, authCodeGrant, scope);

		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());

		if (!tokenResponse.indicatesSuccess()) {
		    // We got an error response...
		    TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
		    System.err.println(errorResponse.getErrorObject().getDescription());
		    fail(errorResponse.getErrorObject().getDescription());
		}

		OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

		// Get the ID and access token, the server may also return a refresh token
//		SignedJWT idToken = (SignedJWT) successResponse.getOIDCTokens().getIDToken();
		AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
//		RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();
		
		assertTrue(accessToken != null);
		
//		System.out.println("TokenType: " + accessToken.getIssuedTokenType().toString());
		
		SignedJWT jwt = SignedJWT.parse(accessToken.getValue());
		
		// Verify id token
		
		Map<String, Object> tokenValues = JsonHelper.parseJson(jwt.getPayload().toString(), true);
		for (String tv : tokenValues.keySet()) {
			System.out.println("IDToken: " + tv + " - " + tokenValues.get(tv));
		}
        
	}
	
	private String getActionFromHtmlForm(String htmlForm) {
		String form = htmlForm.substring(htmlForm.indexOf("<form"));
		int offset = form.indexOf("action=");
		return form.substring(offset + 8, form.indexOf("\"", offset + 8));
	}
}
