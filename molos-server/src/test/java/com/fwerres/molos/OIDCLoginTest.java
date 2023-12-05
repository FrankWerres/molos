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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Level;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.logging.LogEntries;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.logging.LoggingPreferences;
import org.openqa.selenium.remote.CapabilityType;

import com.fwerres.testsupport.JsonHelper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.spi.HttpServerProvider;

import jakarta.json.Json;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;
import jakarta.json.stream.JsonParser.Event;

/**
 * This class tests molos handling of OIDC-like client authentication flows. 
 * 
 * Selenium does not support retrieval of a http status code, see
 * https://github.com/seleniumhq/selenium-google-code-issue-archive/issues/141
 */
public class OIDCLoginTest extends MolosTestbase {

	private Map<String, String> callBackValues;
	
	private class CallbackHandler implements HttpHandler {

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			System.err.println("Handling HttpExchange " + exchange.getRequestMethod() + " " + exchange.getRequestURI().toString());
			callBackValues = retrieveQueryParameters(exchange.getRequestURI().toString());
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
	
	@Test
	public void loginUser() throws Exception {
		ClientID clientId = new ClientID(OIDC_CLIENT_ID);
		URI callback = new URI("http://localhost:8001/callback");
		
		String code = getCodeFromFromOIDCFlow(clientId, callback);
		
//		retrieveTokenForCode(code, clientId, callback);
	}
	
	private void retrieveTokenForCode(String codeRcvd, ClientID clientId, URI callback) throws Exception {
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

	private String getCodeFromFromOIDCFlow(ClientID clientId, URI callback) throws Exception {
		ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
		HttpServer server = HttpServerProvider.provider().createHttpServer(new InetSocketAddress("localhost", 8001), 0);
		server.createContext("/callback", new  CallbackHandler());
		server.setExecutor(threadPoolExecutor);
		server.start();
		
		System.err.println("Started " + server.toString());

		State state = new State();
		
		Nonce nonce = new Nonce();
		
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
	    
	    LoggingPreferences logPrefs = new LoggingPreferences();
	    logPrefs.enable(LogType.PERFORMANCE, Level.ALL);
	    options.setCapability(ChromeOptions.LOGGING_PREFS, logPrefs);	  
	    
	    WebDriver driver = new ChromeDriver(options);
		
	    driver.manage().timeouts().implicitlyWait(Duration.ofMillis(500));

	    driver.get(request.toURI().toString());
	    
	    LogEntries logs = driver.manage().logs().get("performance");

	    int status = getHttpStatusForCall(logs, request.toURI().toString());
	    
	    assertEquals(200, status, "AuthenticationRequest could not be sent successfully, HTTP-Status: ");
	    
		WebElement userIdBox = driver.findElement(By.name("username"));
		userIdBox.sendKeys("theuser");
		WebElement passwordBox = driver.findElement(By.name("password"));
		passwordBox.sendKeys("secretPassword");
        WebElement submitButton = driver.findElement(By.name("login"));
        submitButton.click();
        
//        logs = driver.manage().logs().get("performance");
        
//        showLogs(logs);
        
        assertTrue(callBackValues.containsKey("state"));
        assertEquals(state.getValue(), callBackValues.get("state"));
        assertTrue(callBackValues.containsKey("code"));
        String code = callBackValues.get("code");
        assertTrue(code != null && !code.isEmpty());

        Thread.sleep(500);
        
        driver.close();
        
        return code;
	}

	private void showLogs(LogEntries logs) {
        for (Iterator<LogEntry> it = logs.iterator(); it.hasNext();) {
            LogEntry entry = it.next();

            String message = entry.getMessage();
				System.out.println(message);
        }
	}

	private int getHttpStatusForCall(LogEntries logs, String urlCalled) {
		int status = -1;

        for (Iterator<LogEntry> it = logs.iterator(); it.hasNext();) {
            LogEntry entry = it.next();

            String message = entry.getMessage();
//				System.out.println(message);
			JsonReader reader = Json.createReader(new StringReader(message));
				
			JsonStructure structure = reader.read();
			JsonValue method = structure.getValue("/message/method");
			if (method != null
                       && "Network.responseReceived".equals(((JsonString) method).getString())) {
//				System.out.println(((JsonString) method).getString());
				JsonString url = (JsonString) structure.getValue("/message/params/response/url");
//					response.forEach((key, value) -> {
//						System.out.println(key);
//					});
//				System.out.println(url.getString());
				if (url.getString().startsWith(urlCalled)) {
					status = ((JsonNumber) structure.getValue("/message/params/response/status")).intValue();
				}
            }
        }

//        System.out.println("\nstatus code: " + status);
        return status;
    }
}
