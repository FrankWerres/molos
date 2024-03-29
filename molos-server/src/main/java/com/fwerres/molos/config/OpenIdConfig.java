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
package com.fwerres.molos.config;

import java.util.HashSet;
import java.util.Set;

public class OpenIdConfig {

	public static final String PATH_AUTHORIZATION_ENDPOINT ="/protocol/openid-connect/auth";
	public static final String PATH_CONFIG_ENDPOINT = "/.well-known/openid-configuration";
	public static final String PATH_JWKS_URI = "/protocol/openid-connect/certs";
	public static final String PATH_TOKEN_ENDPOINT = "/protocol/openid-connect/token";
	public static final String PATH_TOKEN_INTROSPECTION_ENDPOINT = "/protocol/openid-connect/token/introspect";
	
	private String issuer;
	private String authorization_endpoint;
	private String introspection_endpoint;
	private String jwks_uri;
	private String token_endpoint;
	private Set<String> subject_types_supported = new HashSet<>();

	public OpenIdConfig(String baseUrl) {
		issuer = baseUrl;
		authorization_endpoint = baseUrl + PATH_AUTHORIZATION_ENDPOINT;
		token_endpoint = baseUrl + PATH_TOKEN_ENDPOINT;
		introspection_endpoint = baseUrl + PATH_TOKEN_INTROSPECTION_ENDPOINT;
		jwks_uri = baseUrl + PATH_JWKS_URI;
		subject_types_supported.add("public");
	}
	
	public OpenIdConfig() {
	}
	
	public String getIssuer() {
		return issuer;
	}

	public String getToken_endpoint() {
		return token_endpoint;
	}

	public String getIntrospection_endpoint() {
		return introspection_endpoint;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public void setToken_endpoint(String token_endpoint) {
		this.token_endpoint = token_endpoint;
	}

	public void setIntrospection_endpoint(String introspection_endpoint) {
		this.introspection_endpoint = introspection_endpoint;
	}

	public Set<String> getSubject_types_supported() {
		return subject_types_supported;
	}

	public void setSubject_types_supported(Set<String> subject_types_supported) {
		this.subject_types_supported = subject_types_supported;
	}

	public String getJwks_uri() {
		return jwks_uri;
	}

	public void setJwks_uri(String jwks_uri) {
		this.jwks_uri = jwks_uri;
	}

	public String getAuthorization_endpoint() {
		return authorization_endpoint;
		
	}

	public void setAuthorization_endpoint(String authorization_endpoint) {
		this.authorization_endpoint = authorization_endpoint;
		
	}
	
}
