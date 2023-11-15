package com.fwerres.molos.config;

public class OpenIdConfig {

	public static final String PATH_TOKEN_INTROSPECTION_ENDPOINT = "/protocol/openid-connect/token/introspect";
	public static final String PATH_TOKEN_ENDPOINT = "/protocol/openid-connect/token";
	public static final String PATH_CONFIG_ENDPOINT = "/.wellknown/openid-configuration";
	
	private String issuer;
	private String token_endpoint;
	private String introspection_endpoint;

	public OpenIdConfig(String baseUrl) {
		issuer = baseUrl;
		token_endpoint = baseUrl + PATH_TOKEN_ENDPOINT;
		introspection_endpoint = baseUrl + PATH_TOKEN_INTROSPECTION_ENDPOINT;
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
	
}
