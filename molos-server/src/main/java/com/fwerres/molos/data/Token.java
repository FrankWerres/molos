package com.fwerres.molos.data;

import java.net.URI;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.Random;
import java.util.TimeZone;
import java.util.UUID;

import com.fwerres.molos.config.ClientConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

public class Token {

	private String access_token = null;
	private int expires_in = 300;
	private int refresh_expires_in = 0;
	private String token_type = "Bearer";
	private String id_token = null;
//	private int not_before_policy = 0;
	private String scope = "openid profile email";
	
	public Token(URI issuer, ClientConfig clientConfig) {
		TimeZone tz = TimeZone.getTimeZone("UTC");
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
		df.setTimeZone(tz);
		Date now = new Date();
		String nowAsISO = df.format(now);
		access_token = "access_token_" + nowAsISO + "_" + Long.toString(new Random().nextLong());
		id_token = createIdToken(issuer, clientConfig, now);
	}
	
	private String createIdToken(URI issuer, ClientConfig clientConfig, Date now) {
		JWTClaimsSet claims = new JWTClaimsSet.Builder()
										.issueTime(now)
										.issuer(issuer.toString())
										.expirationTime(new Date(now.getTime() + expires_in * 1000))
										.audience(clientConfig.getClientId())
										.subject(clientConfig.getClientId())
										.jwtID(UUID.randomUUID().toString())
										.build();
		JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
		SignedJWT jwt = new SignedJWT(header, claims);
		try {
			JWSSigner signer = new MACSigner(clientConfig.getClientSecret());
			jwt.sign(signer);
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		return jwt.serialize();
	}

//	{
//		"exp":1699876988,
//		"iat":1699876688,
//		"auth_time":0,
//		"jti":"726716a8-4fa4-44df-862f-de2b95f8eff1",
//		"iss":"http://localhost:8081/realms/big_dev",
//		"aud":"bigBackendPD",
//		"sub":"da3bb242-1636-4922-9738-b104f542439f",
//		"typ":"ID",
//		"azp":"bigBackendPD",
//		"at_hash":"pQEGhs9mExWdq19MK7Zgvg",
//		"acr":"1",
//		"clientHost":"172.17.0.1",
//		"email_verified":false,
//		"preferred_username":"service-account-bigbackendpd",
//		"clientAddress":"172.17.0.1",
//		"client_id":"bigBackendPD"
//	}
	
	public String getAccess_token() {
		return access_token;
	}
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}
	public int getExpires_in() {
		return expires_in;
	}
	public void setExpires_in(int expires_in) {
		this.expires_in = expires_in;
	}
	public int getRefresh_expires_in() {
		return refresh_expires_in;
	}
	public void setRefresh_expires_in(int refresh_expires_in) {
		this.refresh_expires_in = refresh_expires_in;
	}
	public String getToken_type() {
		return token_type;
	}
	public void setToken_type(String token_type) {
		this.token_type = token_type;
	}
	public String getId_token() {
		return id_token;
	}
	public void setId_token(String id_token) {
		this.id_token = id_token;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
}
