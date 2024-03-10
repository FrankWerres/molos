package com.fwerres.sample.webservice.impl;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.xml.namespace.QName;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.w3c.dom.DOMException;

import jakarta.xml.soap.SOAPException;
import jakarta.xml.ws.handler.MessageContext;
import jakarta.xml.ws.handler.soap.SOAPHandler;
import jakarta.xml.ws.handler.soap.SOAPMessageContext;

public class JWTRequiredHandler implements SOAPHandler<SOAPMessageContext> {

	private static final String HTTP_HEADER_AUTHORIZATION = "Authorization";

	protected final Logger logger = Logger.getLogger(getClass().getName());

	protected String issuer;
	protected String clientIdString;
	protected String clientSecretString;
	protected String tokenIntrospectionUrl;

	public JWTRequiredHandler() {
		Config config = ConfigProvider.getConfig();
		
		this.clientIdString = config.getConfigValue("accessTokenFilter.oidcClientId").getValue();
		this.clientSecretString = config.getConfigValue("accessTokenFilter.oidcClientSecret").getValue();
		this.issuer = config.getConfigValue("accessTokenFilter.oidcIssuer").getValue();
		this.tokenIntrospectionUrl = config.getConfigValue("accessTokenFilter.oidcTokenIntrospectionUrl").getValue();

		if (clientIdString != null) {
			logger.info("clientId: " + clientIdString);
		} else {
			logger.warning("clientId is null!");
		}
		if (clientSecretString != null) {
			logger.info("clientSecret: " + clientSecretString);
		} else {
			logger.warning("clientSecret is null!");
		}
		if (issuer != null) {
			logger.info("issuer: " + issuer);
		} else {
			logger.warning("issuer is null!");
		}
		if (tokenIntrospectionUrl != null) {
			logger.info("tokenIntrospectionUrl: " + tokenIntrospectionUrl);
		} else {
			logger.warning("tokenIntrospectionUrl is null!");
		}
	}
	
	@Override
	public boolean handleMessage(SOAPMessageContext context) {

		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		
		if (!outboundProperty.booleanValue()) {
			Map<String, List<String>> headers = (Map<String, List<String>>) context.get(MessageContext.HTTP_REQUEST_HEADERS);
			
			String token = null;
			if (headers != null && headers.containsKey(HTTP_HEADER_AUTHORIZATION)) {
				String authorization = headers.get(HTTP_HEADER_AUTHORIZATION).get(0);
				if (authorization != null && !authorization.isEmpty()) {
					token = authorization.substring("Bearer".length()).trim();
				}
			}
			if (token != null && !token.isEmpty()) {
				logger.info("Found token " + token);
			}
//			System.err.println("Headers: " + object.getClass().toString());
//			context.getHeaders(null, null, false)
			context.put(MessageContext.HTTP_RESPONSE_CODE, Integer.valueOf(401));
			context.setScope(MessageContext.HTTP_RESPONSE_CODE, MessageContext.Scope.APPLICATION);
			try {
				context.getMessage().getSOAPBody().setTextContent("");
			} catch (DOMException | SOAPException e) {
				e.printStackTrace();
			}
			throw new SecurityException("Invalid or no token!");
		}
		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {
	}

	@Override
	public Set<QName> getHeaders() {
		return null;
	}

}
