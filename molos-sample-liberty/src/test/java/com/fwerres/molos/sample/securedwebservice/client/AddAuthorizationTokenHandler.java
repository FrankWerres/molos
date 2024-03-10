package com.fwerres.molos.sample.securedwebservice.client;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.namespace.QName;

import jakarta.xml.ws.handler.MessageContext;
import jakarta.xml.ws.handler.soap.SOAPHandler;
import jakarta.xml.ws.handler.soap.SOAPMessageContext;

public class AddAuthorizationTokenHandler implements SOAPHandler<SOAPMessageContext> {

	private Logger logger = Logger.getLogger(AddAuthorizationTokenHandler.class.getName());
	
	private static final String HTTP_HEADER_AUTHORIZATION = "Authorization";

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		
		if (outboundProperty.booleanValue()) {
			@SuppressWarnings("unchecked")
			Map<String, List<String>> headers = (Map<String, List<String>>) context.get(MessageContext.HTTP_REQUEST_HEADERS);
			if (headers == null) {
				headers = new HashMap<String, List<String>>();
				context.put(MessageContext.HTTP_REQUEST_HEADERS, headers);
			}
			String headerContent = "Bearer token";// + accessTokenProvider.getAccessToken();
			headers.put(HTTP_HEADER_AUTHORIZATION, Arrays.asList(headerContent));
			logger.info("Adding HTTP Authorization-header " + headerContent);
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
