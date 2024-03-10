package com.fwerres.molos.sample.securedwebservice.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.fwerres.sample.webservice.WebService;
import com.fwerres.sample.webservice.WebService_Service;

import jakarta.xml.ws.Binding;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.handler.Handler;

public class ConsumeSecuredWebServiceIT {

	private String url = "http://localhost:9080/LibertyProject/WebService";
//	private String url = "http://localhost:9080/molos-sample-webservice/WebService";
	
	@Test
	public void testInvokeService() throws MalformedURLException {
		WebService_Service service = new WebService_Service(new URL(url));
		WebService port = service.getWebServiceSOAP();

		Binding binding = ((BindingProvider) port).getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new AddAuthorizationTokenHandler());
		binding.setHandlerChain(handlerChain);
		
		String param = "inputString" + Long.toOctalString(new Random().nextLong());
		boolean gotExpextedException = false;
		try {
			String resultString = port.newOperation(param);
		} catch (RuntimeException se) {
			System.err.println("Exception: " + se.getMessage());
			gotExpextedException = true;
		}
		
		assertTrue(gotExpextedException);
		
//		assertTrue(resultString.startsWith("Processed by newOperation: "));
//		assertEquals(param, resultString.substring(resultString.length() - param.length()));
//		
//		System.out.println("Result: " + resultString);
	}
}
