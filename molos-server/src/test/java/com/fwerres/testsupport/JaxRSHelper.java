package com.fwerres.testsupport;

import java.util.Arrays;

import org.apache.cxf.endpoint.Server;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.JAXRSServiceFactoryBean;

public class JaxRSHelper {

	public Server createLocalCXFServer(String wsUri, Class<?> serverClass, Object[] providers, Object[] filters) throws Exception {
		if (!wsUri.startsWith("/")) {
			throw new IllegalArgumentException("Expect uri to begin with /!");
		}
		
		int portNumber = IPPortSelector.availablePort();
		
		String url = "http://localhost:".concat(Integer.toString(portNumber)).concat(wsUri);

		JAXRSServerFactoryBean serverFactoryBean = new JAXRSServerFactoryBean();
		
		if (providers != null) {
			serverFactoryBean.setProviders(Arrays.asList(providers));
		}
		
		serverFactoryBean.setServiceClass(serverClass);
		if (filters != null && filters.length > 0) {
			serverFactoryBean.setProviders(Arrays.asList(filters));
		}

		Server server = null;
		
		int count = 0;
		while (server == null && count < 3) {
			try {
				serverFactoryBean.setAddress(url);
				server = serverFactoryBean.create();
			} catch (Throwable t) {
			}
			if (server == null) {
				url = IPPortSelector.replacePort(url);
				count++;
			}
		}

		return server;
	}

	public String getActualUrl(Server server) {
		return server.getEndpoint().getEndpointInfo().getTarget().getAddress().getValue();
	}

}
