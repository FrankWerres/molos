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
package com.fwerres.testsupport;

import java.util.Arrays;

//import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;

import org.apache.cxf.endpoint.Server;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;

public class JaxRSHelper {

	public Server createLocalCXFServer(String wsUri, Class<?> serverClass, Object provider, Object[] filters) throws Exception {
		if (!wsUri.startsWith("/")) {
			throw new IllegalArgumentException("Expect uri to begin with /!");
		}
		
		int portNumber = IPPortSelector.availablePort();
		
		String url = "http://localhost:".concat(Integer.toString(portNumber)).concat(wsUri);

		JAXRSServerFactoryBean serverFactoryBean = new JAXRSServerFactoryBean();

		if (provider != null) {
			serverFactoryBean.setProvider(provider);
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
