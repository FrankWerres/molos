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

import java.io.IOException;
import java.net.ServerSocket;

public class IPPortSelector {
	private static int currentPort = 10000;
	
	public synchronized static int availablePort() {
		verifyPortIsAvailable();

		System.err.println("PortsForTest: Returning port #" + currentPort);
		
		return currentPort++;
	}
	
	public static String replacePort(String urlString) {
		int begin = urlString.indexOf(":", urlString.indexOf(":") + 1);
		int end = urlString.indexOf("/", begin);
		return urlString.substring(0, begin + 1).concat(Integer.toString(availablePort())).concat(urlString.substring(end));
		// Would cause runtime problems with cxf library
        //		return UriBuilder.fromUri(urlString).port(freePort()).build().toString();
	}
	
	private static void verifyPortIsAvailable() {
		while (true) {
			try (ServerSocket serverSocket = new ServerSocket(currentPort)) {
				if (serverSocket.getLocalPort() == currentPort) {
					return;
				}
			} catch (IOException e) {
			}
			currentPort++;
		}
	}

}
