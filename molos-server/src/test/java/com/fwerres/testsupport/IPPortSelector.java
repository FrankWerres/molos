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
