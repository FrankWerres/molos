package org.molos.maven.plugin;

import org.apache.cxf.endpoint.Server;

import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import com.fwerres.molos.Molos;
import com.fwerres.testsupport.JaxRSHelper;

public class MolosProcess {

	protected JaxRSHelper jaxrs = new JaxRSHelper();
	private Server theServer;

	public static void main(String[] args) throws Exception {
		new MolosProcess(args[0]);
	}
	
	public MolosProcess(String domain) throws Exception {
//		for (String string : args) {
			System.out.println("Arg: " + domain);
//		}
		
		theServer = jaxrs.createLocalCXFServer("/molos/" + domain, Molos.class, new JacksonJsonProvider(), new Object[] { });
		String wsUrl = jaxrs.getActualUrl(theServer);
		System.out.println("Started server on " + wsUrl);

		System.out.println("URL: " + wsUrl);
		
//		String line = new BufferedReader(new InputStreamReader(System.in)).readLine();
//		
//		System.out.println(line);
//		System.out.println("Now just doing my work ...");
		
		while (true) {
			try {
				Thread.sleep(1000L);
			} catch (InterruptedException ie) {
			}
		}
		
	}

}
