package org.molos.maven.plugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
//import org.glassfish.jersey.jackson.internal.jackson.jaxrs.json.JacksonJsonProvider;

import com.fasterxml.jackson.jakarta.rs.json.JacksonJsonProvider;
import com.fwerres.molos.client.MolosConfig;
import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;

/**
 * Goal which starts a molos server.
 */
@Mojo(name = "start", defaultPhase = LifecyclePhase.PRE_INTEGRATION_TEST)
public class StartMolos extends AbstractMojo {

	@Component
	private MavenProject project;
	
	@Component
    private MojoExecution mojoExecution;
	
	@Parameter(defaultValue = "molos")
	private String domain;

	@Parameter()
	private String contentFile;

	@Parameter()
	private String protocolDir;

	@Parameter(defaultValue = "false")
	private boolean updateFile;

	@Parameter(defaultValue = "false")
	private boolean createProtocol;

	@Parameter(defaultValue = "false")
	private boolean skip;
	
	@Parameter
	private List<ClientConfig> clients;
	
	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		getLog().info("molos - My Own Little Oidc Server - start");
		
		if (skip) {
            getLog().info("\nSkipping start goal.\n");
            return;
        }
		
		getLog().info("domain: " + domain);
		
		if (contentFile == null || contentFile.isEmpty()) {
			contentFile = domain + ".realm";
		}

		if (alreadyRunning()) {
			getLog().warn("Looks like there's already an molos instance serving the domain " + domain);
			return;
		}
		
		project.getProperties().setProperty("molos.version", "0.0.1");
		
		try {
			start(domain);//, "-contentFile", contentFile, "-updateFile", Boolean.toString(updateFile));
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	protected boolean alreadyRunning() {
		return project.getProperties().containsKey("molos.domain." + domain + ".pid");
	}

	protected void start(String... args) throws IOException {
		String javaHome = System.getProperty("java.home");
		String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
		String classpath = "";
		
		for (Artifact dependency : mojoExecution.getMojoDescriptor().getPluginDescriptor().getArtifacts()) {
			classpath = classpath.concat(dependency.getFile().toString()) + File.pathSeparatorChar;
		}
		
		List<String> arguments = new ArrayList<String>();
		arguments.add(javaBin);
		arguments.add("-cp");
		arguments.add(classpath);
		arguments.add("org.molos.maven.plugin.MolosProcess");
		arguments.addAll(List.of(args));
		
		for (String string : arguments) {
			getLog().debug("Argument: " + string);
		}
		
		ProcessBuilder builder = new ProcessBuilder(arguments);
		Process process = builder.start();
		long pid = process.pid();
		
		getLog().info("Started pid " + pid);

		String url = null;
		
		try (BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
			String line = output.readLine();
			while (line != null) {
				getLog().info(line);
				if (!line.startsWith("URL:")) {
					line = output.readLine();
				} else {
					url = line.substring(4).trim();
					line = null;
				}
			}
		}

		getLog().info("Setting up from plugin configuration ...");
		
		getLog().info("contentFile: " + contentFile);
		getLog().info("updateFile: " + updateFile);
		getLog().info("createProtocol: " + createProtocol);
		
		MolosConfig setup = MolosConfig.getConfigurator(url, new JacksonJsonProvider());
//		MolosConfig setup = MolosConfig.getConfigurator(url, new JacksonJaxbJsonProvider());
		MolosResult result = setup.configFile(contentFile);
		if (protocolDir != null && !protocolDir.isEmpty()) {
			System.err.println("Calling /mock-setup/saveLocations");
			result = setup.protocolDir(protocolDir);
		}
		if (createProtocol) {
			System.err.println("Calling setup.startProtocol()");
			result = setup.startProtocol();
		}
		if (clients != null) {
			for (ClientConfig clientConfig : clients) {
				System.err.println("Calling setup.client(clientConfig)");
				result = setup.client(clientConfig);
			}
		}
		
		System.err.println("Done setting up.");
		getLog().info("Done setting up.");
		
		Properties properties = project.getProperties();
		String domainPrefix = "molos.domain." + domain;
		getLog().info("Set " + domainPrefix + ".pid=" + Long.toString(pid));
		properties.setProperty(domainPrefix + ".pid", Long.toString(pid));
		getLog().info("Set " + domainPrefix + ".url=" + url);
		properties.setProperty(domainPrefix + ".url", url);
	}
}
