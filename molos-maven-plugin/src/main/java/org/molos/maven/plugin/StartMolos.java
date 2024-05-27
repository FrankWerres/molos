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

	@Parameter(defaultValue = "${project.basedir}/content.molos")
	private String contentFile;

	@Parameter(defaultValue = "false")
	private boolean updateFile;

	@Parameter(defaultValue = "false")
	private boolean skip;
	
	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		getLog().info("molos - My Own Little Oidc Server - start");
		
		if (skip) {
            getLog().info("\nSkipping start goal.\n");
            return;
        }
		
		getLog().info("domain: " + domain);

		if (alreadyRunning()) {
			getLog().warn("Looks like there's already an molos instance serving the domain " + domain);
			return;
		}
		
		getLog().info("contentFile: " + contentFile);
		getLog().info("updateFile: " + updateFile);
		
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

		Properties properties = project.getProperties();
		String domainPrefix = "molos.domain." + domain;
		getLog().info("Set " + domainPrefix + ".pid=" + Long.toString(pid));
		properties.setProperty(domainPrefix + ".pid", Long.toString(pid));
		getLog().info("Set " + domainPrefix + ".url=" + url);
		properties.setProperty(domainPrefix + ".url", url);
	}
}
