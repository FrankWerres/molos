package org.molos.maven.plugin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/**
 * Goal which starts a molos server.
 */
@Mojo(name = "start", defaultPhase = LifecyclePhase.PRE_INTEGRATION_TEST)
public class StartMolos extends AbstractMojo {

	// inject the project
	@Parameter(defaultValue = "${project}")
	private MavenProject project;

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
		getLog().info("contentFile: " + contentFile);
		getLog().info("updateFile: " + updateFile);
		project.getProperties().setProperty("molos.version", "0.0.1");
		
	}

}
