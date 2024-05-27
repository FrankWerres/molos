package org.molos.maven.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/**
 * Goal which stops a (or all)  molos server(s).
 */
@Mojo(name = "stop", defaultPhase = LifecyclePhase.POST_INTEGRATION_TEST)
public class StopMolos extends AbstractMojo {

	@Component
	private MavenProject project;
	
	@Component
	private MavenSession session;

	@Parameter(defaultValue = "molos")
	private String domain;

	@Parameter(defaultValue = "false")
	private boolean skip;

	@Parameter(defaultValue = "false")
	private boolean stopAll;

	@Override
	public void execute() throws MojoExecutionException, MojoFailureException {
		getLog().info("molos - My Own Little Oidc Server - stop");
		
//		getLog().info(getPluginContext().toString());
		
		if (skip) {
            getLog().info("\nSkipping start goal.\n");
            return;
        }
		
		getLog().info("domain: " + domain);
		getLog().info("stopAll: " + stopAll);
		
		boolean foundDomain = false;
		List<String> removeKeys = new ArrayList<>();
		Properties props = project.getProperties();
		for (Object key : props.keySet()) {
			if (key instanceof String keyName && keyName.startsWith("molos")) {
				getLog().info("Property " + keyName + ": " + props.getProperty(keyName));
				if (keyName.endsWith(".pid")) {
					foundDomain = foundDomain |= keyName.startsWith("molos.domain." + domain);
					if (stopAll || keyName.startsWith("molos.domain." + domain)) {
						String key2remove = "molos.domain." + domain + ".pid";
						removeKeys.add(key2remove);
						stop(Long.parseLong(props.getProperty(key2remove)));
					}
				}
			}
		}
		for (String removeKey : removeKeys) {
			props.remove(removeKey);
		}
		if (!stopAll && !foundDomain) {
			getLog().warn("Didn't find running molos for domain " + domain);
		}
	}

	protected void stop(long pid) {
		Optional<ProcessHandle> optionalProcessHandle = ProcessHandle.of(pid);
		optionalProcessHandle.ifPresentOrElse(processHandle -> { 
			getLog().info("Killing " + processHandle.toString()); 
			processHandle.destroy(); 
		}, () -> { getLog().warn("No process found with given pid " + pid); });
	}

}
