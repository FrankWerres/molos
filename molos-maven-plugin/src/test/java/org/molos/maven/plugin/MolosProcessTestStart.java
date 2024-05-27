package org.molos.maven.plugin;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.ProcessBuilder.Redirect;

import org.junit.jupiter.api.Test;

public class MolosProcessTestStart {

	@Test
	void test() throws IOException {
		String javaHome = System.getProperty("java.home");
		String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
		String classpath = System.getProperty("java.class.path");
		ProcessBuilder builder = new ProcessBuilder(javaBin, "-cp", classpath, "org.molos.maven.plugin.MolosProcess",
				"arg0", "arg1");
		Process process = builder.start();
		long pid = process.pid();
		System.out.println("Started pid " + pid);

		try (BufferedReader output = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
			String line = output.readLine();
			while (line != null) {
				System.out.println(line);
				if (!line.startsWith("URL:")) {
					line = output.readLine();
				} else {
					line = null;
				}
			}
		}
		try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))) {
			writer.write("Started pid " + pid);
			writer.newLine();
		}
		
		System.out.println("Started pid " + pid);
	}

}
