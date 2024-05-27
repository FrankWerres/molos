package org.molos.maven.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;

import org.junit.jupiter.api.Test;

public class MolosProcessTestKill {

	@Test
	void test() throws IOException {
		System.out.println("Enter pid: ");
		String input = new BufferedReader(new InputStreamReader(System.in)).readLine();
		long pid = Long.parseLong(input);
		Optional<ProcessHandle> optionalProcessHandle = ProcessHandle.of(pid);
		optionalProcessHandle.ifPresent(processHandle -> { 
			System.out.println("Killing " + processHandle.toString()); 
			processHandle.destroy(); 
		});
	}

}
