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
package com.fwerres.molos.config;

public class SaveLocations {

	private String configDir;
	private String protocolDir;
	private String configFile;
	
	public String getConfigDir() {
		return configDir;
		
	}
	public void setConfigDir(String configDir) {
		this.configDir = configDir;
		
	}
	public String getConfigFile() {
		return configFile;
		
	}
	public void setConfigFile(String configFile) {
		this.configFile = configFile;
		
	}
	public String getProtocolDir() {
		return protocolDir;
		
	}
	public void setProtocolDir(String protocolDir) {
		this.protocolDir = protocolDir;
		
	}
	
}
