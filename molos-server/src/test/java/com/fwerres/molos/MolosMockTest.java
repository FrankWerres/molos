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
package com.fwerres.molos;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;

import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.junit.jupiter.api.Test;

import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.SaveBehaviour;
import com.fwerres.molos.config.SaveLocations;

import jakarta.ws.rs.core.Response;

/**
 * Tests methods concerned with configuring molos functionality.
 */
public class MolosMockTest {

	@Test
	public void testDefaultConfigDir() {
		Molos molos = new Molos();
		
		SaveLocations sl = new SaveLocations();
		Response response = molos.mockSetSaveLocations(sl);
		MolosResult result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		
		System.out.println(result.getMessages().get(0));
		sl = (SaveLocations) result.getEntity();
		
		String expectedPath = "./.molos";
		String expectedFile = "./.molos/molos.realm";
		File d = new File(expectedPath);

		assertEquals(d.getAbsolutePath(), sl.getConfigDir());
		File f = new File(expectedFile);
		assertEquals(f.getAbsolutePath(), sl.getConfigFile());
		
		assertEquals(d.getAbsolutePath(), sl.getProtocolDir());
	}

	@Test
	public void testDefaultSaveBehaviour() {
		Molos molos = new Molos();
		
		SaveBehaviour sb = new SaveBehaviour();
		Response response = molos.mockSetSaveBehaviour(sb);
		MolosResult result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		System.out.println(result.getMessages().get(0));
		sb = (SaveBehaviour) result.getEntity();
		assertFalse(sb.isSaveActionProtocol());
		assertFalse(sb.isSaveConfigHistory());
		assertFalse(sb.isSaveConfigOnChange());
		
		sb.setSaveActionProtocol(true);
		response = molos.mockSetSaveBehaviour(sb);
		result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		System.out.println(result.getMessages().get(0));
		sb = (SaveBehaviour) result.getEntity();
		assertTrue(sb.isSaveActionProtocol());
		assertFalse(sb.isSaveConfigHistory());
		assertFalse(sb.isSaveConfigOnChange());
		
		sb.setSaveActionProtocol(false);
		sb.setSaveConfigHistory(true);
		response = molos.mockSetSaveBehaviour(sb);
		result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		System.out.println(result.getMessages().get(0));
		sb = (SaveBehaviour) result.getEntity();
		assertFalse(sb.isSaveActionProtocol());
		assertTrue(sb.isSaveConfigHistory());
		assertFalse(sb.isSaveConfigOnChange());

		sb.setSaveConfigHistory(false);
		sb.setSaveConfigOnChange(true);
		response = molos.mockSetSaveBehaviour(sb);
		result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		System.out.println(result.getMessages().get(0));
		sb = (SaveBehaviour) result.getEntity();
		assertFalse(sb.isSaveActionProtocol());
		assertFalse(sb.isSaveConfigHistory());
		assertTrue(sb.isSaveConfigOnChange());
}

	@Test
	public void testSetConfigDir() {
		Molos molos = new Molos();
		
		SaveLocations sl = new SaveLocations();
		
		File d = new File("target/molos");
		File f = new File(d, "molos.realm");
		sl.setConfigDir(d.getPath());
		
		Response response = molos.mockSetSaveLocations(sl);
		MolosResult result = extractResultEntity(response, MolosResult.class);
		assertTrue(result.isSuccess());
		System.out.println(result.getMessages().get(0));
		sl = (SaveLocations) result.getEntity();
		
		System.out.println("Location " + d.getAbsolutePath());
		assertEquals(d.getAbsolutePath(), sl.getConfigDir());
		assertEquals(f.getAbsolutePath(), sl.getConfigFile());
		assertEquals(d.getAbsolutePath(), sl.getProtocolDir());
	}

	private <T> T extractResultEntity(Response response, Class<T> clazz) {
		OutboundJaxrsResponse resp = (OutboundJaxrsResponse) response;
		@SuppressWarnings("unchecked")
		T result = (T) resp.getContext().getEntity();
		return result;
	}
}
