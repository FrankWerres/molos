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

import java.util.ArrayList;
import java.util.List;

import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbBuilder;

public class MolosResult {

	private static Jsonb jsonb = JsonbBuilder.create();
	
	private boolean success = false;
	private List<String> messages = new ArrayList<>();
	private String entity = null;
	
	public boolean isSuccess() {
		return success;
	}
	
	public void setSuccess(boolean success) {
		this.success = success;
	}
	
	public List<String> getMessages() {
		return messages;
	}
	
	public void addToMessages(String msg) {
		messages.add(msg);
	}

	public String getEntity() {
		return entity;
	}

	public <T> T getResultObject(Class<T> clazz) {
		if (entity == null || entity.isEmpty()) {
			return null;
		}
		return jsonb.fromJson(entity, clazz);
		
	}

	public void setEntity(String entity) {
		this.entity = entity;
		
	}

	public void setResultObject(Object entity) {
		this.entity = jsonb.toJson(entity);
		
	}
}
