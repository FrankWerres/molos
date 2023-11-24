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
package com.fwerres.testsupport;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonValue.ValueType;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;

public class JsonHelper {


	public static Map<String, Object> parseJson(String json, boolean removeStringDelimiter) {
		JsonObject jsonValue = null;
		JsonParserFactory parserFactory = Json.createParserFactory(null);
		JsonParser parser = parserFactory.createParser(new StringReader(json));
		
		if (parser.hasNext()) {
			parser.next();
			jsonValue = parser.getObject();
		}
		Map<String, Object> result = new HashMap<>();
		for (Entry<String, JsonValue> entry : jsonValue.entrySet()) {
			if (ValueType.STRING == entry.getValue().getValueType() && removeStringDelimiter) {
				String stringValue = entry.getValue().toString();
				result.put(entry.getKey(), stringValue.toString().substring(1, stringValue.length() - 1));
			} else {
				result.put(entry.getKey(), entry.getValue().toString());
			}
		}
		return result;
	}

	public static boolean responseContainsActiveTrue(String body) {
		JsonValue jsonValue = null;
		JsonParserFactory parserFactory = Json.createParserFactory(null);
		JsonParser parser = parserFactory.createParser(new StringReader(body));
		
		if (parser.hasNext()) {
			parser.next();
			jsonValue = parser.getObjectStream().filter(e->e.getKey().equals("active"))
        		.map(e->e.getValue()).findFirst().get();
		}
		return JsonValue.TRUE.equals(jsonValue);
	}
	
}
