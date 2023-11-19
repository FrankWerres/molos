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

}
