package com.fwerres.molos;

import java.io.StringReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;
import com.fwerres.molos.data.Token;
import com.fwerres.molos.data.TokenIntrospection;
import com.fwerres.molos.setup.State;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;
import jakarta.json.JsonValue.ValueType;
import jakarta.json.bind.Jsonb;
import jakarta.json.bind.spi.JsonbProvider;
import jakarta.json.stream.JsonParser;
import jakarta.json.stream.JsonParserFactory;
import jakarta.json.stream.JsonParser.Event;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;


public class Molos {
	
	private static final String SIGNED_JWT_WITH_CLIENT_SECRET = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";

	@Context
	private UriInfo uriInfo;
	
//	@Inject 
	private final static State state = new State();
	
	private Jsonb jsonb = JsonbProvider.provider().create().build();
	
	@GET
	@Path("/.wellknown/openid-configuration")
    @Produces({ "application/json" })
    public Response openIdConfiguration() {
        return Response.ok().entity(new OpenIdConfig(uriInfo.getBaseUri().toString())).build();
    }
	
	@POST
	@Path("/protocol/openid-connect/token")
    @Produces({ "application/json" })
	public Response getToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);
		
		System.err.println("Request: " + values);
		
		if (values.containsKey(CLIENT_ASSERTION_TYPE) && values.get(CLIENT_ASSERTION_TYPE).equals(SIGNED_JWT_WITH_CLIENT_SECRET)) {
			String clientId = "";
			try {
				SignedJWT jwt = SignedJWT.parse(values.get("client_assertion"));
				String assertion = jwt.getPayload().toString();
				System.err.println("Assertion: " + assertion);
				Map<String, Object> tokenMap = parseJson(assertion);
				clientId = (String) tokenMap.get("iss");
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			Token token = new Token();
			state.registerToken(clientId, token);
			return Response.ok().entity(token).build();
			
		}
		
		String clientId = values.get("client_id");
		String clientSecret = values.get("client_secret");
		
		ClientConfig clientConfig = state.getClient(clientId);
		if (clientConfig != null && clientConfig.getClientSecret().equals(clientSecret) && clientConfig.getScopes().contains(values.get("scope"))) {
			Token token = new Token();
			state.registerToken(clientId, token);
			return Response.ok().entity(token).build();
		} else {
			return Response.serverError().build();
		}
		
//		{
//			"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxZmU3NzNlZS0zOWUzLTQ0MzItYjcyNi0xMWQxMWJiMDJkYzYifQ.eyJleHAiOjE2OTk4NjU0NDEsImlhdCI6MTY5OTg2NTE0MSwianRpIjoiNzdkNmNlZjUtYWU3My00ZmYwLTk5YTEtN2UxMzY2MDJkYTMxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgxL3JlYWxtcy9iaWdfZGV2IiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImRhM2JiMjQyLTE2MzYtNDkyMi05NzM4LWIxMDRmNTQyNDM5ZiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImJpZ0JhY2tlbmRQRCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3BkLmJpZy5jb20iXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iLCJkZWZhdWx0LXJvbGVzLWJpZ19kZXYiXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwiY2xpZW50SG9zdCI6IjE3Mi4xNy4wLjEiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC1iaWdiYWNrZW5kcGQiLCJjbGllbnRBZGRyZXNzIjoiMTcyLjE3LjAuMSIsImNsaWVudF9pZCI6ImJpZ0JhY2tlbmRQRCJ9.OLd-u7kGI51fo89YJ4ocUagpWsLSc4D0_kymohVlTAY",
//			"expires_in":300,
//			"refresh_expires_in":0,
//			"token_type":"Bearer",
//			"id_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI0ZjZlNWhwVEVKN3lGT2dYSUZBNU82UGEweDMxSnB6c1NfUThRSHk1Rjg4In0.eyJleHAiOjE2OTk4NjU0NDEsImlhdCI6MTY5OTg2NTE0MSwiYXV0aF90aW1lIjowLCJqdGkiOiJkYTIxMDk3MC1mZThlLTRkOWUtYjVkNi0zMzIyYThhNDI4N2MiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODEvcmVhbG1zL2JpZ19kZXYiLCJhdWQiOiJiaWdCYWNrZW5kUEQiLCJzdWIiOiJkYTNiYjI0Mi0xNjM2LTQ5MjItOTczOC1iMTA0ZjU0MjQzOWYiLCJ0eXAiOiJJRCIsImF6cCI6ImJpZ0JhY2tlbmRQRCIsImF0X2hhc2giOiJmLWp2ZUpOeXZwUDhPakE2R2xSLXZBIiwiYWNyIjoiMSIsImNsaWVudEhvc3QiOiIxNzIuMTcuMC4xIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZXJ2aWNlLWFjY291bnQtYmlnYmFja2VuZHBkIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4xNy4wLjEiLCJjbGllbnRfaWQiOiJiaWdCYWNrZW5kUEQifQ.NVPCaEKQDgIE6Cj2fNkL9AL4k61zKAsosKo25EbLTs5EIDkmwSdjKGdmSIVkoiyULafHzpciMjMAjZY9XICujF_L6J0ksi5xxWIVNRIWxkTToLKCOqXKBxOAxfEbpjq59_IcSbO5ha5aBb-F9rloZOOUen3T_aro7R9YyZuvlweuFbDh1R4fL2sKmeQBnHmkwowHaVs2HQ_5DabYbSkHRyZkXxRPS9Z-Afpbq_370tf6yTIGSgHgMLF3N2JJFK2FWMEpI_lwEcDLJwsk1hDP6VJliGWdxX8lMDLvwh-L6UoQqJ5-sOE-4xeQNRDQ7bHS7CHP9TvOFhDhZcIWEUn5OA",
//			"not-before-policy":0,
//			"scope":"openid profile email"
//		}
		
    }

	private Map<String, Object> parseJson(String json) {
		JsonObject jsonValue = null;
		JsonParserFactory parserFactory = Json.createParserFactory(null);
		JsonParser parser = parserFactory.createParser(new StringReader(json));
		
		if (parser.hasNext()) {
			Event next = parser.next();
			jsonValue = parser.getObject();//.filter(e->e.getKey().equals("active"))
//        		.map(e->e.getValue()).findFirst().get();
		}
		Map<String, Object> result = new HashMap<>();
		for (Entry<String, JsonValue> entry : jsonValue.entrySet()) {
//			switch (entry.getValue().getValueType()) {
//			case STRING: 
				result.put(entry.getKey(), entry.getValue().toString()); 
//			}
		}
		return result;
	}

	private Map<String, String> parseRequest(String request, HttpHeaders headers, Map<String, String> values) {
		String[] requestParts = request.split("&");
		for (String requestPart : requestParts) {
			String part = URLDecoder.decode(requestPart, Charset.defaultCharset());
			String[] split = part.split("=");
			values.put(split[0],  split[1]);
		}
		
		List<String> authHeaders = headers.getRequestHeader(HttpHeaders.AUTHORIZATION);
		if (authHeaders != null && !authHeaders.isEmpty()) {
			String authorization64 = authHeaders.get(0).substring("Basic ".length());
			String authorization = new String(Base64.getDecoder().decode(authorization64));
			values.put("_authorization", authorization);
			
			String clientId = authorization.substring(0, authorization.indexOf(":"));
			String clientSecret = authorization.substring(authorization.indexOf(":") + 1);
			
			values.put("client_id", clientId);
			values.put("client_secret", clientSecret);
		}
		
		return values;
	}
	
	@POST
	@Path("/protocol/openid-connect/token/introspect")
    @Produces({ "application/json" })
	public Response introspectToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);
		
		String clientId = "";
		if (values.containsKey(CLIENT_ASSERTION_TYPE) && values.get(CLIENT_ASSERTION_TYPE).equals(SIGNED_JWT_WITH_CLIENT_SECRET)) {
			try {
				SignedJWT jwt = SignedJWT.parse(values.get("client_assertion"));
				String assertion = jwt.getPayload().toString();
				System.err.println("Assertion: " + assertion);
				Map<String, Object> tokenMap = parseJson(assertion);
				clientId = (String) tokenMap.get("iss");
			} catch (ParseException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			clientId = values.get("client_id");
		}

		String token = values.get("token");
		
		TokenIntrospection tokenIntrospection = new TokenIntrospection();

		tokenIntrospection.setActive(state.isRegisteredToken(clientId, token));
			
		return Response.ok().entity(tokenIntrospection).build();
	}

	// mock configuration stuff ...
	
	@POST
	@Path("/mock-setup/clear")
	@Produces({ "application/json" })
	public Response clear(String request, @Context HttpHeaders headers) {
		MolosResult result = new MolosResult();
		result.setSuccess(true);
		
		return Response.ok().entity(result).build();
	}
	
	@POST
	@Path("/mock-setup/client")
	@Consumes({ "application/json" })
	@Produces({ "application/json" })
	public Response mockSetupClient(ClientConfig cc) {
		MolosResult result = new MolosResult();

		System.out.println("Registering #" + cc.getClientId());
		
		result.setSuccess(state.registerClient(cc, result.getMessages()));
		
		return Response.ok().entity(result).build();
	}
}
