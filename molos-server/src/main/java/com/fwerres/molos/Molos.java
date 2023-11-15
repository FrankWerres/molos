package com.fwerres.molos;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.fwerres.molos.config.ClientConfig;
import com.fwerres.molos.config.MolosResult;
import com.fwerres.molos.config.OpenIdConfig;
import com.fwerres.molos.data.Token;
import com.fwerres.molos.data.TokenIntrospection;
import com.fwerres.molos.setup.State;

import jakarta.json.bind.Jsonb;
import jakarta.json.bind.spi.JsonbProvider;
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
	
	@Context
	private UriInfo uriInfo;
	
//	@Inject 
	private final static State state = new State();
	
	private Jsonb jsonb = JsonbProvider.provider().create().build();
	
	@GET
	@Path("/.wellknown/openid-configuration")
    @Produces({ "application/json" })
    public Response openIdConfiguration() {
        return Response.ok().entity(jsonb.toJson(new OpenIdConfig(uriInfo.getBaseUri().toString()))).build();
    }
	
	@POST
	@Path("/protocol/openid-connect/token")
    @Produces({ "application/json" })
	public Response getToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);
		
		System.err.println("Request: " + values);
		
		String clientId = values.get("_clientId");
		String clientSecret = values.get("_clientSecret");
		
		ClientConfig clientConfig = state.getClient(clientId);
		if (clientConfig != null && clientConfig.getClientSecret().equals(clientSecret) && clientConfig.getScopes().contains(values.get("scope"))) {
			Token token = new Token();
			state.registerToken(clientId, token);
			return Response.ok().entity(jsonb.toJson(token)).build();
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

	private Map<String, String> parseRequest(String request, HttpHeaders headers, Map<String, String> values) {
		String[] requestParts = request.split("&");
		for (String requestPart : requestParts) {
			String part = URLDecoder.decode(requestPart, Charset.defaultCharset());
			String[] split = part.split("=");
			values.put(split[0],  split[1]);
		}
		
		String authorization64 = headers.getRequestHeader(HttpHeaders.AUTHORIZATION).get(0).substring("Basic ".length());
		String authorization = new String(Base64.getDecoder().decode(authorization64));
		values.put("_authorization", authorization);

		String clientId = authorization.substring(0, authorization.indexOf(":"));
		String clientSecret = authorization.substring(authorization.indexOf(":") + 1);

		values.put("_clientId", clientId);
		values.put("_clientSecret", clientSecret);
		
		return values;
	}
	
	@POST
	@Path("/protocol/openid-connect/token/introspect")
    @Produces({ "application/json" })
	public Response introspectToken(String request, @Context HttpHeaders headers) {
		Map<String, String> values = new HashMap<>();
		
		parseRequest(request, headers, values);

		String token = values.get("token");
		
		TokenIntrospection tokenIntrospection = new TokenIntrospection();
		
		String clientId = values.get("_clientId");

		tokenIntrospection.setActive(state.isRegisteredToken(clientId, token));
			
		return Response.ok().entity(jsonb.toJson(tokenIntrospection)).build();
	}

	// mock configuration stuff ...
	
	@POST
	@Path("/mock-setup/clear")
	@Produces({ "application/json" })
	public Response clear(String request, @Context HttpHeaders headers) {
		MolosResult result = new MolosResult();
		result.setSuccess(true);
		
		return Response.ok().entity(jsonb.toJson(result)).build();
	}
	
	@POST
	@Path("/mock-setup/client")
	@Consumes({ "application/json" })
	@Produces({ "application/json" })
	public Response mockSetupClient(String request) {
		MolosResult result = new MolosResult();

		ClientConfig cc = jsonb.fromJson(request, ClientConfig.class);
		System.out.println("Registering #" + cc.getClientId());
		
		result.setSuccess(state.registerClient(cc, result.getMessages()));
		
		return Response.ok().entity(jsonb.toJson(result)).build();
	}
}
