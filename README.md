# molos - My Own Little OIDC Server
This project wants to supply a replacement for an actual OIDC server (like e.g. KeyCloak) suitable to support test and development of OIDC client applications.

The approach is to selectively support flows encountered during development of a secured application.


## Currently implemented:

### Client authentication, OAuth2: Verifying a shared secret in order to recognize legitimate clients (clients are software installations, not individuals!)

*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsBasic and its verification on the server side
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsPost and its verification on the server side
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientSecretJWT and its verification on the server side

```mermaid
sequenceDiagram
participant Client
participant Server
participant OAuth-/Identityprovider
note over OAuth-/Identityprovider: Holds ClientID/-Secret
note over Client,Server: Shared knowledge:<br/>ClientID/-Secret<br/>administered in<br/> OAuth-/Identityprovider
Client->>OAuth-/Identityprovider: I'm <ClientID> and I know <ClientSecret><br/>I need an AccessToken to verify this.
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Client: Here is your <AccessToken>!
deactivate OAuth-/Identityprovider
Client->>Server: Here's my <AccessToken>,<br/>please do X for me!
activate Server
Server->>OAuth-/Identityprovider: I'm <ClientID> and I know <ClientSecret>,<br/>Is <AccessToken> valid for me?
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Server: Yes!
deactivate OAuth-/Identityprovider
Server->>Server: do X
Server->>Client: I did X!
deactivate Server
```

### Client authentication, OIDC: Client retrieves a signed id token that can be verified on the server locally (clients are software installations, not individuals!)

```mermaid
sequenceDiagram
participant Client
participant Server
participant OAuth-/Identityprovider
note over OAuth-/Identityprovider: Holds ClientID/-Secret
note over Client,Server: No more shared knowledge
Client->>OAuth-/Identityprovider: I'm <ClientID> and I know <ClientSecret><br/>I need an IDToken to verify this.
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Client: Here is your <IDToken>!
deactivate OAuth-/Identityprovider
Client->>Server: Here's my <IDToken>,<br/>please do X for me!
activate Server
opt Keys not yet known
Server->>OAuth-/Identityprovider: Please give me public key<br/>to verify your signature
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Server: Here you are!
deactivate OAuth-/Identityprovider
end
Server->>Server: verify <IDToken>
Server->>Server: do X
Server->>Client: I did X!
deactivate Server
```

## Latest improvements
* added IDToken to token response
* supporting OIDC flow where the server side does not need to know the clientID/clientSecret credentials

## Coming next
* add RefreshToken to the token response
* Replacing hand-written server-side code with actual standard-compliant server 
