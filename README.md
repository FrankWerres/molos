# molos - My Own Little OIDC Server
This project wants to supply a replacement for an actual OIDC server (like e.g. KeyCloak) suitable to support test and development of OIDC client applications.

The approach is to selectively support flows encountered during development of a secured application.


## Currently implemented:

### Client authentication: Verifying a secret shared only with the IP in order to recognize legitimate clients (clients are software installations, not individuals!)

*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsBasic and its verification on the server side by calling the issuer
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsPost and its verification on the server side by calling the issuer
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientSecretJWT and its verification on the server side by calling the issuer

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

### Client authentication: Client retrieves a signed access token carrying role information that can be verified on the server locally (clients are software installations, not individuals!)

```mermaid
sequenceDiagram
participant Client
participant Server
participant OAuth-/Identityprovider
note over OAuth-/Identityprovider: Holds ClientID/-Secret
note over Client,Server: No more shared knowledge
Client->>OAuth-/Identityprovider: I'm <ClientID> and I know <ClientSecret><br/>I need an AccessToken identifying my rights.
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Client: Here is your <AccessToken>!
deactivate OAuth-/Identityprovider
Client->>Server: Here's my <AccecssToken><br/>telling what I'm allowed to do,<br/>please do X for me!
activate Server
opt Keys not yet known
Server->>OAuth-/Identityprovider: Please give me your public key<br/>to verify your signature
activate OAuth-/Identityprovider
OAuth-/Identityprovider->>Server: Here you are!
deactivate OAuth-/Identityprovider
end
Server->>Server: verify <AccessToken> and <br/>included rights
Server->>Server: do X
Server->>Client: I did X!
deactivate Server
```

### User authentication: Verifying userId/password for a user account in order to recognize legitimate users (individuals!)

* this works by (mis-)using the ResourceOwnersPasswordCredentialsGrant from a legitimate client installation



## Latest improvements
* added IDToken to token response
* supporting OIDC flow where the server side does not need to know the clientID/clientSecret credentials
* Replacing hand-written server-side code with actual standard-compliant server 

## Coming next
* add RefreshToken to the token response
