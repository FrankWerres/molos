# molos - My Own Little OIDC Server
This project wants to supply a replacement for an actual OIDC server (like e.g. KeyCloak) suitable to support test and development of OIDC client applications.

The approach is to selectively support flows encountered during development of a secured application.


## Currently implemented:

### Client authentication, OAuth2: Verifying a shared secret in order to recognize legitimate clients, where clients are software installations, not individuals!

*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsBasic and its verification on the server side
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsPost and its verification on the server side

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
