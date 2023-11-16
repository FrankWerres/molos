# molos - My Own Little OIDC Server
This project wants to supply a replacement for an actual OIDC server (like e.g. KeyCloak) suitable to support test and development of OIDC client applications.

The approach is to selectively support flows encountered during development of a secured application.

Currently implemented:

*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsBasic and its verification on the server side
*   retrieving an access token for a 'Client Credentials Grant' transferred via ClientCredentialsPost and its verification on the server side

