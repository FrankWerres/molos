# molos - My Own Little OIDC Server
This project wants to supply a replacement for an actual OIDC server (like e.g. KeyCloak) suitable to support test and development of OIDC client applications.

The approach is to selectively support flows encountered during development of a secured application, the first being retrieving an access token for a 'Client Credentials Grant' and its verification on the server side.