# sample-angularjs-spa
Demo AngularJS single-page app that uses the OpenID Connect Implicit profile for authentication.


### Overview

I used this sample to learn AngularJS so it is probably not the best example of Javascript or Angular, however it demonstrates using OpenID Connect to authenticate a user and display their tokens and the results of a request to the userinfo endpoint.


### Requirements

The app uses PingFederate as the OpenID Connect OP. You should be able to stand up a PingFederate server with the OAuth Playground, configure the redirect URI in the im_client or im_oidc_client and point this application at that server. You can grab a developer license for PingFederate from the [Ping Identity Developer Site].

This also uses the following libraries:
- JSRSASIGN for crypto (validating signatures, creating hashs)
- AngularJS for .. you know.. the Angular stuff
- Bootstrap for making it look pretty


### Installation

1. Drop this app into a web container
2. Add angular.min.js, bootstrap.min.js and jsrsasign-latest-min.js into the assets/js folder
3. Install PingFederate and the OAuth Playground
4. Modify the im_client and set a redirect_uri to this app
5. Modify the app.js and set the issuer to your PingFederate server and the redirect_uri to this app

**Note**: You may need to tweak some PingFederate files because of CORS (the JS app will get the openid-configuration file as well as call the userinfo endpoint). This can be configured by following this tech article: https://ping.force.com/Support/PingIdentityArticle?id=kA340000000TNuPCAW


### Disclaimer

This is sample software, and is not supported commercially by myself or my employer (Ping Identity). Any questions/issues should go to the Github issues tracker or discuss on the [Ping Identity developer communities] . See also the DISCLAIMER file in this directory.

[Ping Identity developer communities]: https://community.pingidentity.com/collaborate
[Ping Identity Developer Site]: https://developer.pingidentity.com/getstarted