(function () {
    
    var app = angular.module('LoginService', [ ]);

    
    // ---------- NotificationService
    // Simple notification service - sets the banner on the main view
    app.service('NotificationService', [ '$rootScope', function($rootScope) {
        
        var notification = this;
        var notificationLifetimeInSeconds = 5;
    
        this.setNotification = function(severity, message) {

            notification.message = message;
            notification.severity = severity;
            
            var now = new Date();
            var expires = now.getSeconds() + notificationLifetimeInSeconds;
            
            notification.expiry = now.setSeconds(expires);
            $rootScope.$broadcast("NotificationUpdate");
        }
        
        this.clearNotification = function() {

            notification = null;
        }
        
    }])
    
    // ---------- StorageHelper
    // General local storage helper (could modify to use cookies or persistent storage as needed)
    app.factory('StorageHelper', function ($window, Utils) {
    
        var storageKeyPrefix = "com.pingidentity.developer.js-app";
        
        return {
            storeData: function(itemKey, itemValue) {

                $window.sessionStorage.setItem(storageKeyPrefix + "." + itemKey, JSON.stringify(itemValue));
                return this;
            },
            retrieveData: function(itemKey) {
                
                var retrievedData = $window.sessionStorage.getItem(storageKeyPrefix + "." + itemKey);
                return Utils.isNothing(retrievedData) ? undefined : JSON.parse(retrievedData);
            },
            clearData: function(itemKey) {
                
                $window.sessionStorage.removeItem(storageKeyPrefix + "." + itemKey);
                return this;
            }
        };
    })

    
    // ---------- HttpHelper
    // General Http helper factory
    app.factory('HttpHelper', function($http, $q) {

        //TODO: Handle http headers
        
        return {
            postData: function(destinationUrl, postData, headers) {

                var deferred = $q.defer();
            
                $http.defaults.headers.post = { 'Content-Type': 'application/x-www-form-urlencoded' };
                $http.post(destinationUrl, postData).success(function (data) {
                    deferred.resolve(data);
                }).error(function (data, status) {
                    deferred.reject(status);
                });
                
                return deferred.promise;
            },
            
            getData: function(destinationUrl, headers) {
                
                var deferred = $q.defer();

                $http.get(destinationUrl).success(function (data) {
                    deferred.resolve(data);
                }).error(function (data, status) {
                    deferred.reject(status, data);
                });
            
                return deferred.promise;
            },
            
            getDataWithAccessToken: function(destinationUrl, access_token) {
                
                var deferred = $q.defer();

                var bearerAuthorizationHeader = "Bearer " + access_token;
                $http.defaults.headers.get = { 'Authorization': bearerAuthorizationHeader };
                
                $http.get(destinationUrl).success(function (data) {
                    deferred.resolve(data);
                }).error(function (data, status) {
                    deferred.reject(status, data);
                });
            
                return deferred.promise;
            }
        }
    })
    
    
    // ---------- Utils
    // General utils
    app.service('Utils', [ '$rootScope', 'NotificationService', function($rootScope, NotificationService) {
        
        this.isNothing = function(value) {
        
            return (value == null);
        }
        
        this.generateHash = function(hashAlgorithm, valueToHash) {
        
            var md = new KJUR.crypto.MessageDigest({"alg": hashAlgorithm, "prov": "cryptojs"});
            return md.digestString(valueToHash.toString());
        }
        
        this.postNotification = function(severity, message) {
            
            NotificationService.setNotification(severity, message);
            $rootScope.$broadcast('NotificationUpdate');
        }
        
        this.formatQueryString = function(queryParameters) {
        
            var queryString = [];
            
            for (var k in queryParameters) {
                var v = queryParameters[k];
                queryString.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
            }
            
            return queryString.join("&");
        }
        
    }])
    
    
    app.service('OIDCIdToken', [ '$log', '$q', 'HttpHelper', 'Utils', function($log, $q, HttpHelper, Utils) {
        
        // ---------- parse
        // Parse the encoded id_token
        this.parse = function(encodedJwt) {

            var parsedJwt = {};
            parsedJwt.rawToken = encodedJwt;
            
            var jwtComponents = encodedJwt.split('\.');
            parsedJwt.jsonHeader = JSON.parse(atob(jwtComponents[0]));
            parsedJwt.jsonPayload = JSON.parse(atob(jwtComponents[1]));
            
            parsedJwt.signingAlgorithm = parsedJwt.jsonHeader.alg;
            parsedJwt.signingKeyIdentifier = parsedJwt.jsonHeader.kid;
            parsedJwt.signingKeyType = parsedJwt.signingAlgorithm.substr(0,2);
            if (parsedJwt.signingKeyType == "RS") { parsedJwt.signingKeyType = "RSA" };
            parsedJwt.signingKeyHashAlgorithm = "sha" + parsedJwt.signingAlgorithm.substring(2);
            
            parsedJwt.issuer = parsedJwt.jsonPayload.iss;
            parsedJwt.audience = parsedJwt.jsonPayload.aud;
            parsedJwt.id = parsedJwt.jsonPayload.jti;
            
            var iss_ms = Number(parsedJwt.jsonPayload.iat)*1000;
            parsedJwt.issuedAt = new Date(iss_ms);
            
            var exp_ms = Number(parsedJwt.jsonPayload.exp)*1000;
            parsedJwt.expiresAt = new Date(exp_ms);

            //OpenID Connect specific
            parsedJwt.sub = parsedJwt.jsonPayload.sub;
            parsedJwt.nonce = parsedJwt.jsonPayload.nonce;
            parsedJwt.at_hash = parsedJwt.jsonPayload.at_hash;
         
            return parsedJwt;
        }
        
        
        // ---------- getClaim
        // Returns the specified claim value from the id_token
        this.getClaim = function(decodedJwt, claim) {
        
            return decodedJwt.jsonPayload[claim];
        }
        
        
        // ---------- validateIdTokenSignature
        // Validates the id_token digital signature (used as part of id_token verification)
        this.validateDigitalSignature = function(decodedJwt, jwks_uri) {
            
            var deferred = $q.defer();

            // Get the JWKS first
            HttpHelper.getData(jwks_uri)
            .then( function(data) {

                // Find the signing key from the JWKS
                var jwk = {};
                
                data.keys.some( function(value, index, _dataKeys) {
                    if (value.kty == decodedJwt.signingKeyType && value.kid == decodedJwt.signingKeyIdentifier) {
                        jwk = value;
                        return true;
                    } else {
                        return false;
                    }
                })

                // Validate the dsig (uses the JSRASIGN library)
                var verificationCertificate = KEYUTIL.getKey(jwk);
                var isValid = KJUR.jws.JWS.verify(decodedJwt.rawToken, verificationCertificate, [ "RS256" ]);
                
                if(Boolean(isValid)) {
                    deferred.resolve("Digital signature verification passed");
                } else {
                    deferred.reject("Digital signature verification failed");
                }
            })

            return deferred.promise;
        }

        
        // ---------- validate
        // Validates the id_token according to Implicit Profile
        this.validate = function(decodedJwt, issuer, access_token, requestParameters, jwks_uri) {

            var deferred = $q.defer();

            this.validateDigitalSignature(decodedJwt, jwks_uri)
            .then( function(data) {

                var isValid = true;
                
                // verify issuer
                if (issuer !== decodedJwt.issuer) {
                    deferred.reject("Issuer does not match: " + issuer + " vs " + decodedJwt.issuer);
                    isValid = false;
                }
            
                // verify audience
                if (requestParameters.client_id !== decodedJwt.audience) {
                    deferred.reject("Audience does not match: " + requestParameters.client_id + " vs " + decodedJwt.audience);
                    isValid = false;
                }

                var now = new Date();
                // verify current time < expiry
                if(now > decodedJwt.expiresAt) {
                    deferred.reject("Token has expired: " + now + " > " + decodedJwt.expiresAt)
                    isValid = false;
                }

                // verify iat < current time
                if(now < decodedJwt.issuedAt) {
                    deferred.reject("Token hasn't been issued yet: " + now + " < " + decodedJwt.issuedAt)
                    isValid = false;
                }

                // verify nonce
                if (requestParameters.nonce !== decodedJwt.nonce) {
                    deferred.reject("Nonce does not match: " + requestParameters.nonce + " vs " + decodedJwt.nonce);
                    isValid = false;
                }

                // verify acr
                if (!Utils.isNothing(requestParameters.acr_values)) {
                    if (requestParameters.acr_values !== decodedJwt.acr) {
                        deferred.reject("acr_values mismatch: " + requestParameters.acr_values + " vs " + decodedJwt.acr);
                        isValid = false;
                    }
                }

                // verify at_hash
                var hashValue = Utils.generateHash(decodedJwt.signingKeyHashAlgorithm, access_token);
                var leftMost = hashValue.substring(0, 32);
                var b64Encoded = b64tob64u(hextob64(leftMost));

                if (b64Encoded !== decodedJwt.at_hash) {
                    deferred.reject("at_hash is not valid: " + b64Encoded + " vs " + decodedJwt.at_hash);
                    isValid = false;
                }
                
                if (isValid) {
                    deferred.resolve("id_token is valid");
                } else {
                    deferred.reject("id_token is invalid");
                }
                
            }, function(reason) {
                deferred.reject(reason);
            })
            
            return deferred.promise;
        }
        
    }]);
        
    app.service('OpenIDConnectService', [ '$log', '$rootScope', '$window', 'StorageHelper', 'HttpHelper', 'OIDCIdToken', 'Utils', function ($log, $rootScope, $window, StorageHelper, HttpHelper, OIDCIdToken, Utils) {
        
        var OpenIDConnectServiceStorageKey = "OpenIDConnectService";
        var OpenIDConnectUserStorageKey = "OpenIDConnectUser";
        var OpenIDConnectRequestStorageKey = "OpenIDConnectRequest";

        // Check for a cached copy of the AS information (rather than grabbing the discovery document every time)
        var OpenIDConnectProvider = StorageHelper.retrieveData(OpenIDConnectServiceStorageKey);
        
        if(Utils.isNothing(OpenIDConnectProvider)) {
            OpenIDConnectProvider = {};
        }

        // Check for a local user session
        var OpenIDConnectUser = StorageHelper.retrieveData(OpenIDConnectUserStorageKey);

        if(Utils.isNothing(OpenIDConnectUser)) {
            OpenIDConnectUser = {}
            OpenIDConnectUser.tokens = {};
        }

        
        // ---------- setCurrentUser
        // Sets / updates the current user
        this.setCurrentUser = function(id_token, access_token, expires_in) {

            var jwtIdToken = OIDCIdToken.parse(id_token);
            var request = StorageHelper.retrieveData(OpenIDConnectRequestStorageKey);
            
            OIDCIdToken.validate(jwtIdToken, request.issuer, access_token, request.queryParameters, OpenIDConnectProvider.jwks_uri)
            .then(function(result) {
                
                OpenIDConnectUser = {};
                OpenIDConnectUser.sub = OIDCIdToken.getClaim(jwtIdToken, "sub");

                // Calculate the access token expiry (add "expires_in" seconds to the current time)
                var now = new Date();
                var secondsToAdd = now.getSeconds() + parseInt(expires_in);
                now.setSeconds(secondsToAdd);
            
                OpenIDConnectUser.tokens = {
                    access_token: access_token,
                    id_token: id_token,
                    expires_at: now
                };
                
                OpenIDConnectUser.decodedIdToken = jwtIdToken;
                StorageHelper.storeData(OpenIDConnectUserStorageKey, OpenIDConnectUser);
                
                $rootScope.$broadcast('OIDCUserStateChanged');
                Utils.postNotification("info", "Successfully signed in");
                
            }, function(reason) {
                Utils.postNotification("danger", "Failed to validate id_token (" + reason + ")");
            })
        }
        

        // ---------- getCurrentUser
        // Returns the current user
        this.getCurrentUser = function() {
            
            if (Utils.isNothing(OpenIDConnectUser)) {
                OpenIDConnectUser = StorageHelper.retrieveData(OpenIDConnectUserStorageKey);
            }
            return OpenIDConnectUser;
        }

        
        // ---------- clearCurrentUser
        // Clears the current user (logs out of the local application)
        this.clearCurrentUser = function() {
            
            OpenIDConnectUser = null;
            StorageHelper.clearData(OpenIDConnectUserStorageKey);
            $rootScope.$broadcast('OIDCUserStateChanged');
        }

        
        // ---------- isAuthorized
        // Checks whether the user is currently authorized (ie has an access token)
        this.isAuthorized = function() {
                
            if (!Utils.isNothing(OpenIDConnectUser)) {
                return (!Utils.isNothing(OpenIDConnectUser.tokens.access_token));
            } else {
                return false;
            }
        }
        
        
        // ---------- getUserProfile
        // Call the OpenID Connect UserInfo endpoint to retrieve the user profile
        this.getUserProfile = function() {
                
            var userInfoPromise = HttpHelper.getDataWithAccessToken(OpenIDConnectProvider.userinfo_endpoint, OpenIDConnectUser.tokens.access_token);
            
            userInfoPromise.then( function(data) {

                if (data.sub !== OpenIDConnectUser.sub) {
                    Utils.postNotification("danger", "Subject from userinfo does not match id_token subject!");
                } else {
                    OpenIDConnectUser.profile = data;
                    Utils.postNotification("info", "Refreshed UserInfo from OpenID Connect provider");
                }
            }, function(status, data) {
                
                Utils.postNotification("danger", "Error refreshing UserInfo from OpenID Connect provider (" + status + ")");
            });
        }
        
        
        // ---------- generateAuthorizationRequestUrl
        // Creates an authorization request and returns the URL
        this.generateAuthorizationRequestUrl = function(issuer, client_id, scope, redirect_uri, additionalParameters) {

            var OIDCRequest = {};
            OIDCRequest.issuer = issuer;
            OIDCRequest.audience = client_id;
            
            var queryParameters = {};

            // OpenID Connect Implicit Profile
            queryParameters.response_type = "token id_token";
                
            // client_id and redirect_uri are configured above
            queryParameters.client_id = client_id;
            queryParameters.redirect_uri = redirect_uri;
            queryParameters.scope = scope;

            var state = Utils.generateHash("sha256", Math.random());
            queryParameters.state = state;

            var nonce = Utils.generateHash("sha256", (new Date).getTime());
            queryParameters.nonce = nonce;

            for (var k in additionalParameters) {
                var v = additionalParameters[k];
                queryParameters[k] = v;
            }

            OIDCRequest.queryParameters = queryParameters;
            StorageHelper.storeData(OpenIDConnectRequestStorageKey, OIDCRequest);

            var authorizationUrl = OpenIDConnectProvider.authorization_endpoint;
            authorizationUrl += "?" + Utils.formatQueryString(queryParameters);
        
            return authorizationUrl;
        }

        
        // ---------- generateAuthorizationRequest
        // Creates an authorization request and redirects the browser
        this.generateAuthorizationRequest = function(issuer, client_id, scope, redirect_uri, additionalParameters) {

            var authorizationUrl = this.generateAuthorizationRequestUrl(issuer, client_id, scope, redirect_uri, additionalParameters);

            $log.debug("Authorizing user at: " + authorizationUrl);
            $window.location.href = authorizationUrl;
        }

        
        // ---------- processAuthorizationCallback
        // Processes the url fragment received after an authorization request
        this.processAuthorizationCallback = function(fragment) {

            if(fragment == "_") { return; }
            
            var fragmentParameters = fragment.split('&');
            var fragmentComponents = {};
        
            for( i = 0; i < fragmentParameters.length; i++ ) {
                var thisComponent = fragmentParameters[i].split('=');
                fragmentComponents[thisComponent[0]]  = thisComponent[1];
            }
                
            $window.location.hash = '#_';

            if (!Utils.isNothing(fragmentComponents.error)) {

                Utils.postNotification("danger", "Error encountered during login: " + fragmentComponents.error);
                this.clearCurrentUser();

            } else if (Object.keys(fragmentComponents).length != 1) {

                // Successful response
                this.setCurrentUser(fragmentComponents.id_token, fragmentComponents.access_token, fragmentComponents.expires_in);

            } else {

                Utils.postNotification("danger", "Error encountered during login: No tokens found");
                this.clearCurrentUser();
            }
        };
        
        
        // ---------- revokeAccessToken
        // Revokes the current access_token at the authorization server as per RFC7009
        this.revokeAccessToken = function(client_id) {

            var postDataParameters = {};
            postDataParameters.client_id = client_id;
            postDataParameters.token = OpenIDConnectUser.tokens.access_token;
            postDataParameters.token_type_hint = "access_token";
            
            var postData = Utils.formatQueryString(postDataParameters);
            var revocationPromise = HttpHelper.postData(OpenIDConnectProvider.revocation_endpoint, postData, null);
            
            revocationPromise.then( function(data) {
                Utils.postNotification("info", "Revoked access token at OAuth authorization server");
            }, function(status, data) {
                Utils.postNotification("danger", "Error encountered during token revocation (" + status + ")");
            });
        };
        
        
        // ---------- configureProvider
        // Configures the OpenID Connect provider by reading the discovery document
        this.configureProvider = function(issuer) {

            var configurationUrl = issuer + "/.well-known/openid-configuration"
            var discoveryPromise = HttpHelper.getData(configurationUrl, null);
            
            discoveryPromise.then( function(data) {
                
                OpenIDConnectProvider = data;
                StorageHelper.storeData(OpenIDConnectServiceStorageKey, OpenIDConnectProvider);
                
            }, function(status, data) {
                Utils.postNotification("danger", "Error: Could not configure OpenID Connect Provider (" + data + ")");
            })
        }
        
        // ---------- clearProvider
        // Removes the caches AS information from localStorage
        this.clearProvider = function() {
            
            OpenIDConnectProvider = null
            StorageHelper.clearData(OpenIDConnectServiceStorageKey);
        }
        
    }]);
    
})();
