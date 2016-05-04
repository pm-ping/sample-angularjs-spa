(function () {
    
    var app = angular.module('OpenIDConnectDemoApp', [ 'LoginService' ]);
    
    app.config(function($locationProvider) {
        $locationProvider.html5Mode(true).hashPrefix('!');
    });
    
    app.filter('prettyprintjson', function($sce) {

        return function(input) {
            return (input) ? $sce.trustAsHtml("<pre>" + JSON.stringify(input, null, "    ") + "</pre>") : input;
        }
    })
    
    app.filter('formatJWT', function($sce) {
        
        return function(input) {
            
            if (input == undefined) { return input; }
            
            if ((input.match(/\./g) || []).length == 2) {
                
                var jwtComponents = input.split('.');
            
                var formattedJwt = "<pre><span class='text-info'>" + jwtComponents[0] + "</span>";
                formattedJwt += "<br/>.<br/><span class='text-danger'>" + jwtComponents[1] + "</span>";
                formattedJwt += "<br/>.<br/><span class='text-muted'>" + jwtComponents[2] + "</span></pre>";
                formattedJwt += "<p>&nbsp;</p>"
                formattedJwt += "<pre><span class='text-info'>" + JSON.stringify(JSON.parse(atob(jwtComponents[0])), null, "    ") + "</span>";
                formattedJwt += "<br/>.<br/><span class='text-danger'>" + JSON.stringify(JSON.parse(atob(jwtComponents[1])), null, "    ") + "</span>";
                formattedJwt += "<br/>.<br/><span class='text-muted'>[Signature]</span></pre>";
            
                return $sce.trustAsHtml(formattedJwt);
            } else {

                return input;
            }
        }
    })
    
    app.directive('pingNotificationPanel', function () {
  
        return {
            restrict: 'E',
            templateUrl: 'pingNotificationPanel.html'
        };
    });

    app.directive('reloginDialog', function () {
  
        return {
            restrict: 'E',
            templateUrl: 're-login-form.html'
        };
    });
    
    app.controller('ApplicationController', [ '$log', '$scope', '$location', '$sce', '$timeout', 'OpenIDConnectService', 'NotificationService', function($log, $scope, $location, $sce, $timeout, OpenIDConnectService, NotificationService) {
      
        // Application configuration for OpenID Connect
        var issuer = "http://sso.pingdevelopers.com:9030";
        var client_id = "im_client";
        var redirect_uri = "http://sso.pingdevelopers.com:8888/js-app";
        var scope = "openid profile email";
        var additionalParameters = {};
        
        // Configure the OpenID Connect Provider
        OpenIDConnectService.configureProvider(issuer);

        // Process any OIDC callback
        if ($location.hash() !== "") {
            OpenIDConnectService.processAuthorizationCallback($location.hash());
        }

        // event to handle changes to the user state (ie sign in, sign out)
        $scope.$on('OIDCUserStateChanged', function () {
            
            $scope.currentUser = OpenIDConnectService.getCurrentUser();
            $scope.isLoggedOn = OpenIDConnectService.isAuthorized();
        });
        
        // event to display any notifications
        $scope.$on('NotificationUpdate', function() {

            if (NotificationService !== null) {
                $scope.hasNotification = true;
                $scope.notificationSeverity = NotificationService.severity;
                $scope.notificationMessage = NotificationService.message;
            }
        })
            
        
        // action to handle sign out request
        $scope.signout = function() {
            
            OpenIDConnectService.clearCurrentUser();
            NotificationService.setNotification("info", "User signed out of application");
            $scope.$broadcast('NotificationUpdate');
        };


        // action to handle sign in request (ensure configuration is updated above)
        $scope.signin = function() {
            
            OpenIDConnectService.generateAuthorizationRequest(issuer, client_id, scope, redirect_uri, additionalParameters);
        };

        // action to handle sign in request in the background (via iFrame)
        $scope.signinBackground = function() {

            additionalParameters["prompt"] = "none";
            $scope.authorizationUrl = $sce.trustAsResourceUrl(OpenIDConnectService.generateAuthorizationRequestUrl(issuer, client_id, scope, redirect_uri, additionalParameters));
            $scope.backgroundSignInAction = true;
        };
        
        // action to revoke the users access token (RFC7009)
        $scope.revokeAccessToken = function() {
            
            OpenIDConnectService.revokeAccessToken(client_id);
        }
        
        // action to call the userinfo endpoint to retrieve the OIDC profile
        $scope.refreshUserInfo = function() {
            
            OpenIDConnectService.getUserProfile();
        }
        
        $scope.refreshUI = function() {
            $timeout( function() {
                $scope.currentUser = OpenIDConnectService.getCurrentUser();
            }, 100)
            .then( function() {
                NotificationService.setNotification("info", "Updated UI");
                $scope.$broadcast('NotificationUpdate');
            })
        }
        
    }]);
    
})();