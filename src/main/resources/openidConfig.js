/*
 * Copyright (C) 2015 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * Config block which registers OAuth-specific field types.
 */
angular.module('guacOpenID').config(['formServiceProvider',
    function guacOpenIDConfig(formServiceProvider) {

        // Define field for token from OpenID service
        formServiceProvider.registerFieldType("GUAC_OPENID_TOKEN", {
            template: 'null',
            controller: 'guacOpenIDController',
            module: 'guacOpenID'
        });

    }]);

/**
 * Config block which augments the existing routing, providing special handling
 * for the "id_token=" fragments provided by OpenID Connect.
 */
// angular.module('index').config(['$routeProvider',
//         function indexRouteConfig($routeProvider) {
//
//     Transform "/#/id_token=..." to "/#/?id_token=..."
    // $routeProvider.when('/id_token=:response', {
    //
    //     template   : '',
    //     controller : ['$location', function reroute($location) {
    //         var params = $location.path().substring(1);
    //         $location.url('/');
    //         $location.search(params);
    //     }]
    //
    // });
//
// }]);
