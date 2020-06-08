<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/



$router->get('/', function () use ($router) {
    return $router->app->version();
});

$router->get('/version', function () use ($router) {
    return $router->app->version();
});

$router->get('/info', function () use ($router) {
    return phpinfo();
});

$router->get('/certificates', 'Certificates@getCertificates');

$router->get('/certificates/{certificateId}', 'Certificates@getCertificate');
$router->post('/certificates/', 'Certificates@postCertificates');

$router->get('/trusted-lists/{trustedListId}', 'TrustedLists@getTrustedList');
$router->get('/trust-service-providers/{tspId}', 'TrustServiceProviders@getTSP');
