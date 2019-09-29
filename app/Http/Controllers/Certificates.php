<?php

namespace App\Http\Controllers;

use Psr\Http\Message\ServerRequestInterface;
use eIDASCertificate\Certificate\X509Certificate;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Nyholm\Psr7\Factory\Psr17Factory;

class Certificates extends Controller
{
    private $dataDir;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->dataDir = $certDir = __DIR__.'/../../../data/';
        $this->response = new Response();
    }

    public function getCertificate(ServerRequestInterface $request, $certificateId = null)
    {
      $certDir = $this->dataDir .'certs/';
      if (file_exists($certDir.$certificateId.'.crt')) {
        $certFile = \file_get_contents($certDir.$certificateId.'.crt');
        $cert = new X509Certificate($certFile);
        $accept = explode(',',$request->getHeaderLine('Accept'))[0];
        switch ($accept) {
          case 'application/json':
            $response = $this->response->withStatus(200);
            $response = $response->withHeader('Content-Type','application/json');
            $attributes = $cert->getAttributes();
            $responseBody = Stream::create(json_encode($attributes));
            $response = $response->withBody($responseBody);
            break;

          default:
            $response = $this->response->withStatus(406);
            break;
        }
      } else {
        $response = $this->response->withStatus(404);
      }
      return self::respond($response);
    }

    public function getCertificates(ServerRequestInterface $request)
    {
      $response = $this->response->withStatus(201);
      return self::respond($response);
    }

    public function postCertificate(ServerRequestInterface $request)
    {
      $uploadedData = stream_get_contents($request->getBody()->detach(),10240);
      try {
        $cert = new X509Certificate($uploadedData);
      } catch (\Exception $e) {
        $response = $this->response->withStatus(400);
        $responseBody = Stream::create(json_encode(['Error' => $e->getMessage(), $request->getUploadedFiles(), $uploadedData]));
        $response = $response->withBody($responseBody);
        return self::respond($response);
      }
      $id = $cert->getIdentifier();
      if (! self::isKnown($id)) {
        $pem = $cert->toPEM();
        $id = $cert->getIdentifier();
        $response = $this->response->withStatus(201);
      } else {
        $response = $this->response->withStatus(200);
      }
      $response = $response->withHeader(
        'Location',
        '/certificates/'.$id.'?from_post=true'
      );
      return self::respond($response);
    }

    private function respond($response)
    {
      $newResponse = (new HttpFoundationFactory())->createResponse($response);
      return $newResponse;
    }

    private function isKnown($id)
    {
      $certDir = $this->dataDir .'certs/';
      return in_array($id,scandir($certDir));
    }
}
