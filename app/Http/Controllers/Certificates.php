<?php

namespace App\Http\Controllers;

use App\Helpers;
use Psr\Http\Message\ServerRequestInterface;
use eIDASCertificate\Certificate\X509Certificate;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Nyholm\Psr7\Factory\Psr17Factory;

class Certificates extends Controller
{
    private $dataDir;

    const maxUpload = 10240;
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->dataDir = __DIR__.'/../../../data/';
        $this->response = new Response();
        Helpers::mkdir($this->dataDir.'certs/');
        Helpers::mkdir($this->dataDir.'CAs/');
        Helpers::mkdir($this->dataDir.'SKIs/');
    }

    public function getCertificate(ServerRequestInterface $request, $certificateId = null)
    {
      $certDir = $this->dataDir .'certs/';
      if (file_exists($certDir.$certificateId.'.crt')) {
        $crtFile = \file_get_contents($certDir.$certificateId.'.crt');
        $crt = new X509Certificate($crtFile);
        $accept = explode(',',$request->getHeaderLine('Accept'))[0];
        switch ($accept) {
          case 'application/json':
            $response = $this->response->withStatus(200);
            $response = $response->withHeader('Content-Type','application/json');
            $body = json_encode($crt->getAttributes(), JSON_PRETTY_PRINT);
            $responseBody = Stream::create($body);
            $response = $response->withBody($responseBody);
            break;

          default:
            $response = $this->response->withStatus(406);

            break;
        }
      } else {
        $response = $this->response->withStatus(404);
        $response = $response->withHeader('Content-Type','application/json');
        $body = json_encode(['error' => 'Not Found']);
        $responseBody = Stream::create($body);
        $response = $response->withBody($responseBody);
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
        if ($request->hasHeader('content-type')) {
          $ct = strtolower($request->getHeaderLine('content-type'));
        }
        $ct = explode(';',$ct)[0];
        switch ($ct) {
          case 'application/x-www-form-urlencoded':
            if ($request->getBody()->getSize() >= 10) {
              return $this->respondError(400,'Too much data arrived, is this really a certificate?');
            }
            if(substr((string)$request->getBody(),0,27) == '-----BEGIN CERTIFICATE-----')
            break;
          case 'multipart/form-data':
            if (sizeof($request->getUploadedFiles()) > 1) {
              return $this->respondError(400,'Only one candidate certificate at a time');
            } elseif (sizeof($request->getUploadedFiles()) == 0) {
              return $this->respondError(400,'No file uploaded');
            }
            if (sizeof($request->getUploadedFiles()) == 1) {
              if (current($request->getUploadedFiles())->getSize() >= self::maxUpload) {
                return $this->respondError(400,'Too much data arrived, is this really a certificate?');
              }
              $filename = array_keys($request->getUploadedFiles())[0];
              $candidate = stream_get_contents(current($request->getUploadedFiles())->getStream()->detach());
            }
            // code...
            break;

          default:
          return $this->respondError(400,'Could not understand the request');

            break;
        }
        try {
          $candidate = new X509Certificate($candidate);
        } catch (\Exception $e) {
          return $this->respondError(400,"Could not parse input as a certificate: ".$e->getMessage());
        }
        try {

          $this->persistCertificate($candidate);
        } catch (\Exception $e) {
          return $this->respondError(500,'Cannot persist certificate');

        }

        $crtId = $candidate->getIdentifier();
        $getPath = "/certificates/$crtId?fromPost=true";
        $response = $this->response->withStatus(302);
        $response = $response->withHeader('Location',$getPath);
        return self::respond($response);

    }

    public function persistCertificate($crt)
    {
        $crtId = $crt->getIdentifier();
        $crtPath = $this->crtDir.$crt->getIdentifier().'.crt';
        if (file_exists($crtPath)) {
            return false;
        }
        file_put_contents($crtPath,$crt->toPEM());
        return true;
    }

    private function respond($response)
    {
      return (new HttpFoundationFactory())->createResponse($response);
    }

    public function respondError($code, $errorMsg)
    {
      $response = $this->response->withStatus($code);
      $response = $response->withHeader('Content-Type','application/json');
      $body = json_encode(["error" => $errorMsg]);
      $responseBody = Stream::create($body);
      $response = $response->withBody($responseBody);
      return (new HttpFoundationFactory())->createResponse($response);
    }
    //
}
