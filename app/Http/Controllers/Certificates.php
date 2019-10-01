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
            $body = json_encode($crt->getAttributes());
            $responseBody = Stream::create($body);
            $response = $response->withBody($responseBody);
            break;

          default:
            $response = $this->response->withStatus(406);

            break;
        }
        return self::respond($response);
      } else {
        return "bar ".$certDir.$certificateId.'.crt';
      }
    }

    public function getCertificates(ServerRequestInterface $request)
    {
      $response = $this->response->withStatus(201);
      return self::respond($response);
    }

    public function postCertificate(ServerRequestInterface $request)
    {
        if (sizeof($request->getUploadedFiles()) > 1) {
          $response = $this->response->withStatus(400);
          $response = $response->withHeader('Content-Type','application/json');
          $body = json_encode(["error" => 'Only one candidate certificate at a time']);
          $responseBody = Stream::create($body);
          $response = $response->withBody($responseBody);
          return self::respond($response);
        }
        $filename = array_keys($request->getUploadedFiles())[0];
        if ($request->getUploadedFiles()[$filename]->getSize() > 10241) {
          $response = $this->response->withStatus(400);
          $response = $response->withHeader('Content-Type','application/json');
          $body = json_encode(["error" => 'Too much data arrived, is this really a certificate?']);
          $responseBody = Stream::create($body);
          $response = $response->withBody($responseBody);
          return self::respond($response);
        }
        $uploadedData = stream_get_contents($request->getUploadedFiles()[$filename]->getStream()->detach(),10240);
        try {
          $candidate = new X509Certificate($uploadedData);
        } catch (\Exception $e) {
          $response = $this->response->withStatus(400);
          $response = $response->withHeader('Content-Type','application/json');
          $body = json_encode(["error" => $e->getMessage()]);
          $responseBody = Stream::create($body);
          $response = $response->withBody($responseBody);
          return self::respond($response);
        }
        $crtId = $candidate->getIdentifier();
        $getPath = "/certificates/$crtId?fromPost=true";
        $response = $this->response->withStatus(302);
        $response = $response->withHeader('Location',$getPath);
        return self::respond($response);

        // return $this->persistCertificate($candidate);
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
    //
}
