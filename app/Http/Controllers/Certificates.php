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
            $body = json_encode(["subject" => $crt->getSubjectName()]);
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

    private function respond($response)
    {
      return (new HttpFoundationFactory())->createResponse($response);
    }
    //
}
