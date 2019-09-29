<?php

namespace App\Http\Controllers;

use Psr\Http\Message\ServerRequestInterface;
use eIDASCertificate\Certificate\X509Certificate;
use Illuminate\Http\Response;

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
            $response = new Response("",200);
            $response = $response->header('Content-Type','application/json');
            $response = $response->setContent(json_encode(["subject" => $crt->getSubjectName()]));
            break;

          default:
            $response = new Response("Error",406);
            return $response;

            break;
        }
        return $response;
        // return $crt->getSubjectName();
      } else {
        return "bar ".$certDir.$certificateId.'.crt';
      }
    }

    public function getCertificates(ServerRequestInterface $request)
    {

      return "get /certificates";
    }
    //
}
