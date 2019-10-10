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
        $this->crtDir = $this->dataDir.'certs/';
        $this->caDir = $this->dataDir.'CAs/';
        $this->skiDir = $this->dataDir.'SKIs/';
        $this->tspServiceDir = $this->dataDir.'TSPServices/';
        $this->response = new Response();
        Helpers::mkdir($this->dataDir.'certs/');
        Helpers::mkdir($this->dataDir.'CAs/');
        Helpers::mkdir($this->dataDir.'SKIs/');
    }

    public function getCertificate(ServerRequestInterface $request, $certificateId)
    {
      $crt = $this->getFromLocal($certificateId, true);
      if (empty($crt)) {
        var_dump(404);
        return $this->respondError(404,'Not Found');
      }
      // $accept = explode(',',$request->getHeaderLine('Accept'))[0];
      // switch ($accept) {
      //   case 'application/json':
          $response = $this->response->withStatus(200);
          $response = $response->withHeader('Content-Type','application/json');
          $body = json_encode($crt->getAttributes(), JSON_PRETTY_PRINT);
          $responseBody = Stream::create($body);
          $response = $response->withBody($responseBody);
          // break;

      //   default:
      //     $response = $this->response->withStatus(406);
      //
      //     break;
      // }
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
            if ($request->getBody()->getSize() >= 10241) {
              return $this->respondError(400,'Too much data arrived, is this really a certificate?');
            }
            $body = trim((string)$request->getBody());
            $body = str_replace("\r\n","\n",$body);
            $candidate = self::PEMFromBody($body);
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
              $body = trim(stream_get_contents(current($request->getUploadedFiles())->getStream()->detach()));
              $candidate = self::PEMFromBody($body);
            }
            // code...
            break;

          default:
            return $this->respondError(400,'Could not understand the request');

            break;
        }
        try {
          $crt = new X509Certificate($candidate);
        } catch (\Exception $e) {
          return $this->respondError(400,"Could not parse input as a certificate: ".$e->getMessage(), $candidate);
        }
        $this->persistCertificate($crt);

        $crtId = $crt->getIdentifier();
        $getPath = "/certificates/$crtId?fromPost=true";
        $response = $this->response->withStatus(302);
        $response = $response->withHeader('Location',$getPath);
        return self::respond($response);

    }

    public function persistCertificate($crt)
    {
        $crtId = $crt->getIdentifier();
        $crtFileName = $crt->getIdentifier().'.crt';
        $crtPath = $this->crtDir.$crtFileName;
        if (file_exists($crtPath)) {
            return false;
        } else {
          if (Helpers::persistFile($crtPath,$crt->toPEM())) {
            if ($crt->isCA()) {
              $ski = bin2hex($crt->getSubjectKeyIdentifier());
              $skiDir = $this->skiDir.'/'.$ski.'/';
              Helpers::mkdir($skiDir);
              Helpers::link($skiDir.$crtFileName, '../../certs/'.$crtFileName);
              Helpers::link($this->caDir.$crtFileName,'../certs/'.$crtFileName);
            };
          }
        }
    }

    private function respond($response)
    {
      return (new HttpFoundationFactory())->createResponse($response);
    }

    public function respondError($code, $errorMsg, $moreData = null)
    {
      $body = [];
      $response = $this->response->withStatus($code);
      $response = $response->withHeader('Content-Type','application/json');
      $body['error'] = $errorMsg;
      if (! empty($moreData)) {
        $body['data'] = $moreData;
      }
      $body = json_encode($body);
      $responseBody = Stream::create($body);
      $response = $response->withBody($responseBody);
      return (new HttpFoundationFactory())->createResponse($response);
    }

    public static function PEMFromBody($body)
    {
      $body = trim($body);
      // TODO: move to library
      $bodyLines = explode("\n",$body);
      if (sizeof($bodyLines) > 1 ) {
        if (in_array('-----BEGIN CERTIFICATE-----',$bodyLines) && in_array('-----END CERTIFICATE-----',$bodyLines)) {
          while ($bodyLines[0] != '-----BEGIN CERTIFICATE-----') {
            array_shift($bodyLines);
          }
          while (end($bodyLines) != '-----END CERTIFICATE-----') {
            unset($bodyLines[sizeof($bodyLines)]);
          }
          $body = implode("\n",$bodyLines);
        }
      } elseif
      (
        substr($body,0,27) == '-----BEGIN CERTIFICATE-----' &&
        substr($body,-25,25) == '-----END CERTIFICATE-----'
      ) {
        $b64 = trim(substr(substr($body,27),0,strlen($body)-52));
        var_dump($b64);
        $body =
          "-----BEGIN CERTIFICATE-----\r\n".
          chunk_split(base64_encode(base64_decode($b64)), 64, "\r\n").
          "-----END CERTIFICATE-----";
      }
      return $body;
    }

    public function getIDsBySKI($ski)
    {
        if (empty($ski)) {
          return [];
        }
        $crts = [];
        $ski = bin2hex($ski);
        if (is_dir($this->skiDir.$ski)) {
          foreach (scandir($this->skiDir.$ski) as $crtFile) {
            if (is_link($this->skiDir.$ski.'/'.$crtFile)) {
              $crts[] = explode('.',$crtFile)[0];
            }
          }
        }
        return $crts;
    }

    public function getFromLocal($certificateId, $withIssuer = false)
    {
      $crtFilePath = $this->crtDir.$certificateId.'.crt';
      if (!file_exists($crtFilePath)) {
        return false;
      }
      $crtFile = file_get_contents($crtFilePath);
      $tspServiceFilePath = $this->crtDir.$certificateId.'.tspService.json';
      $crt = new X509Certificate($crtFile);
      if (is_link($tspServiceFilePath)) {
        $tspService = json_decode(file_get_contents($tspServiceFilePath),true);
        $crt->setTSPService($tspService);
      }
      $crtId = $crt->getIdentifier();
      if ($withIssuer) {
        $aki = $crt->getAuthorityKeyIdentifier();
        foreach ($this->getIDsBySKI($aki) as $issuerId) {
          if ($issuerId != $crtId) {
            try {
              $issuer = $this->getFromLocal($issuerId, true);
              $crt->withIssuer($issuer);
            } catch (\Exception $e) {
              throw new \Exception("Unable to process issuer cert (this should never happen)", 1);
            }
          }
        }
      }
      return $crt;
    }
}
