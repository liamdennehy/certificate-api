<?php

namespace App\Http\Controllers;

use App\Helpers;
use Psr\Http\Message\ServerRequestInterface;
use eIDASCertificate\Certificate\X509Certificate;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\Stream;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Nyholm\Psr7\Factory\Psr17Factory;
use eIDASCertificate\OCSP\OCSPRequest;
use eIDASCertificate\OCSP\OCSPResponse;

class Certificates extends Controller
{
    private $dataDir;

    const maxUpload = 10240;
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct($dataDir = null)
    {
        if (empty($dataDir)) {
          $this->dataDir = __DIR__.'/../../../data/';
        } else {
          $this->dataDir = $dataDir;
        }
        if (!is_dir($this->dataDir)) {
          throw new \Exception("DataDir '$dataDir' does not exist", 1);
        }
        if ($this->dataDir[strlen($this->dataDir) - 1] != '/') {
          $this->dataDir .= '/';
        }
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
      $response = $this->response;
      if (sizeof(explode('.',$certificateId)) == 2) {
        $suffix = explode('.',$certificateId)[0];
        $certificateId = explode('.',$certificateId)[1];
      }
      $crt = $this->getFromLocal($certificateId, true);
      if (empty($crt)) {
        return $this->respondError(404,'Not Found');
      }
      if (! empty($suffix) && $suffix = 'crt') {
        $accept = 'application/x-pem-file';
      } elseif (! empty($suffix) && $suffix = 'cer') {
        $accept = 'application/pkix-cert';
      } elseif (! $request->hasHeader('accept')) {
        $accept = 'application/json';
      } else {
        foreach (explode(',',$request->getHeaderLine('accept')) as $acceptable) {
          if (! empty($accept)) {
            break;
          }
          $acceptable = explode(';',$acceptable)[0];
          switch ($acceptable) {
            case 'text/html':
              $accept = 'text/html';
              break;
            case 'application/ocsp-request':
              $accept = 'application/ocsp-request';
              break;
            case 'application/x-pem-file':
              $accept = 'application/x-pem-file';
              break;
            case 'application/pkix-cert':
              $accept = 'application/pkix-cert';
              break;

            case 'application/json':
            default:
              $accept = 'application/json';
              break;
          }
        }
      }

      switch ($accept) {
        case 'application/ocsp-request':
          if (array_key_exists('sha1',$request->getQueryParams())) {
            $alg = 'sha1';
          } elseif (array_key_exists('sha512',$request->getQueryParams())) {
            $alg = 'sha512';
          } elseif (array_key_exists('sha384',$request->getQueryParams())) {
            $alg = 'sha384';
          } else {
            $alg = 'sha256';
          }
          if (array_key_exists('nononce',$request->getQueryParams())) {
            $nonce = 'none';
          } else {
            $nonce = 'auto';
          }
          if (! $crt->hasIssuers()) {
            $response = $response->withHeader('IssuerURI',implode(',',$crt->getIssuerURIs()));
            $response = $response->withHeader('Content-Type','text/plain');
            $body = "Certificate with id '$certificateId' has no associated issuer. check the 'IssuerURI' header for possible URLs";
          } elseif (sizeof($crt->getIssuers()) > 1) {
            $body = "More than one issuer in certificate '$certificateId'. Sorry...";
            $response = $response->withHeader('Content-Type','text/plain');
            $response = $response->withHeader('Issuer',implode(',',array_keys($crt->getIssers())));
          } else {
            $ocspRequest = $this->getCertificateOCSPRequest($crt, $alg, $nonce);
            $body = $ocspRequest['application/ocsp-response'];
            $response = $response->withHeader('OCSP-URI',$ocspRequest['OCSP-URI']);
          }
          break;
        case 'application/x-pem-file':
          if (array_key_exists('chain',$request->getQueryParams()) && $request->getQueryParams()['chain'] != 'false') {
            $body = $crt->toPEM(true);
          } else {
            $body = $crt->toPEM(false);
          }
          $response = $response->withHeader('Content-Type','application/x-pem-file');
          break;
        case 'application/pkix-cert':
          $body = $crt->getBinary();
          $response = $response->withHeader('Content-Type','application/pkix-cert');
          break;
        case 'application/json':
          $body = json_encode($this->getAttributes($crt), JSON_PRETTY_PRINT);
          $response = $response->withHeader('Content-Type','application/json');
          break;
        default:
          $body = dd($this->getAttributes($crt));
          $response = $response->withHeader('Content-Type','text/html');
          $response = $response->withHeader('From-Accept',$request->getHeaderLine('accept'));
          break;
      }
      $responseBody = Stream::create($body);
      // $response = $response->withBody($responseBody);
      return self::respond($response->withBody($responseBody));
    }

    public function getCertificateOCSPRequest($certs, $alg = 'sha256', $nonce = 'auto')
    {
        if (! is_array($certs)) {
          $certs = [$certs];
        }
        $issuerId = null;
        $ocspURL = null;
        foreach ($certs as $cert) {
          $certId = $cert->getIdentifier();
          if (! $cert->hasIssuers()) {
            return (new Response(
              400,
              ['IssuerURI' => implode(',',$cert->getIssuerURIs()),'Content-Type' => 'text/plain'],
              "Certificate with id '$certId' has no associated issuer. check the 'IssuerURI' header for possible URLs"
            ));
          }
          if (sizeof($cert->getIssuers()) > 1) {
            return [
              'code' => 400,
              'headers' => ['IssuerCount' => sizeof($issuerIDs), 'Content-Type' => 'text/plain'],
              'body' => "More than one issuer in certificate '$certId'. Sorry..."
            ];
          }
          if (is_null($issuerId)) {
            $issuerId = current($cert->getIssuers())->getIdentifier();
          } elseif (current($cert->getIssuers())->getIdentifier() !== $issuerId) {
            return (new Response(
              400,
              ['Content-Type' => 'text/plain'],
              'Provided certificates ar from multiple issuer.'
            ));
          }
        }
        $ocspRequest = OCSPRequest::fromCertificate($certs,$alg, $nonce);
        return [
          'OCSP-URI' => implode(',',$cert->getOCSPURIs()),
          'application/ocsp-response' => $ocspRequest->getBinary()
        ];


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
          case 'application/x-pem-file':
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

          case 'application/ocsp-response':
            $ocspResponse = OCSPResponse::fromDER((string)$request->getBody());
            foreach ($ocspResponse->getCertificates() as $certId => $includedCert) {
              $this->persistCert($includedCert);
            }
            $response = $this->response->withStatus(200);
            $attributes = $ocspResponse->getAttributes();
            $attributes['_links']['signer'] =
              '/certificates/'.$ocspResponse->getSigningCert()->getIdentifier();
            if ($ocspResponse->hasCertificates()) {
              foreach ($ocspResponse->getCertificates() as $certId => $includedCert) {
                $attributes['_links']['includedCert'][$certId] =
                  '/certifictes/'.$certId;
              }
            }
            if ($request->getHeaderLine('Accept') == 'application/json') {
              $jsonBody = json_encode($attributes,JSON_PRETTY_PRINT);
              $responseBody = Stream::create($jsonBody);
              $response = $response->withHeader('Location','application/json');
            } else {
              $responseBody = Stream::create(dd($attributes));
              $response = $response->withHeader('Content-Type','text/html');
            }
            $response = $response->withBody($responseBody);
            return self::respond($response);

            break;

          default:
            file_put_contents('header-'.(new \Datetime)->format('U'),$request->getHeaderLine('accept'));
            return $this->respondError(400,'Could not understand the request');

            break;
        }
        try {
          $crt = new X509Certificate($candidate);
        } catch (\Exception $e) {
          return $this->respondError(400,"Could not parse input as a certificate: ".$e->getMessage(), $candidate);
        }
        $this->persistCert($crt);

        $crtId = $crt->getIdentifier();
        $getPath = "/certificates/$crtId?fromPost=true";
        $response = $this->response->withStatus(302);
        $response = $response->withHeader('Location',$getPath);
        return self::respond($response);

    }

    public function persistCert($crt)
    {
        $crtId = $crt->getIdentifier();
        $crtFileName = $crtId.'.crt';
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

    public function persistFindings($crtAttributes)
    {
      foreach ($crtAttributes['findings'] as $findingLevel => $findings) {
        foreach ($findings as $component => $componentFindings) {
          foreach ($componentFindings as $finding) {
            // code...
            $crtAttributes['findings-unique'][] = hash('sha256',$component.'.'.print_r($finding[0],true));
          }
        }
      }
    }

    public function getAttributes($crt)
    {
      $crtAttributes = $crt->getAttributes();
      $crtAttributes = $this->setLinks($crtAttributes);
      return $crtAttributes;
    }

    public function setLinks($crtAttributes)
    {
      $crtAttributes['_links']['self']  = '/certificates/'.$crtAttributes['fingerprint'];
      if (array_key_exists('certificates',$crtAttributes['issuer'])) {
        foreach ($crtAttributes['issuer']['certificates'] as $index => $issuer) {
          $crtAttributes['issuer']['certificates'][$index] =
            $this->setLinks($issuer);
        }
      }
      if (array_key_exists('tspService',$crtAttributes)) {
        $crtAttributes['tspService'] = TSPServices::setLinks($crtAttributes['tspService']);
      }
      return $crtAttributes;
    }
}
