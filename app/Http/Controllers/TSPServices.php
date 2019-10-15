<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Certificates;
use eIDASCertificate\Certificate\X509Certificate;

class TSPServices extends Controller
{
    private $dataDir;
    private $tspServicesDir;
    /**
     * Create a new controller instance.
     *
     * @return void
     */
     public function __construct($dataDir = null)
     {
       if (!empty($dataDir)) {
         if ($dataDir[strlen($dataDir)-1] != '/') {
           $dataDir .= '/';
         }
         $this->dataDir = $dataDir;
       } else {
         $this->dataDir = __DIR__.'/../../../data/';
       }
       if (!is_dir($this->dataDir)) {
         throw new \Exception("DataDir is not a directory", 1);

       }
       $this->tspServicesDir = $this->dataDir.'TSPServices/';
     }

    public function getFromLocal($ski)
    {

    }

    public static function setLinks($tspServiceAttributes)
    {
      $id = hash(
        'sha256',
        $tspServiceAttributes['trustServiceProvider']['trustedList']['schemeTerritory'].
        ': '.$tspServiceAttributes['name']
      );
      $tspServiceAttributes['_links']['self'] = '/tsp-services/'.$id;
      $tspServiceAttributes['trustServiceProvider'] =
        TrustServiceProviders::setLinks($tspServiceAttributes['trustServiceProvider']);
      return $tspServiceAttributes;
    }

    public function persistAttributes($tspServiceAttributes)
    {
        // var_dump(implode(',',array_keys($tspServiceAttributes)));
        $certificates = new Certificates($this->dataDir);
        $certsDir = $this->dataDir.'certs/';
        $skisDir = $this->dataDir.'SKIs/';
        $casDir = $this->dataDir.'CAs/';
        // Make sure we're processing associative arrays even if json is object-oriented
        // $tspServiceAttributes = json_decode(
        //     json_encode($tspServiceAttributes),
        //     true
        // );
        // var_dump(sizeof($tspServiceAttributes['certificates']));
        // if(empty($tspServiceAttributes)) {
        //   exit;
        // }
        $tspServiceId = hash('sha256', $tspServiceAttributes['name']);
        $country = $tspServiceAttributes['trustServiceProvider']['trustedList']['schemeTerritory'];
        $name = $country.': '.$tspServiceAttributes['name'];
        $ski = $tspServiceAttributes['skiHex'];
        $skiLen = strlen(hex2bin($ski));
        if (! in_array($skiLen,[6,8,20,32])) {
          if ($skiLen != 0 && $skiLen != 294) { // some spanish provider put the entire public key in the SKI field...
            print PHP_EOL."Unsupported SKI length: ".$skiLen;
          }
          $ski = null;
        }
        if (! empty($ski)) {
            $skiDir = $skisDir.$ski.'/';
            if (!file_exists($skiDir)) {
                mkdir($skiDir);
            }
        }
        foreach ($tspServiceAttributes['certificates'] as $certificate) {
            $PEM = $certificate['PEM'];
            $crt = new X509Certificate($PEM);
            $crtId = $crt->getIdentifier();
            $certificates->persist($crt);
            if (! empty($ski)) {
                $skiLinked = false;
                $skiEntries = array_diff(scandir($skiDir),['.','..']);
                foreach ($skiEntries as $skiEntry) {
                    $parts = explode('/', readlink($skiDir.'/'.$skiEntry));
                    if (sizeof($parts) <> 4) {
                        var_dump(['type' => $tspServiceAttributes['type'],$ski, $crt->getSubjectKeyIdentifier(),$skiEntry,$parts]);
                        exit;
                    }
                    $target = explode('/', readlink($skiDir.'/'.$skiEntry))[3];
                    if ($target == $crtId.'.crt') {
                        $skiLinked = true;
                    }
                }
                if (! $skiLinked) {
                    symlink('../../certs/'.$crtId.'.crt', $skiDir.$crtId.'.crt');
                }
            }
            $crtTSPServiceJsonLink = $certsDir.$crtId.'.tspService.json';
            if (is_link($crtTSPServiceJsonLink)) {
                unlink($crtTSPServiceJsonLink);
            }
            symlink('../TSPServices/'.$tspServiceId.'.json', $crtTSPServiceJsonLink);
        }
        file_put_contents(
          $this->tspServicesDir.$tspServiceId.'.json',
          json_encode(
            $tspServiceAttributes,
            JSON_PRETTY_PRINT
            )
        );
    }
}
