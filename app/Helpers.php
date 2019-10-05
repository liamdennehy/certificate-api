<?php

namespace App;

use eIDASCertificate\Certificate\X509Certificate;

abstract class Helpers
{
    public static function getTLXML($tlURI, $dataDir, $name, $maxAge = 86400)
    {
        $now = (int)date('U');
        $tlXML = null;
        $tlURIId = hash('sha256', $tlURI);
        $tlDirPath = $dataDir.'TrustedLists/';
        $tlFilePath = $tlDirPath.'/tl-'.$tlURIId.'.xml';
        if (file_exists($tlFilePath)) {
            $tlXMLAge = $now - filemtime($tlFilePath);
            if ($tlXMLAge < $maxAge) {
                $tlXML = file_get_contents($tlFilePath);
            }
        }
        if (empty($tlXML)) {
            $tlXML = DataSource::getHTTP($tlURI);
        }
        return $tlXML;
    }

    public static function persistTLXML($tlURI, $dataDir, $tl, $maxAge = 86400)
    {
        $now = (int)date('U');
        $tlXMLAge = null;
        $tlName = $tl->getName();
        $tlURIId = hash('sha256', $tlURI);
        $tlDirPath = $dataDir.'TrustedLists/';
        $tlFilePath = $tlDirPath.'/tl-'.$tlURIId.'.xml';
        $symlink = $tlDirPath.$tlName.'.xml';
        if (file_exists($tlFilePath)) {
            $tlXMLAge = $now - filemtime($tlFilePath);
        }
        if (is_null($tlXMLAge) || $tlXMLAge >= $maxAge) {
            file_put_contents($tlFilePath, $tl->getXML());
            if (file_exists($symlink)) {
                unlink($symlink);
            }
            symlink('./tl-'.$tlURIId.'.xml', $symlink);
        }
    }

    public static function persistTSPService($tspServiceAttributes, $dataDir)
    {
        $tspServicesDir = $dataDir.'TSPServices/';
        $certsDir = $dataDir.'certs/';
        $skisDir = $dataDir.'SKIs/';
        $casDir = $dataDir.'CAs/';
        // Make sure we're processing associative arrays even if json is object-oriented
        $tspServiceAttributes = json_decode(
        json_encode($tspServiceAttributes),
        true
    );
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
            file_put_contents($certsDir.'/'.$crtId.'.crt', $PEM);
            if (! empty($ski)) {
                $skiLinked = false;
                $skiEntries = scandir($skiDir);
                array_shift($skiEntries);
                array_shift($skiEntries);
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
            if ($crt->isCA()) {
                if (file_exists($casDir.$crtId.'.crt')) {
                    unlink($casDir.$crtId.'.crt');
                }
                symlink('../certs/'.$crtId.'.crt', $casDir.$crtId.'.crt');
            }
            $crtTSPServiceJsonLink = $certsDir.$crtId.'.tspService.json';
            if (file_exists($crtTSPServiceJsonLink)) {
                unlink($crtTSPServiceJsonLink);
            }
            symlink('../TSPServices/'.$tspServiceId.'.json', $crtTSPServiceJsonLink);
        }
        file_put_contents(
          $tspServicesDir.$tspServiceId.'.json',
          json_encode($tspServiceAttributes, JSON_PRETTY_PRINT
        )
    );
    }

    public static function mkdir($dir)
    {
        if (!is_dir($dir)) {
            if (file_exists($dir)) {
                throw new \Exception("$dir exists and is not a directory", 1);
            } else {
                mkdir($dir);
                chmod($dir, 0775);
            }
        }
    }

    public static function link($linkPath, $linkTarget)
    {
        if (!is_link($linkPath)) {
            if (file_exists($linkPath)) {
                throw new \Exception("$linkPath exists and is not a link", 1);
            } else {
                symlink($linkTarget, $linkPath);
                chmod($linkPath, 0664);
            }
        }
    }

    public static function persistFile($filePath, $fileContents)
    {
        file_put_contents($filePath, $fileContents);
        chmod($filePath, 0664);
        return true;
    }
}
