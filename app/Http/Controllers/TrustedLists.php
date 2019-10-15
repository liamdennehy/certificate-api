<?php

namespace App\Http\Controllers;

use App\DataSource;
use eIDASCertificate\TrustedList;
use eIDASCertificate\Certificate\X509Certificate;

class TrustedLists extends Controller
{
    private $dataDir;

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
    }

    public function getTL()
    {
        // code...
    }

    public function setLinks($tlAttributes)
    {
      $id = hash(
        'sha256',
        $tlAttributes['schemeTerritory'].
        ': '.$tlAttributes['schemeOperatorName']
      );
      $tlAttributes['_links']['self'] = '/trusted-lists/'.$id;
      if (array_key_exists('parentTSL',$tlAttributes)) {
        $tlAttributes['parentTSL'] =
          self::setLinks($tlAttributes['parentTSL']);
      }
      return $tlAttributes;
    }

    public function persistXML($tl, $maxAge = 86400)
    {
        $now = (int)date('U');
        $tlXMLAge = null;
        $tlURI = $tl->getTSLLocation();
        $tlName = str_replace(
          '/',
          '-',
          $tl->getName()
        );
        $tlURIId = hash('sha256', $tlURI);
        $tlDirPath = $this->dataDir.'TrustedLists/';
        $tlFileName = $tlURIId.'.xml';
        $tlFilePath = $tlDirPath.$tlFileName;
        $symlink = $tlDirPath.$tlName.'.xml';
        if (file_exists($tlFilePath)) {
            $tlXMLAge = $now - filemtime($tlFilePath);
        }
        if (is_null($tlXMLAge) || $tlXMLAge >= $maxAge) {
            file_put_contents($tlFilePath, $tl->getXML());
            if (file_exists($symlink)) {
                unlink($symlink);
            }
            var_dump('./'.$tlFileName, $symlink);
            symlink('./'.$tlFileName, $symlink);
        }
    }

    public function persistAttributes($attrs)
    {
      $id = $attrs['sourceURI'];
      $tlName = str_replace(
        '/',
        '-',
        $attrs['schemeTerritory'].': '.$attrs['schemeOperatorName']
      );
      $tlURIId = hash('sha256', $attrs['sourceURI']);
      $tlDirPath = $this->dataDir.'TrustedLists/';
      $attrFileName = $tlURIId.'.json';
      $attrFilePath = $tlDirPath.'/'.$attrFileName;
      $attrLink = $tlDirPath.'/'.$tlName.'.json';
      file_put_contents($attrFilePath,json_encode($attrs,JSON_PRETTY_PRINT));
          if (file_exists($attrLink)) {
              unlink($attrLink);
          }
          symlink('./'.$attrFileName, $attrLink);
    }

    public function getSourceXML($tlURI, $maxAge = 86400)
    {
        $now = (int)date('U');
        $tlXML = null;
        print $tlURI.': ';
        $tlURIId = hash('sha256', $tlURI);
        $tlDirPath = $this->dataDir.'TrustedLists/';
        $tlFileName = $tlURIId.'.xml';
        $tlFilePath = $tlDirPath.$tlFileName;
        if (file_exists($tlFilePath)) {
            $tlXMLAge = $now - filemtime($tlFilePath);
            if ($tlXMLAge < $maxAge) {
                $tlXML = file_get_contents($tlFilePath);
                print 'from local'.PHP_EOL;
            }
        }
        if (empty($tlXML)) {
            $tlXML = DataSource::getHTTP($tlURI);
            print ' from http'.PHP_EOL;
        }
        return $tlXML;
    }

    function getSigned($tlURI, $signingCertDir)
    {
      $tlXML = TrustedLists::getSourceXML($tlURI, $this->dataDir);
      $tl = new TrustedList($tlXML);
      $tlSignerFiles = scandir($signingCertDir);
      array_shift($tlSignerFiles);
      array_shift($tlSignerFiles);
      if (sizeof($tlSignerFiles) == 0) {
        print "Trusted certificate directory appears empty".PHP_EOL;
        exit(1);
      }
      $tlSigners=[];
      foreach ($tlSignerFiles as $tlSignerFile) {
        $tlSignerPath = $signingCertDir.$tlSignerFile;
        $tlSigner = new X509Certificate(file_get_contents($tlSignerPath));
        $tlSigners[$tlSigner->getIdentifier()] = $tlSigner;
      }
      print 'Trusted List \''.$tl->getName().'\' Sequence Number '.$tl->getSequenceNumber().PHP_EOL;
      if (! $tl->verifyTSL($tlSigners)) {
        print "Cannot verify LOTL!". PHP_EOL;
        exit(1);
      }
      print 'Signed By \''.$tl->getSignedBy()->getSubjectDN().'\''.PHP_EOL;
      $attrs = $tl->getAttributes();
      if (!empty($tl->getTSLPointers())) {
        $attrs['pointedTLs'] = [];
        foreach ($tl->getTSLPointers()['xml'] as $tlName => $tlPointer) {
          // var_dump(array_keys($tlPointer)); exit;
          $pointedTL['schemeTerritory'] = $tlPointer->getSchemeTerritory();
          $pointedTL['schemeOperator'] = $tlPointer->getSchemeOperatorName();
          $pointedTL['sourceURI'] = $tlPointer->getTSLLocation();
          $pointedTL['sourceId'] = hash('sha256',$tlPointer->getTSLLocation());
          $attrs['pointedTLs'][$tlPointer->getName()] = $pointedTL;
        }
      }
      return ['trustedList' => $tl, 'attributes' => $attrs];
    }
}
