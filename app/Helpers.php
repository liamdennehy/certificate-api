<?php

namespace App;


abstract class Helpers
{

  public static function getTLXML($tlURI, $dataDir, $name, $maxAge = 86400)
  {
    $now = (int)date('U');
    $tlXML = null;
    $tlURIId = hash('sha256',$tlURI);
    $tlDirPath = $dataDir.'TrustedLists/';
    $tlFilePath = $tlDirPath.'/tl-'.$tlURIId.'.xml';
    if (file_exists($tlFilePath)) {
      $tlXMLAge = $now - filemtime($tlFilePath);
      print "Cached '$name' is $tlXMLAge seconds old".PHP_EOL;
      if ($tlXMLAge < $maxAge) {
        print "Loading local '$name' from $tlURI".PHP_EOL;
        $tlXML = file_get_contents($tlFilePath);
      }
    }
    if (empty($tlXML)) {
      print "Fetching $tlURI".PHP_EOL;
      $tlXML = DataSource::getHTTP($tlURI);
    }
    return $tlXML;

  }

  public static function persistTLXML($tlURI, $dataDir, $tl, $maxAge = 86400)
  {
      $now = (int)date('U');
      $tlXMLAge = null;
      $tlName = $tl->getName();
      $tlURIId = hash('sha256',$tlURI);
      $tlDirPath = $dataDir.'TrustedLists/';
      $tlFilePath = $tlDirPath.'/tl-'.$tlURIId.'.xml';
      $symlink = $tlDirPath.$tlName.'.xml';
      if (file_exists($tlFilePath)) {
        $tlXMLAge = $now - filemtime($tlFilePath);
      }
      if (is_null($tlXMLAge) || $tlXMLAge >= $maxAge) {
        print 'Saving TrustedList '.$tlName." in $tlFilePath".PHP_EOL;
        file_put_contents($tlFilePath,$tl->getXML());
        if (file_exists($symlink)) {
          unlink($symlink);
        }
        symlink('./tl-'.$tlURIId.'.xml',$symlink);
      }
  }
}
