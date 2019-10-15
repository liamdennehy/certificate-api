<?php

require_once __DIR__.'/../vendor/autoload.php';

use Dotenv\Dotenv;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use App\Http\Controllers\TrustedLists;
use App\Http\Controllers\Certificates;
use App\Helpers;

$dotenv = Dotenv::create(__DIR__.'/../');
$dotenv->load();
if (empty(getenv('DATADIR'))) {
  print "No DATADIR environment variable found.".PHP_EOL;
  print "Set in current environment or place in the .env file.".PHP_EOL;
  exit(1);
}
$dataDir = __DIR__ . '/../'.getenv('DATADIR').'/';
if (!is_dir($dataDir)) {
  print "DATADIR does not seem to exist.".PHP_EOL;
  exit(1);
}

if (!array_key_exists(1,$argv)) {
  usage($argv);
  exit(1);
} else {
  $scheme = $argv[1];
  switch ($scheme) {
    case 'EU':
      $lotlURI = TrustedList::ListOfTrustedListsXMLPath;
      break;
    default:
      print "Unrecognised trust scheme '$scheme'".PHP_EOL;
      usage($argv);
      exit(1);
      break;
  }
}
if (!array_key_exists(2,$argv)) {
  print "No trusted signing certificate directory specified".PHP_EOL;
  usage($argv);
  exit(1);
} elseif (!is_dir(__DIR__.'/../'.$argv[2])) {
  print "Trusted certificate directory does not seem to exist".PHP_EOL;
  exit(1);
} elseif (sizeof(array_diff(scandir(__DIR__.'/../'.$argv[2]),['.','..'])) == 0) {
  print "Trusted certificate directory seems empty".PHP_EOL;
} else {
  $signingCertDir = __DIR__.'/../'.$argv[2];
}
$certificates = new Certificates($dataDir);
$trustedLists = new TrustedLists($dataDir);
$lotl = $trustedLists->getSigned($lotlURI, $signingCertDir.'/');
$trustedLists->persistAttributes($lotl['attributes']);
$trustedLists->persistXML($lotl['trustedList']);
$certificates->persist($lotl['trustedList']->getSignedBy());
foreach ($lotl['attributes']['pointedTLs'] as $name => $pointedTL) {
  $tlName = $pointedTL['schemeTerritory'].': '.$pointedTL['schemeOperator'];
  $tlXML = $trustedLists->getSourceXML($pointedTL['sourceURI']);
  $tlName = $lotl['trustedList']->addTrustedListXML($tlName, $tlXML);
  $tl = $lotl['trustedList']->getTrustedLists()[$tlName];
  $tlSignedBy = $tl->getSignedBy();
  if (empty($tlSignedBy)) {
    $tlSignedBy = $tl->getSignedByHash();
  } else {
    $signedBy = $tl->getSignedBy();
    $signedByHash = $signedBy->getIdentifier();
    $certificates->persist($signedBy);
    $tlSignedBy = $signedBy->getSubjectDN()."($signedByHash)";
  }
  $tlAttributes = $tl->getAttributes();
  $tlAttributes['identifier'] = hash('sha256',$tl->getTSLLocation());
  $trustedLists->persistAttributes($tlAttributes);
  $trustedLists->persistXML($tl);

  print 'Trusted List \''.$tl->getName().'\' Sequence Number '.$tl->getSequenceNumber().PHP_EOL;
  print 'Signed By \''.$tlSignedBy.'\''.PHP_EOL;
}
function usage($argv)
{
  print "TrustedList Attribute exporter".PHP_EOL;
  print "Usage:".PHP_EOL;
  print $argv[0].' <scheme=EU> [trustedListName]'.PHP_EOL;
}
