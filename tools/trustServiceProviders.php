<?php

require_once __DIR__.'/../vendor/autoload.php';

use Dotenv\Dotenv;
use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use App\Http\Controllers\TrustedLists;
use App\Http\Controllers\TrustServiceProviders;
use App\Http\Controllers\TSPServices;
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
$tlDir = $dataDir.'/TrustedLists/';
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
      $lotlURIId = hash('sha256',$lotlURI);
      break;
    default:
      print "Unrecognised trust scheme '$scheme'".PHP_EOL;
      usage($argv);
      exit(1);
      break;
  }
}

$lotlAttributes = json_decode(file_get_contents($tlDir.$lotlURIId.'.json'),true);
$trustedListAttributes = [];
$tlXML = [];
$trustServiceProviders = new TrustServiceProviders($dataDir);
$tspServices = new TSPServices($dataDir);
// $trustedLists = new TrustedLists($dataDir);
$trustedListDirFiles = array_diff(scandir($tlDir), array('..', '.'));
foreach ($lotlAttributes['pointedTLs'] as $pointedTL) {
  $tlId = $pointedTL['sourceId'];
  $tlAttributes = json_decode(file_get_contents($tlDir.$tlId.'.json'),true);
  $tlName = $tlAttributes['schemeTerritory'].': '.$tlAttributes['schemeOperator']['name'];
  print $tlName.' '.PHP_EOL;
  if (!array_key_exists('signature',$tlAttributes)) {
    print $tlAttributes['schemeOperator']['name'].' Not verified'.PHP_EOL;
    continue;
  } else {
    $trustedListAttributes[$tlName] = $tlAttributes;
    $tlTerritory = $tlAttributes['schemeTerritory'];
    $tlXML[$tlName] = file_get_contents($tlDir.$tlId.'.xml');
    try {

      $tl = new TrustedList($tlXML[$tlName]);
    } catch (\Exception $e) {
      print $e->getMessage();
      continue;
    }

    foreach ($tl->getTSPs() as $tsp) {
      $tspName = $tsp->getName();
      print '  '.$tspName.PHP_EOL;
      $tspId = hash('sha256',$tlTerritory.': '.$tspName);
      $tspAttributes = $tsp->getAttributes();
      $tspAttributes['trustedList'] = $tlAttributes;
      $trustServiceProviders->persistAttributes($tspAttributes);
      foreach ($tsp->getTSPServices() as $tspService) {
        $tspServiceAttributes = $tspService->getAttributes();
        $tspServiceAttributes['trustServiceProvider'] = $tspAttributes;
        $tspServices->persistAttributes($tspServiceAttributes);
      }
    }
  }
}


exit;

function usage($argv)
{
  print "TrustedList Attribute exporter".PHP_EOL;
  print "Usage:".PHP_EOL;
  print $argv[0].' <scheme=EU> [trustedListName]'.PHP_EOL;
}
