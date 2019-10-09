<?php

require_once __DIR__.'/../vendor/autoload.php';

use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use App\Helpers;
use App\DataSource;

$lotlXML = null;
$dataDir = __DIR__ . '/../data/';
// TODO: Move to parameters
$journalDir = $dataDir.'journal/c-276-1/';
$lotlURI = TrustedList::ListOfTrustedListsXMLPath;
$lotlXML = Helpers::getTLXML($lotlURI, $dataDir, 'List of Trusted Lists');

$verifiedTLs = [];
$unVerifiedTLs = [];
$pointedTLs = [];
$lotl = new TrustedList($lotlXML);
$lotlSignerFiles = scandir($journalDir);
array_shift($lotlSignerFiles);
array_shift($lotlSignerFiles);
$lotlSigners=[];
foreach ($lotlSignerFiles as $lotlSignerFile) {
  $lotlSignerPath = $journalDir.$lotlSignerFile;
  $lotlSigner = new X509Certificate(file_get_contents($lotlSignerPath));
  $lotlSigners[$lotlSigner->getIdentifier()] = $lotlSigner;
}
if (! $lotl->verifyTSL($lotlSigners)) {
  print "Cannot verify LOTL!". PHP_EOL;
  exit(1);
}
$lotlName = $lotl->getName();
Helpers::persistTLXML($lotlURI, $dataDir, $lotl);
if (empty($argv[1])) {
  print(implode("\n",array_keys($lotl->getTLPointerPaths())));
} else {
  $title = $argv[1];
  print $title;
  $tlPointer = $lotl->getTLPointerPaths()[$title];
  $tlURI = $tlPointer['location'];
  $tlXML = Helpers::getTLXML($tlURI, $dataDir, $title);
  try {
    $schemeOperatorName =
    $lotl->addTrustedListXML($title, $tlXML);
    $verifiedTLs[$schemeOperatorName] = $schemeOperatorName;
    Helpers::persistTLXML($tlURI, $dataDir, $lotl->getTrustedLists()[$schemeOperatorName]);

  } catch (SignatureException $e) {
    $unVerifiedTLs[] = $title;
  }
  $trustedList = $lotl->getTrustedLists(true)[$schemeOperatorName];
  $st = $trustedList->getSchemeTerritory();
  $tspServices = $trustedList->getTSPServices();
  foreach ($tspServices as $name => $tspServiceAttributes) {
    if (empty($tspServiceAttributes)) {
      var_dump($name);
    }
    // var_dump([$name => $tspServiceAttributes]); exit;
    // print $st.': '.$tspServiceAttributes['name'].': '.memory_get_usage();
    Helpers::persistTSPService($tspServiceAttributes,$dataDir);
    // print 'h'. PHP_EOL;
  }

};
print PHP_EOL; exit;

// foreach ($lotl->getTLPointerPaths() as $title => $tlPointer) {
// }
$tls = $lotl->getTrustedLists(true);
// unset($lotl);
$tlCount = 0;
foreach ($tls as $name => &$trustedList) {
  $st = $trustedList->getSchemeTerritory();
  print $trustedList->getName().PHP_EOL;
  $tspServices = $trustedList->getTSPServices();
  print ($trustedList->getName()).PHP_EOL;
  foreach ($tspServices as $name => &$tspServiceAttributes) {
    // var_dump([$name => $tspServiceAttributes]); exit;
    print $st.': '.$tspServiceAttributes['name'].': '.memory_get_usage();
    Helpers::persistTSPService($tspServiceAttributes,$dataDir);
    print 'h'. PHP_EOL;
  }
  unset($tls[$name]);
  unset($trustedList);
  gc_collect_cycles();
  $tlCount += 1;
}
exit;
