<?php

require_once __DIR__.'/../vendor/autoload.php';

use eIDASCertificate\Certificate\X509Certificate;
use eIDASCertificate\TrustedList;
use App\Helpers;
use App\DataSource;

$lotlXML = null;
$dataDir = __DIR__ . '/../data/';
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

foreach ($lotl->getTLPointerPaths() as $title => $tlPointer) {
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
}
exit;
$serviceTypeCounts = [];
$tspServices = $lotl->getTSPServices(true);
// var_dump($tspServices["POSTArCA G2"]); exit;
$tspServiceAttributes = [];
foreach ($tspServices as $name => $tspService) {
    $tspServiceAttributes[$name] = $tspService;
}
print json_encode($tspServiceAttributes).PHP_EOL;
