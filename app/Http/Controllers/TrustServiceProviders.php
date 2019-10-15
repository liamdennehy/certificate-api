<?php

namespace App\Http\Controllers;

use Psr\Http\Message\ServerRequestInterface;
use App\Helpers;

class TrustServiceProviders extends Controller
{
    private $dataDir;
    private $tspDir;
    private $helpers;

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
      $this->tspDir = $this->dataDir.'TSPs/';
    }

    public function getTSP(ServerRequestInterface $request, $tspID)
    {
      if (strpos($tspID,'.') > 0 || strlen($tspID) != 64) {
        $response = Helpers::respondError(400, 'Unrecognised Input');
        return $response;
      }
      $tspAttributesFile = $this->tspDir.$tspID.'.json';
      if (!is_file($tspAttributesFile)) {
        Helpers::respondError(404, 'Not Found');
      }
      $tspAttributes = json_decode(file_get_contents($tspAttributesFile),true);
      $tspAttributes = self::setLinks($tspAttributes);
      $response = Helpers::respond(200,'application/json',$tspAttributes);
      return $response;
    }

    public static function setLinks($tspAttributes)
    {
      $id = hash(
        'sha256',
        $tspAttributes['trustedList']['schemeTerritory'].
        ': '.$tspAttributes['name']
      );
      $tspAttributes['_links']['self'] = '/trust-service-providers/'.$id;
      $tspAttributes['trustedList'] =
        TrustedLists::setLinks($tspAttributes['trustedList']);
      return $tspAttributes;
    }

    public function persistAttributes($attrs)
    {
      $tspName = str_replace (
        '/',
        '-',
        $attrs['trustedList']['schemeTerritory'].': '.$attrs['name']
      );
      $tspId = hash('sha256',$tspName);
      $attrFileName = $tspId.'.json';
      $attrFilePath = $this->tspDir.$attrFileName;
      $attrLink = $this->tspDir.$tspName.'.json';
      file_put_contents($attrFilePath,json_encode($attrs,JSON_PRETTY_PRINT));
          if (file_exists($attrLink)) {
              unlink($attrLink);
          }
          symlink('./'.$attrFileName, $attrLink);
    }

}
