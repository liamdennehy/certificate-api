<?php

namespace App\Http\Controllers;

class TrustServiceProviders extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
      $this->dataDir = __DIR__.'/../../../data/';
      $this->tspServiceDir = $this->dataDir.'TSPs/';
    }

    public function getFromLocal($ski)
    {

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
}
