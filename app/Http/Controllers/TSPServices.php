<?php

namespace App\Http\Controllers;

class TSPServices extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
      $this->dataDir = __DIR__.'/../../../data/';
      $this->tspServiceDir = $this->dataDir.'TSPServices/';
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
}
