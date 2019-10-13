<?php

namespace App\Http\Controllers;

class TrustedLists extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    public function getTL()
    {
        // code...
    }

    public static function setLinks($tlAttributes)
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

}
