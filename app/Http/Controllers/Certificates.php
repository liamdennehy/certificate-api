<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use eIDASCertificate\Certificate\X509Certificate;

class Certificates extends Controller
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

    public function getCertificate(Request $request, $certificateId = null)
    {
      $certDir = __DIR__.'/../../../data/certs/';
      if (file_exists($certDir.$certificateId.'.crt')) {
        $crtFile = \file_get_contents($certDir.$certificateId.'.crt');
        $crt = new X509Certificate($crtFile);
        return $crt->getSubjectName();
      } else {
        return "bar ".$certDir.$certificateId.'.crt';
      }
    }

    public function getCertificates(Request $request)
    {
      return "foo";
    }
    //
}
