<?php

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__ . "/app")
    ->in(__DIR__ . "/routes")
    ->in(__DIR__ . "/storage")
    ->in(__DIR__ . "/tests");

return PhpCsFixer\Config::create()
    ->setRules([
        '@PSR2' => true,
    ])
    ->setFinder($finder)
;
