<?php namespace Sunspikes\ClamavValidator;

use GuzzleHttp\Client;

class ClamavClient
{

    private $client;
    /**
     * Creates a new instance of ClamavClient.
     *
     * ClamavClient constructor.
     */
    public function __construct(
    ) {
        $this->client = new Client();
    }
}
