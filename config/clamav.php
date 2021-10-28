<?php

return [
    /*
    |--------------------------------------------------------------------------
    | ClamAV URL
    |--------------------------------------------------------------------------
    | This option defines the TCP socket to the ClamAV instance.
    */
    'clamav_url' => env('CLAMAV_URL', '127.0.0.1:3310'),

    /*
    |--------------------------------------------------------------------------
    | Socket read timeout
    |--------------------------------------------------------------------------
    | This option defines the maximum time to wait in seconds for a read.
    */
    'socket_read_timeout' => env('CLAMAV_SOCKET_READ_TIMEOUT', 30),

    /*
    |--------------------------------------------------------------------------
    | Skip validation
    |--------------------------------------------------------------------------
    | This skips the virus validation for current environment.
    |
    | Please note when true it won't connect to ClamAV and will skip the virus validation.
    */
    'skip_validation' => env('CLAMAV_SKIP_VALIDATION', false),
];
