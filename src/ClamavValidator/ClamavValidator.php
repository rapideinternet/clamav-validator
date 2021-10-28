<?php

namespace Sunspikes\ClamavValidator;

use Illuminate\Contracts\Translation\Translator;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\Validator;
use Xenolope\Quahog\Client as QuahogClient;
use Socket\Raw\Factory as SocketFactory;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class ClamavValidator extends Validator
{
    /**
     * Creates a new instance of ClamavValidator.
     *
     * ClamavValidator constructor.
     * @param Translator $translator
     * @param array      $data
     * @param array      $rules
     * @param array      $messages
     * @param array      $customAttributes
     */
    public function __construct(
        Translator $translator,
        array $data,
        array $rules,
        array $messages = [],
        array $customAttributes = []
    ) {
        parent::__construct($translator, $data, $rules, $messages, $customAttributes);
    }

    /**
     * Validate the uploaded file for virus/malware with ClamAV.
     *
     * @param  $attribute   string
     * @param  $value       mixed
     * @param  $parameters  array
     *
     * @return boolean
     * @throws ClamavValidatorException
     */
    public function validateClamav($attribute, $value, $parameters)
    {
        if (true === Config::get('clamav.skip_validation')) {
            return true;
        }

        if(is_array($value)) {
        	$result = true;
        	foreach($value as $file) {
        		$result &= $this->validateFileWithClamAv($file);
			}

        	return $result;
		}

		return $this->validateFileWithClamAv($value);
	}

	/**
	 * Validate the single uploaded file for virus/malware with ClamAV.
	 *
	 * @param $value mixed
	 *
	 * @return bool
	 * @throws ClamavValidatorException
	 */
	protected function validateFileWithClamAv($value)
	{
        $filePath = $this->getFilePath($value);
        if (! is_readable($filePath)) {
            throw ClamavValidatorException::forNonReadableFile($filePath);
        }

        try {
            $response  = $this->performCurlRequest($value);
        } catch (\Exception $exception) {
            throw ClamavValidatorException::forClientException($exception);
        }

        if ($response['httpcode'] === 200) {
            return true;
        }

        if ($response['httpcode'] === 403) {
            return false;
        }

        throw ClamavValidatorException::forClientException($response['body']);
    }

    /**
     * Guess the ClamAV socket.
     *
     * @return string
     */
    protected function performCurlRequest($file)
    {
        $formData = [
            'file' => new \CURLFile($file->getRealPath(), $file->getMimeType(), $file->getFilename())
        ];
        $headers = ["Content-Type" => "multipart/form-data"];

        $url = Config::get('clamav.clamav_url');
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url . '/v1alpha/scan');
        curl_setopt($ch, CURLOPT_POST,true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $formData);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TCP_KEEPALIVE, true);
        curl_setopt($ch, CURLOPT_TCP_KEEPIDLE, 30);
        curl_setopt($ch, CURLOPT_TCP_KEEPINTVL, 15);

        $result = curl_exec ($ch);

        if(!$result) {
            throw ClamavValidatorException::connectionException();
        }

        $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($result, 0, $header_size);
        $body = substr($result, $header_size);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close ($ch);

        $data = [
            'httpcode' => $httpcode,
            'header' => $header,
            'body' => $body
        ];

        return $data;
    }

    /**
     * Return the file path from the passed object.
     *
     * @param mixed $file
     * @return string
     */
    protected function getFilePath($file)
    {
        // if were passed an instance of UploadedFile, return the path
        if ($file instanceof UploadedFile) {
            return $file->getRealPath();
        }

        // if we're passed a PHP file upload array, return the "tmp_name"
        if (is_array($file) && null !== Arr::get($file, 'tmp_name')) {
            return $file['tmp_name'];
        }

        // fallback: we were likely passed a path already
        return $file;
    }
}
