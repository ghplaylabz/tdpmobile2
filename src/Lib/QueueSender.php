<?php

namespace App\Lib;

use Cake\Log\Log;
use Cake\Http\Client;
use Cake\Core\Configure;
use Cake\ORM\TableRegistry;

/**
 * Api Sender class
 * Library class for sending request to Queue Server
 */
class QueueSender
{

    public function __construct()
    {
    }

    /**
     * sends data to queue server
     *
     * @param string $url
     * @param array $data
     * @return \Cake\Http\Client\Response|null
     */
    public static function send($url, $type, $data)
    {
        $http = new Client();
        $textToSign = $type === 'post' ? json_encode($data) : [];
        $secret_key = Configure::read('Mailer.secret');
        $headers = [
            'X-CA-Secret' => $secret_key,
            'X-CA-Signature' => base64_encode(hash_hmac('SHA256', $textToSign, $secret_key, true))
        ];
        try {
            $response = null;
            if ($type === 'get') {
                $response = $http->get(Configure::read('Mailer.api_url') . $url, $data, ['headers' => $headers,'timeout' => Configure::read('Mailer.timeout')]);
            } else {
                $response = $http->post(Configure::read('Mailer.api_url') . $url, $data, ['headers' => $headers,'timeout' => Configure::read('Mailer.timeout')]);
            }
            
            if (!$response->isOk()) {
                Log::debug(json_encode(['response' => $response->getStringBody(), 'data' => $data]));
                return null;
            }
            return $response;
        } catch (\Exception $e) {
            Log::debug(json_encode($data));
        }
        return null;
    }

    /**
     * Streams a binary response (e.g. a ZIP of vouchers) from the queue server straight to a file.
     *
     * Cake\Http\Client buffers the whole body in memory, which can exhaust memory_limit on a large ZIP,
     * so this uses curl with CURLOPT_FILE. Same auth headers as send().
     *
     * @param string $url Path relative to Mailer.api_url (e.g. '/download-zipped-pdf')
     * @param string $type 'post' or 'get'
     * @param array $data Payload
     * @param string $destinationPath Absolute path to write the body to (removed on failure)
     * @return array{path: string, httpCode: int, headers: array<string, string>}|null null on error or non-2xx
     */
    public static function download($url, $type, $data, $destinationPath)
    {
        $type = strtolower((string)$type);
        $textToSign = $type === 'post' ? json_encode($data) : '';
        $secret = (string)Configure::read('Mailer.secret');
        $timeout = (int)(Configure::read('Mailer.timeout') ?: 120);
        $fullUrl = Configure::read('Mailer.api_url') . $url;

        $destDir = dirname($destinationPath);
        if (!is_dir($destDir)) {
            @mkdir($destDir, 0775, true);
        }
        $fp = @fopen($destinationPath, 'w+b');
        if ($fp === false) {
            Log::error('QueueSender::download: cannot open ' . $destinationPath);

            return null;
        }

        $respHeaders = [];
        $opts = [
            CURLOPT_HTTPHEADER => [
                'X-CA-Secret: ' . $secret,
                'X-CA-Signature: ' . base64_encode(hash_hmac('SHA256', $textToSign, $secret, true)),
            ],
            CURLOPT_FILE => $fp,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 30,
            CURLOPT_HEADERFUNCTION => function ($ch, $headerLine) use (&$respHeaders) {
                $line = trim($headerLine);
                if ($line !== '' && str_contains($line, ':')) {
                    [$k, $v] = explode(':', $line, 2);
                    $respHeaders[strtolower(trim($k))] = trim($v);
                }

                return strlen($headerLine);
            },
        ];
        if ($type === 'get') {
            $opts[CURLOPT_URL] = $fullUrl . (!empty($data) ? '?' . http_build_query($data) : '');
        } else {
            $opts[CURLOPT_URL] = $fullUrl;
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $data;
        }

        $ch = curl_init();
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        fclose($fp);

        if ($ok === false || $httpCode < 200 || $httpCode >= 300) {
            Log::error('QueueSender::download failed: HTTP ' . $httpCode . ' ' . $curlErr . ' ' . $url . ' ' . json_encode($data));
            @unlink($destinationPath);

            return null;
        }

        return ['path' => $destinationPath, 'httpCode' => $httpCode, 'headers' => $respHeaders];
    }
}
