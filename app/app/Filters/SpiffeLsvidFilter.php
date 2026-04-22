<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use SDPMlab\LSVID\LSVIDContext;

/**
 * SPIFFE LSVID Filter — Go Sidecar 版本
 *
 * 透過 Unix Domain Socket 呼叫 Go spiffe-sidecar 的 /lsvid/validate API
 * 驗證 X-LSVID header，取代原本直接使用 php-lsvid 套件的方式。
 */
class SpiffeLsvidFilter implements FilterInterface
{
    public function before(RequestInterface $request, $arguments = null)
    {
        $request  = \Config\Services::request();
        $response = \Config\Services::response();
        $rawLsvid = $request->getHeaderLine('X-LSVID');

        $required = (getenv('LSVID_REQUIRED') ?: '0') === '1';

        if ($rawLsvid === '') {
            if ($required) {
                return $response->setStatusCode(401)->setJSON([
                    'status' => 401,
                    'error'  => 'Missing X-LSVID header',
                ]);
            }
            return;
        }

        // 透過 Go sidecar 驗證 LSVID
        $mySpiffeId = getenv('SPIFFE_ID') ?: null;
        $result = $this->validateViaSidecar($rawLsvid, $mySpiffeId);

        if ($result === null) {
            // Sidecar 不可達
            if ($required) {
                return $response->setStatusCode(503)->setJSON([
                    'status' => 503,
                    'error'  => 'LSVID validation unavailable — sidecar not reachable',
                ]);
            }
            return;
        }

        if (!$result['valid']) {
            return $response->setStatusCode(403)->setJSON([
                'status' => 403,
                'error'  => 'LSVID validation failed: ' . ($result['error'] ?? 'unknown'),
            ]);
        }

        // 驗證成功：存入 context 供下游傳播
        LSVIDContext::set($rawLsvid);

        $request->lsvid        = $rawLsvid;
        $request->lsvidIssuer  = $result['issuer'] ?? '';
        $request->lsvidSubject = $result['subject'] ?? '';
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        LSVIDContext::clear();
    }

    /**
     * 透過 Go spiffe-sidecar 的 UDS API 驗證 LSVID token。
     *
     * @param string      $rawToken       原始 LSVID JWS token
     * @param string|null $expectedAudience 預期的 audience（本服務的 SPIFFE ID）
     * @return array|null 驗證結果 {valid, issuer, subject, error} 或 null（sidecar 不可達）
     */
    private function validateViaSidecar(string $rawToken, ?string $expectedAudience): ?array
    {
        $socketPath = getenv('SPIFFE_SIDECAR_SOCKET') ?: '/tmp/spiffe-sidecar.sock';

        $payload = json_encode([
            'raw_token'         => $rawToken,
            'expected_audience' => $expectedAudience ?? '',
            'jti_cache_id'      => 'php-filter',
        ]);

        try {
            $ctx = stream_context_create([
                'socket' => ['bindto' => '0:0'],
                'http'   => [
                    'method'  => 'POST',
                    'header'  => "Content-Type: application/json\r\nContent-Length: " . strlen($payload) . "\r\n",
                    'content' => $payload,
                    'timeout' => 3,
                ],
            ]);

            // 透過 Unix Domain Socket 連線
            $fp = @stream_socket_client(
                'unix://' . $socketPath,
                $errno,
                $errstr,
                3,
            );

            if ($fp === false) {
                error_log("[spiffe-lsvid-filter] sidecar unreachable: $errstr ($errno)");
                return null;
            }

            // 手動發送 HTTP 請求（UDS 上的 HTTP/1.1）
            $httpRequest = "POST /lsvid/validate HTTP/1.1\r\n"
                . "Host: localhost\r\n"
                . "Content-Type: application/json\r\n"
                . "Content-Length: " . strlen($payload) . "\r\n"
                . "Connection: close\r\n"
                . "\r\n"
                . $payload;

            fwrite($fp, $httpRequest);

            $responseRaw = '';
            while (!feof($fp)) {
                $responseRaw .= fread($fp, 4096);
            }
            fclose($fp);

            // 解析 HTTP response body（跳過 headers）
            $parts = explode("\r\n\r\n", $responseRaw, 2);
            $body = $parts[1] ?? '';

            // 處理 chunked transfer encoding
            if (stripos($parts[0] ?? '', 'Transfer-Encoding: chunked') !== false) {
                $body = $this->decodeChunked($body);
            }

            $decoded = json_decode($body, true);
            if (!is_array($decoded)) {
                error_log("[spiffe-lsvid-filter] invalid sidecar response: $body");
                return null;
            }

            return $decoded;
        } catch (\Throwable $e) {
            error_log("[spiffe-lsvid-filter] sidecar error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * 解碼 HTTP chunked transfer encoding。
     */
    private function decodeChunked(string $data): string
    {
        $result = '';
        while (true) {
            $nlPos = strpos($data, "\r\n");
            if ($nlPos === false) {
                break;
            }
            $chunkSize = hexdec(substr($data, 0, $nlPos));
            if ($chunkSize === 0) {
                break;
            }
            $result .= substr($data, $nlPos + 2, $chunkSize);
            $data = substr($data, $nlPos + 2 + $chunkSize + 2);
        }
        return $result;
    }
}
