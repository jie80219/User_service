<?php

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use SDPMlab\LSVID\FileSvidReader;
use SDPMlab\LSVID\JtiReplayCache;
use SDPMlab\LSVID\LSVIDContext;
use SDPMlab\LSVID\LSVIDException;
use SDPMlab\LSVID\LSVIDValidator;

class SpiffeLsvidFilter implements FilterInterface
{
    /**
     * Per-worker replay cache — survives across requests in the same
     * RoadRunner worker process, preventing token replay within that worker.
     */
    private static ?JtiReplayCache $replayCache = null;

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

        $validator = $this->buildValidator();
        if ($validator === null) {
            if ($required) {
                return $response->setStatusCode(503)->setJSON([
                    'status' => 503,
                    'error'  => 'LSVID validation unavailable — no SVID configured',
                ]);
            }
            return;
        }

        try {
            $mySpiffeId = getenv('SPIFFE_ID') ?: null;
            $lsvid = $validator->validate($rawLsvid, expectedAudience: $mySpiffeId);

            // Store raw token in coroutine-safe context for downstream propagation
            LSVIDContext::set($rawLsvid);

            $request->lsvid        = $lsvid;
            $request->lsvidIssuer  = $lsvid->issuer();
            $request->lsvidSubject = $lsvid->chain()[0]->subject();
        } catch (LSVIDException $e) {
            return $response->setStatusCode(403)->setJSON([
                'status' => 403,
                'error'  => 'LSVID validation failed: ' . $e->getMessage(),
            ]);
        }
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null)
    {
        // Clear per-request LSVID context to prevent leaking between
        // sequential requests handled by the same RoadRunner worker.
        LSVIDContext::clear();
    }

    private function buildValidator(): ?LSVIDValidator
    {
        $shmDir = getenv('SPIFFE_SHM_DIR') ?: '/tmp/spiffe-shared';

        try {
            $reader = new FileSvidReader(
                certPath:   $shmDir . '/svid.pem',
                keyPath:    $shmDir . '/svid_key.pem',
                bundlePath: $shmDir . '/bundle.pem',
            );
            $primary = $reader->readX509Primary();
            if ($primary === null) {
                return null;
            }

            if (self::$replayCache === null) {
                self::$replayCache = new JtiReplayCache();
            }

            return new LSVIDValidator(
                $reader,
                clockSkewSeconds: 30,
                jtiCache: self::$replayCache,
            );
        } catch (\Throwable) {
            return null;
        }
    }
}
