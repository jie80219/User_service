<?php
/**
 * SPIFFE mTLS Verification Test
 *
 * Proves that the SPIRE infrastructure is working end-to-end:
 *
 *   1. Connect to SPIRE Agent via Workload API (UDS)
 *   2. Fetch X.509-SVID (certificate + private key + CA bundle)
 *   3. Verify the SVID contents (SPIFFE ID, SAN, chain)
 *   4. Start a TLS server using the SVID
 *   5. Connect a TLS client using the same SVID (mTLS)
 *   6. Verify mutual authentication succeeded
 *   7. Fetch JWT-SVID and validate claims
 */

declare(strict_types=1);

$socketPath = getenv('SPIFFE_ENDPOINT_SOCKET') ?: 'unix:/run/spire/sockets/agent.sock';
$rawSocket = preg_replace('#^unix:#', '', $socketPath);

echo "╔══════════════════════════════════════════════════════════════╗\n";
echo "║          SPIFFE mTLS Verification Test                      ║\n";
echo "╚══════════════════════════════════════════════════════════════╝\n";
echo "  Agent socket: {$socketPath}\n\n";

$pass = 0;
$fail = 0;

function check(string $name, bool $ok, string $detail = ''): void {
    global $pass, $fail;
    if ($ok) {
        $pass++;
        echo "  \033[32m✓\033[0m {$name}\n";
    } else {
        $fail++;
        echo "  \033[31m✗\033[0m {$name}" . ($detail ? " — {$detail}" : '') . "\n";
    }
}

// ──────────────────────────────────────────────────────────────
//  1. Agent socket reachable
// ──────────────────────────────────────────────────────────────
echo "\033[1m[1. Agent Connectivity]\033[0m\n";
check('Agent socket exists', file_exists($rawSocket));

if (!file_exists($rawSocket)) {
    echo "\n  Cannot proceed without agent socket.\n";
    exit(1);
}

// ──────────────────────────────────────────────────────────────
//  2. Fetch X.509-SVID via Workload API
// ──────────────────────────────────────────────────────────────
echo "\n\033[1m[2. Fetch X.509-SVID from SPIRE Agent]\033[0m\n";

// Use a raw socket connection to the Workload API
// The Workload API is gRPC over HTTP/2, but we can also use
// the SPIRE Agent's built-in fetch utility if available.
// Since we're in a minimal container, we'll parse the SVID
// using openssl after dumping it via a helper script.

// Write a small Python script to fetch SVID (most containers have python3)
$fetchScript = <<<'PYTHON'
import socket, struct, sys, json, os

sock_path = sys.argv[1]
# Connect to SPIRE Agent Workload API via UDS
# This uses a simplified HTTP/1.1 approach since the agent
# also exposes a REST-like endpoint for fetching SVIDs.

# Actually, SPIRE Workload API is gRPC only.
# Let's check if we can use the SPIRE agent CLI instead.
print("NEED_CLI")
PYTHON;

// Alternative approach: use openssl s_client to test TLS
// First, let's try to get the SVID by writing PEM files using
// the SPIRE agent's built-in API

// Check if spire-agent binary is available in this container
$hasAgentCli = false;
$agentBin = '/opt/spire/bin/spire-agent';

// We're running inside the php-worker or app container, which
// doesn't have spire-agent binary. We need to use our PHP SDK.
// But we need the protobuf extension for that.

$hasProtobuf = extension_loaded('protobuf');
$hasSwow = extension_loaded('swow');

check('ext-openssl loaded', extension_loaded('openssl'));
check('ext-swow loaded', $hasSwow, $hasSwow ? '' : 'Required for gRPC client');

if (!$hasSwow) {
    echo "\n  Swow not available. Using alternative validation...\n";
    echo "  Writing PEM files via shell commands...\n\n";

    // Use docker exec from host to get SVIDs
    // Since we're inside the container, try a TCP test instead
    goto manual_tls_test;
}

// If we have Swow, try to load the SDK
$autoload = __DIR__ . '/../../vendor/autoload.php';
if (!file_exists($autoload)) {
    echo "  vendor/autoload.php not found. Using manual test.\n\n";
    goto manual_tls_test;
}

require $autoload;

if (!class_exists(\Spiffe\SpiffeWorkloadAPIClient::class)) {
    echo "  SpiffeWorkloadAPIClient not available.\n\n";
    goto manual_tls_test;
}

echo "  Using PHP SPIFFE SDK (Swow + protobuf)...\n\n";

try {
    $client = new \Spiffe\SpiffeWorkloadAPIClient($socketPath, 5.0, 10.0);
    $response = $client->fetchX509Svid();
    check('FetchX509SVID succeeded', true);

    $svids = $response->getSvids();
    $count = count($svids);
    check("Got {$count} SVID(s)", $count > 0);

    if ($count > 0) {
        $proto = $svids[0];
        $spiffeId = $proto->getSpiffeId();
        check("SPIFFE ID: {$spiffeId}", str_starts_with($spiffeId, 'spiffe://zt.local/'));
        check('Has certificate chain', strlen($proto->getX509Svid()) > 0);
        check('Has private key', strlen($proto->getX509SvidKey()) > 0);
        check('Has CA bundle', strlen($proto->getBundle()) > 0);

        // Parse the SVID
        $svid = \Spiffe\X509Svid::fromProto($proto);
        $certPem = $svid->certChainPem();
        $keyPem = $svid->privateKeyPem();
        $bundlePem = $svid->bundlePem();

        check('PEM cert is valid', str_contains($certPem, '-----BEGIN CERTIFICATE-----'));
        check('PEM key is valid', str_contains($keyPem, '-----BEGIN PRIVATE KEY-----'));

        // Verify certificate with OpenSSL
        $leaf = $svid->leafCertificate();
        $certInfo = openssl_x509_parse($leaf);
        $san = $certInfo['extensions']['subjectAltName'] ?? '';
        check("SAN contains SPIFFE URI", str_contains($san, 'spiffe://'));
        check("SAN matches: {$san}", str_contains($san, $spiffeId));

        // Key pair matches
        $keyMatches = openssl_x509_check_private_key($leaf, $svid->privateKey());
        check('Private key matches certificate', $keyMatches);

        // Certificate not expired
        $now = time();
        $notAfter = $certInfo['validTo_time_t'] ?? 0;
        check('Certificate is not expired', $now < $notAfter, "expires: " . date('Y-m-d H:i:s', $notAfter));

        // ──────────────────────────────────────────────────────
        //  3. mTLS Test: Server + Client using SVID
        // ──────────────────────────────────────────────────────
        echo "\n\033[1m[3. mTLS Handshake Test]\033[0m\n";

        // Write PEM files for TLS test
        $certFile = tempnam(sys_get_temp_dir(), 'svid_cert_');
        $keyFile = tempnam(sys_get_temp_dir(), 'svid_key_');
        $caFile = tempnam(sys_get_temp_dir(), 'svid_ca_');
        file_put_contents($certFile, $certPem);
        file_put_contents($keyFile, $keyPem);
        chmod($keyFile, 0600);
        file_put_contents($caFile, $bundlePem);

        check('PEM files written', file_exists($certFile) && file_exists($keyFile));

        // Start TLS server in a coroutine
        $testPort = 19443;
        $serverReady = false;
        $clientResult = null;
        $serverPeerId = null;

        \Swow\Coroutine::run(function () use ($certFile, $keyFile, $caFile, $testPort, &$serverReady, &$serverPeerId) {
            $ctx = stream_context_create([
                'ssl' => [
                    'local_cert'        => $certFile,
                    'local_pk'          => $keyFile,
                    'cafile'            => $caFile,
                    'verify_peer'       => true,
                    'verify_peer_name'  => false,
                    'allow_self_signed' => false,
                    'capture_peer_cert' => true,
                ],
            ]);

            $server = @stream_socket_server("ssl://127.0.0.1:{$testPort}", $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
            if (!$server) {
                echo "  Server failed: {$errstr}\n";
                return;
            }

            $serverReady = true;

            $conn = @stream_socket_accept($server, 5);
            if ($conn) {
                $data = fread($conn, 1024);

                // Extract peer certificate
                $params = stream_context_get_params($conn);
                $peerCert = $params['options']['ssl']['peer_certificate'] ?? null;
                if ($peerCert) {
                    $info = openssl_x509_parse($peerCert);
                    $san = $info['extensions']['subjectAltName'] ?? '';
                    preg_match('/URI:(\S+)/', $san, $m);
                    $serverPeerId = $m[1] ?? null;
                }

                fwrite($conn, "mTLS OK from server");
                fclose($conn);
            }
            fclose($server);
        });

        // Small delay for server to start
        \Swow\Coroutine::sleep(100);

        // Client connects with mTLS
        \Swow\Coroutine::run(function () use ($certFile, $keyFile, $caFile, $testPort, &$clientResult) {
            $ctx = stream_context_create([
                'ssl' => [
                    'local_cert'        => $certFile,
                    'local_pk'          => $keyFile,
                    'cafile'            => $caFile,
                    'verify_peer'       => true,
                    'verify_peer_name'  => false,
                    'allow_self_signed' => false,
                    'capture_peer_cert' => true,
                ],
            ]);

            $client = @stream_socket_client("ssl://127.0.0.1:{$testPort}", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
            if ($client) {
                fwrite($client, "Hello from mTLS client");
                $clientResult = fread($client, 1024);

                // Extract server's peer cert
                $params = stream_context_get_params($client);
                $peerCert = $params['options']['ssl']['peer_certificate'] ?? null;
                if ($peerCert) {
                    $info = openssl_x509_parse($peerCert);
                    $san = $info['extensions']['subjectAltName'] ?? '';
                }

                fclose($client);
            } else {
                $clientResult = "CONNECT_FAILED: {$errstr}";
            }
        });

        // Wait for both to complete
        \Swow\Coroutine::sleep(500);

        $handshakeOk = $clientResult === 'mTLS OK from server';
        check('mTLS handshake succeeded', $handshakeOk, $handshakeOk ? '' : "got: {$clientResult}");
        check('Server saw client SPIFFE ID', $serverPeerId !== null, $serverPeerId ?? 'null');

        if ($serverPeerId) {
            check("Peer ID: {$serverPeerId}", str_starts_with($serverPeerId, 'spiffe://zt.local/'));
        }

        // Cleanup
        @unlink($certFile);
        @unlink($keyFile);
        @unlink($caFile);

        // ──────────────────────────────────────────────────────
        //  4. JWT-SVID Test
        // ──────────────────────────────────────────────────────
        echo "\n\033[1m[4. JWT-SVID Test]\033[0m\n";

        $jwtReq = new \Spiffe\Workload\JWTSVIDRequest();
        $jwtReq->setAudience(['mtls-test']);
        $jwtResp = $client->fetchJwtSvid($jwtReq);

        $jwtSvids = $jwtResp->getSvids();
        check('FetchJWTSVID succeeded', count($jwtSvids) > 0);

        if (count($jwtSvids) > 0) {
            $jwtProto = $jwtSvids[0];
            $token = $jwtProto->getSvid();
            check('JWT token is JWS format', substr_count($token, '.') === 2);

            // Decode claims
            $parts = explode('.', $token);
            $claims = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
            check("JWT sub = {$claims['sub']}", str_starts_with($claims['sub'] ?? '', 'spiffe://zt.local/'));
            check("JWT aud contains 'mtls-test'", in_array('mtls-test', (array)($claims['aud'] ?? [])));
            check('JWT exp is in the future', ($claims['exp'] ?? 0) > time());
        }
    }

    $client->close();
} catch (\Throwable $e) {
    check('SDK execution', false, get_class($e) . ': ' . $e->getMessage());
}

goto summary;

// ──────────────────────────────────────────────────────────────
manual_tls_test:
// ──────────────────────────────────────────────────────────────
echo "\033[1m[Manual TLS Test — no SDK available]\033[0m\n";
echo "  Run this test inside a container with Swow + protobuf:\n";
echo "  docker exec zt-anser-app php spiffe/e2e/test-mtls.php\n\n";
check('SDK available', false, 'Install ext-swow and ext-protobuf in the container');

summary:
// ──────────────────────────────────────────────────────────────
echo "\n" . str_repeat('─', 60) . "\n";
echo sprintf("Results: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n", $pass, $fail);

exit($fail > 0 ? 1 : 0);
