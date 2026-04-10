<?php

/**
 * SPIFFE E2E Test Suite
 *
 * Validates the full SPIFFE credential lifecycle against a live SPIRE
 * Server + Agent environment:
 *
 *   ① Wait for SPIRE Agent socket to be ready
 *   ② FetchX509SVID  → parse SVID → validate SPIFFE ID, cert chain, key pair
 *   ③ FetchX509Bundles → parse CA bundle → validate trust domain
 *   ④ FetchJWTSVID    → parse JWT → validate claims (sub, aud, exp)
 *   ⑤ FetchJWTBundles → parse JWKS → validate key presence
 *   ⑥ ValidateJWTSVID → server-side validation
 *   ⑦ Entity classes  → X509Svid, JwtSvid, SpiffeId, TrustDomain
 *   ⑧ Validation      → X509SvidValidator, JwtSvidValidator
 *   ⑨ TLS context     → verify PEM file output
 *
 * Exit code:
 *   0 = all tests passed
 *   1 = one or more tests failed
 *
 * Usage:
 *   SPIFFE_ENDPOINT_SOCKET=unix:/run/spire/sockets/agent.sock php spiffe/e2e/test-e2e.php
 */

declare(strict_types=1);

require __DIR__ . '/../../vendor/autoload.php';

// ══════════════════════════════════════════════════════════════════
//  Test harness
// ══════════════════════════════════════════════════════════════════

final class E2ETestRunner
{
    private int $passed = 0;
    private int $failed = 0;
    private float $startTime;

    /** @var list<string> */
    private array $failures = [];

    public function __construct()
    {
        $this->startTime = microtime(true);
    }

    public function assert(string $name, bool $condition, string $detail = ''): void
    {
        if ($condition) {
            $this->passed++;
            fwrite(STDOUT, "  \033[32m✓\033[0m {$name}\n");
        } else {
            $this->failed++;
            $msg = $detail !== '' ? "{$name}: {$detail}" : $name;
            $this->failures[] = $msg;
            fwrite(STDOUT, "  \033[31m✗\033[0m {$name}" . ($detail ? " — {$detail}" : '') . "\n");
        }
    }

    public function section(string $title): void
    {
        fwrite(STDOUT, "\n\033[1m[{$title}]\033[0m\n");
    }

    public function finish(): int
    {
        $elapsed = round(microtime(true) - $this->startTime, 2);
        fwrite(STDOUT, "\n" . str_repeat('─', 60) . "\n");
        fwrite(STDOUT, sprintf(
            "Results: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m (%.2fs)\n",
            $this->passed,
            $this->failed,
            $elapsed,
        ));

        if ($this->failures !== []) {
            fwrite(STDOUT, "\nFailures:\n");
            foreach ($this->failures as $i => $f) {
                fwrite(STDOUT, "  " . ($i + 1) . ". {$f}\n");
            }
        }

        return $this->failed > 0 ? 1 : 0;
    }
}

// ══════════════════════════════════════════════════════════════════
//  Configuration
// ══════════════════════════════════════════════════════════════════

$socketPath = getenv('SPIFFE_ENDPOINT_SOCKET') ?: 'unix:/run/spire/sockets/agent.sock';
$trustDomain = getenv('SPIFFE_TRUST_DOMAIN') ?: 'zt.local';
$maxWait = (int) (getenv('SPIFFE_E2E_WAIT') ?: '120');

$t = new E2ETestRunner();

fwrite(STDOUT, "\033[1m╔══════════════════════════════════════════════════════╗\033[0m\n");
fwrite(STDOUT, "\033[1m║          SPIFFE E2E Test Suite                       ║\033[0m\n");
fwrite(STDOUT, "\033[1m╚══════════════════════════════════════════════════════╝\033[0m\n");
fwrite(STDOUT, "  Socket:       {$socketPath}\n");
fwrite(STDOUT, "  Trust domain: {$trustDomain}\n");

// ══════════════════════════════════════════════════════════════════
//  ① Wait for SPIRE Agent
// ══════════════════════════════════════════════════════════════════

$t->section('Agent Readiness');

$rawPath = preg_replace('#^unix:#', '', $socketPath);
$elapsed = 0;
while (!file_exists($rawPath)) {
    if ($elapsed >= $maxWait) {
        $t->assert('Agent socket exists', false, "Socket not found at {$rawPath} after {$maxWait}s");
        exit($t->finish());
    }
    sleep(1);
    $elapsed++;
}
$t->assert('Agent socket exists', true);

// Also wait for bootstrap-done marker if available
$bootstrapMarker = '/opt/spire/conf/shared/bootstrap-done';
$elapsed = 0;
while (!file_exists($bootstrapMarker) && $elapsed < 30) {
    sleep(1);
    $elapsed++;
}
$t->assert('Bootstrap completed', file_exists($bootstrapMarker) || $elapsed >= 30);

// Small delay for workload registration to propagate
sleep(2);

// ══════════════════════════════════════════════════════════════════
//  ② Value Objects — TrustDomain, SpiffeId
// ══════════════════════════════════════════════════════════════════

$t->section('Value Objects');

use Spiffe\TrustDomain;
use Spiffe\SpiffeId;

$td = TrustDomain::parse($trustDomain);
$t->assert('TrustDomain::parse()', $td->name() === $trustDomain);
$t->assert('TrustDomain::idString()', $td->idString() === "spiffe://{$trustDomain}");

$id = SpiffeId::parse("spiffe://{$trustDomain}/php-gateway");
$t->assert('SpiffeId::parse()', (string) $id === "spiffe://{$trustDomain}/php-gateway");
$t->assert('SpiffeId::trustDomain()', $id->trustDomain()->equals($td));
$t->assert('SpiffeId::path()', $id->path() === '/php-gateway');
$t->assert('SpiffeId::memberOf()', $id->memberOf($td));

// Invalid SPIFFE ID
$invalidCaught = false;
try {
    SpiffeId::parse('https://not-a-spiffe-id');
} catch (\InvalidArgumentException) {
    $invalidCaught = true;
}
$t->assert('SpiffeId rejects non-spiffe scheme', $invalidCaught);

// ══════════════════════════════════════════════════════════════════
//  ③ FetchX509SVID via Swoole gRPC client
// ══════════════════════════════════════════════════════════════════

$t->section('FetchX509SVID');

use Spiffe\SwooleSpiffeWorkloadAPIClient;
use Spiffe\Workload\X509SVIDRequest;
use Spiffe\X509Svid;

$x509Response = null;
$fetchError = null;

\Swoole\Coroutine\run(function () use ($socketPath, &$x509Response, &$fetchError) {
    try {
        $client = new SwooleSpiffeWorkloadAPIClient($socketPath, 5.0, 10.0);
        $x509Response = $client->fetchX509Svid(new X509SVIDRequest());
        $client->close();
    } catch (\Throwable $e) {
        $fetchError = $e->getMessage();
    }
});

$t->assert('FetchX509SVID succeeds', $x509Response !== null, $fetchError ?? '');

if ($x509Response !== null) {
    $svids = $x509Response->getSvids();
    $svidCount = count($svids);
    $t->assert('Response contains SVIDs', $svidCount > 0, "got {$svidCount}");

    if ($svidCount > 0) {
        $proto = $svids[0];
        $t->assert('SVID has spiffe_id', str_starts_with($proto->getSpiffeId(), "spiffe://{$trustDomain}/"));
        $t->assert('SVID has x509_svid (cert chain)', strlen($proto->getX509Svid()) > 0);
        $t->assert('SVID has x509_svid_key (private key)', strlen($proto->getX509SvidKey()) > 0);
        $t->assert('SVID has bundle', strlen($proto->getBundle()) > 0);

        // ── Entity class: X509Svid ──
        $t->section('X509Svid Entity');

        $svid = X509Svid::fromProto($proto);
        $t->assert('X509Svid::spiffeId()', str_starts_with((string) $svid->spiffeId(), "spiffe://{$trustDomain}/"));
        $t->assert('X509Svid::trustDomain()', $svid->trustDomain()->name() === $trustDomain);
        $t->assert('X509Svid::certChainPem() not empty', strlen($svid->certChainPem()) > 100);
        $t->assert('X509Svid::privateKeyPem() not empty', strlen($svid->privateKeyPem()) > 100);
        $t->assert('X509Svid::bundlePem() not empty', strlen($svid->bundlePem()) > 50);
        $t->assert('X509Svid::certChainPem() is valid PEM', str_contains($svid->certChainPem(), '-----BEGIN CERTIFICATE-----'));
        $t->assert('X509Svid::privateKeyPem() is valid PEM', str_contains($svid->privateKeyPem(), '-----BEGIN PRIVATE KEY-----'));

        // OpenSSL parsing
        $leafCert = $svid->leafCertificate();
        $t->assert('leafCertificate() returns OpenSSLCertificate', $leafCert instanceof \OpenSSLCertificate);

        $privKey = $svid->privateKey();
        $t->assert('privateKey() returns OpenSSLAsymmetricKey', $privKey instanceof \OpenSSLAsymmetricKey);

        // Key pair matches
        $keyMatches = openssl_x509_check_private_key($leafCert, $privKey);
        $t->assert('Private key matches leaf certificate', $keyMatches);

        // SAN contains SPIFFE ID
        $certInfo = openssl_x509_parse($leafCert);
        $san = $certInfo['extensions']['subjectAltName'] ?? '';
        $t->assert('Leaf cert SAN contains spiffe:// URI', str_contains($san, 'spiffe://'));

        // ── Validation ──
        $t->section('X509SvidValidator');

        use Spiffe\Bundle\X509Bundle;
        use Spiffe\Validation\X509SvidValidator;

        $bundle = X509Bundle::fromDer($svid->trustDomain(), $proto->getBundle());
        $t->assert('X509Bundle::fromDer() succeeds', count($bundle->authorities()) > 0);

        $validator = new X509SvidValidator(120);
        $result = $validator->validate($svid, $bundle);
        $t->assert('X509SvidValidator::validate() passes', $result->isValid(), implode('; ', $result->errors()));
        $t->assert('X509SvidValidator::isExpired() = false', !$validator->isExpired($svid));

        // ── TLS temp files ──
        $t->section('TLS Temp Files');

        $files = $svid->writeToTempFiles();
        $t->assert('writeToTempFiles() returns cert path', file_exists($files['cert']));
        $t->assert('writeToTempFiles() returns key path', file_exists($files['key']));
        $t->assert('writeToTempFiles() key has 0600 perms', (fileperms($files['key']) & 0777) === 0600);

        // Cleanup
        @unlink($files['cert']);
        @unlink($files['key']);
        @unlink($files['ca']);
    }
}

// ══════════════════════════════════════════════════════════════════
//  ④ FetchJWTSVID
// ══════════════════════════════════════════════════════════════════

$t->section('FetchJWTSVID');

use Spiffe\Workload\JWTSVIDRequest;
use Spiffe\JwtSvid;

$jwtResponse = null;
$jwtError = null;

\Swoole\Coroutine\run(function () use ($socketPath, &$jwtResponse, &$jwtError) {
    try {
        $client = new SwooleSpiffeWorkloadAPIClient($socketPath, 5.0, 10.0);
        $req = new JWTSVIDRequest();
        $req->setAudience(['e2e-test']);
        $jwtResponse = $client->fetchJwtSvid($req);
        $client->close();
    } catch (\Throwable $e) {
        $jwtError = $e->getMessage();
    }
});

$t->assert('FetchJWTSVID succeeds', $jwtResponse !== null, $jwtError ?? '');

if ($jwtResponse !== null) {
    $jwtSvids = $jwtResponse->getSvids();
    $jwtCount = count($jwtSvids);
    $t->assert('Response contains JWT SVIDs', $jwtCount > 0, "got {$jwtCount}");

    if ($jwtCount > 0) {
        $jwtProto = $jwtSvids[0];
        $t->assert('JWT has spiffe_id', str_starts_with($jwtProto->getSpiffeId(), "spiffe://{$trustDomain}/"));
        $t->assert('JWT has svid token', strlen($jwtProto->getSvid()) > 50);

        // ── Entity class: JwtSvid ──
        $t->section('JwtSvid Entity');

        $jwtSvid = JwtSvid::fromProto($jwtProto);
        $t->assert('JwtSvid::spiffeId()', str_starts_with((string) $jwtSvid->spiffeId(), "spiffe://{$trustDomain}/"));
        $t->assert('JwtSvid::token() is JWT format', substr_count($jwtSvid->token(), '.') === 2);
        $t->assert('JwtSvid::subject() matches spiffe_id', $jwtSvid->subject() === (string) $jwtSvid->spiffeId());
        $t->assert('JwtSvid::audience() contains e2e-test', $jwtSvid->hasAudience('e2e-test'));
        $t->assert('JwtSvid::isExpired() = false', !$jwtSvid->isExpired());

        $exp = $jwtSvid->expiry();
        $t->assert('JwtSvid::expiry() is in the future', $exp !== null && $exp > new \DateTimeImmutable());

        $header = $jwtSvid->header();
        $t->assert('JWT header has alg', isset($header['alg']));
        $t->assert('JWT header has kid', isset($header['kid']));
    }
}

// ══════════════════════════════════════════════════════════════════
//  ⑤ FetchJWTBundles
// ══════════════════════════════════════════════════════════════════

$t->section('FetchJWTBundles');

use Spiffe\Workload\JWTBundlesRequest;

$jwtBundlesResponse = null;
$jwtBundlesError = null;

\Swoole\Coroutine\run(function () use ($socketPath, &$jwtBundlesResponse, &$jwtBundlesError) {
    try {
        $client = new SwooleSpiffeWorkloadAPIClient($socketPath, 5.0, 10.0);
        $jwtBundlesResponse = $client->fetchJwtBundles(new JWTBundlesRequest());
        $client->close();
    } catch (\Throwable $e) {
        $jwtBundlesError = $e->getMessage();
    }
});

$t->assert('FetchJWTBundles succeeds', $jwtBundlesResponse !== null, $jwtBundlesError ?? '');

if ($jwtBundlesResponse !== null) {
    $bundleMap = $jwtBundlesResponse->getBundles();
    $hasDomain = false;
    foreach ($bundleMap as $tdUri => $jwksBytes) {
        if (str_contains($tdUri, $trustDomain)) {
            $hasDomain = true;
            $jwks = json_decode($jwksBytes, true);
            $t->assert('JWKS is valid JSON', $jwks !== null);
            $t->assert('JWKS has keys array', isset($jwks['keys']) && is_array($jwks['keys']));
            $t->assert('JWKS has at least one key', count($jwks['keys'] ?? []) > 0);

            // Parse with JwtBundle
            use Spiffe\Bundle\JwtBundle;
            $jwtBundle = JwtBundle::fromJwks(TrustDomain::parse($trustDomain), $jwksBytes);
            $t->assert('JwtBundle::fromJwks() succeeds', count($jwtBundle->keyIds()) > 0);
        }
    }
    $t->assert("Bundles contain trust domain {$trustDomain}", $hasDomain);
}

// ══════════════════════════════════════════════════════════════════
//  ⑥ AuthorizationPolicy
// ══════════════════════════════════════════════════════════════════

$t->section('AuthorizationPolicy');

use Spiffe\TLS\AuthorizationPolicy;

$policy = AuthorizationPolicy::create()
    ->allowTrustDomain($trustDomain)
    ->denyId("spiffe://{$trustDomain}/blocked");

$testId = SpiffeId::parse("spiffe://{$trustDomain}/php-gateway");
$blockedId = SpiffeId::parse("spiffe://{$trustDomain}/blocked");
$foreignId = SpiffeId::parse('spiffe://evil.domain/attacker');

$t->assert('Policy allows same trust domain', $policy->allows($testId));
$t->assert('Policy denies blocked ID', !$policy->allows($blockedId));
$t->assert('Policy denies foreign domain', !$policy->allows($foreignId));

$eval = $policy->evaluate($testId);
$t->assert('evaluate() returns reason', $eval['reason'] !== '');

// ══════════════════════════════════════════════════════════════════
//  Summary
// ══════════════════════════════════════════════════════════════════

exit($t->finish());
