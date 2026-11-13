<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
require_post_same_origin();
$in = read_json(8000);
$url = trim((string)($in['url'] ?? ''));
if (!quota_take('f:' . ip_key(), (int)cfg('limit_url_fetch', 20))) fail('Too many URL scans today. Download the file and drop it here instead.', 429);
if (!verify_turnstile(isset($in['turnstile']) ? (string)$in['turnstile'] : null)) fail('Security check failed. Please complete the Cloudflare check and try again.', 403);
@set_time_limit(90);

if (!function_exists('str_starts_with')) {
    function str_starts_with(string $h, string $n): bool { return strncmp($h, $n, strlen($n)) === 0; }
}
function utf8_clean(string $s): string
{
    if (function_exists('mb_convert_encoding')) return mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    if (function_exists('iconv')) return (string)@iconv('UTF-8', 'UTF-8//IGNORE', $s);
    return preg_replace('/[\x80-\xff]/', '?', $s);
}

const FILE_MAX = 100 * 1024 * 1024;
const PAGE_MAX = 3 * 1024 * 1024;
const SCRIPT_MAX = 1536 * 1024;
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 RatScanner/1.0';

function public_ip(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false
        && !preg_match('/^(0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|192\.0\.0\.|198\.1[89]\.|::ffff:)/i', $ip);
}

function resolve_url(string $base, string $rel): string
{
    $rel = trim(html_entity_decode($rel, ENT_QUOTES | ENT_HTML5));
    if ($rel === '') return '';
    if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $rel)) return $rel;
    $b = parse_url($base);
    $scheme = $b['scheme'] ?? 'https';
    $auth = ($b['host'] ?? '') . (isset($b['port']) ? ':' . $b['port'] : '');
    if (str_starts_with($rel, '//')) return $scheme . ':' . $rel;
    if (str_starts_with($rel, '/')) return $scheme . '://' . $auth . $rel;
    $path = $b['path'] ?? '/';
    if ($rel[0] === '?' || $rel[0] === '#') return $scheme . '://' . $auth . $path . $rel;
    $dir = substr($path, 0, (int)strrpos($path, '/') + 1);
    $parts = [];
    foreach (explode('/', $dir . $rel) as $seg) {
        if ($seg === '..') array_pop($parts);
        elseif ($seg !== '.') $parts[] = $seg;
    }
    return $scheme . '://' . $auth . implode('/', $parts);
}

/* Fetches a URL hop by hop and re-checks every redirect target against private/metadata addresses. */
function safe_get(string $url, int $fileMax, int $timeout, bool $wantCert = false): array
{
    $chain = [];
    for ($hop = 0; $hop < 8; $hop++) {
        $p = parse_url($url);
        $scheme = strtolower((string)($p['scheme'] ?? ''));
        $host = strtolower((string)($p['host'] ?? ''));
        $port = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        if (!in_array($scheme, ['http', 'https'], true)) return ['error' => 'only http(s) links are allowed', 'chain' => $chain];
        if ($host === '' || !in_array($port, [80, 443, 8080, 8443], true)) return ['error' => 'invalid host or port', 'chain' => $chain];
        $h = trim($host, '[]');
        $ips = filter_var($h, FILTER_VALIDATE_IP) ? [$h] : array_merge(gethostbynamel($h) ?: [], array_column(@dns_get_record($h, DNS_AAAA) ?: [], 'ipv6'));
        if (!$ips) return ['error' => 'host not found', 'chain' => $chain];
        foreach ($ips as $ip) if (!public_ip($ip)) return ['error' => 'private, loopback and cloud metadata addresses are refused', 'chain' => $chain];
        $pin = $ips[0];
        $size = 0; $buf = ''; $headers = []; $isPage = false; $truncated = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_RESOLVE => [$h . ':' . $port . ':' . (strpos($pin, ':') !== false ? '[' . $pin . ']' : $pin)],
            CURLOPT_USERAGENT => UA,
            CURLOPT_HTTPHEADER => ['Accept: text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Language: en-US,en;q=0.8'],
            CURLOPT_ENCODING => '',
            CURLOPT_CERTINFO => $wantCert,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers, &$isPage) {
                $i = strpos($line, ':');
                if ($i !== false) {
                    $k = strtolower(trim(substr($line, 0, $i)));
                    $v = trim(substr($line, $i + 1));
                    if (count($headers) < 60) $headers[$k] = mb_substr($v, 0, 400);
                    if ($k === 'content-type' && preg_match('#text/html|application/xhtml#i', $v)) $isPage = true;
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$size, &$buf, &$isPage, &$truncated, $fileMax) {
                $max = $isPage ? PAGE_MAX : $fileMax;
                if ($size + strlen($chunk) > $max) { $buf .= substr($chunk, 0, max(0, $max - $size)); $size = $max + 1; $truncated = true; return 0; }
                $size += strlen($chunk);
                $buf .= $chunk;
                return strlen($chunk);
            },
        ]);
        curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $loc = (string)curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        $err = curl_errno($ch);
        $errMsg = curl_error($ch);
        $cert = $wantCert ? (curl_getinfo($ch, CURLINFO_CERTINFO) ?: []) : [];
        curl_close($ch);
        $chain[] = ['url' => $url, 'code' => $code, 'ip' => $pin];
        if ($code >= 300 && $code < 400 && $loc !== '') { $url = $loc; continue; }
        if ($err && !($truncated && $err === 23)) {
            if (in_array($err, [51, 58, 60], true)) return ['error' => 'the HTTPS certificate is invalid (' . $errMsg . ') – do not trust this site', 'certError' => true, 'chain' => $chain];
            return ['error' => 'connection failed (' . $errMsg . ')', 'chain' => $chain];
        }
        return ['url' => $url, 'code' => $code, 'ip' => $pin, 'headers' => $headers, 'body' => $buf, 'page' => $isPage, 'truncated' => $truncated, 'chain' => $chain, 'cert' => $cert];
    }
    return ['error' => 'too many redirects', 'chain' => $chain];
}

function reg_domain(string $host): string
{
    if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) return $host;
    $p = explode('.', $host);
    $n = count($p);
    if ($n <= 2) return $host;
    $two = $p[$n - 2] . '.' . $p[$n - 1];
    $sl = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.br', 'com.tr', 'co.jp', 'co.kr', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.ar', 'com.pl', 'com.ru', 'com.ua', 'co.il', 'com.sg', 'com.hk', 'com.tw'];
    return in_array($two, $sl, true) ? $p[$n - 3] . '.' . $two : $two;
}

function rdap(string $domain): ?array
{
    if (!preg_match('/^[a-z0-9-]+(\.[a-z0-9-]+)+$/', $domain)) return null;
    $ch = curl_init('https://rdap.org/domain/' . rawurlencode($domain));
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_TIMEOUT => 6, CURLOPT_CONNECTTIMEOUT => 4,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS, CURLOPT_USERAGENT => 'RatScanner/1.0', CURLOPT_HTTPHEADER => ['Accept: application/rdap+json']]);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if (!is_string($raw) || $code !== 200 || strlen($raw) > 400000) return null;
    $j = json_decode($raw, true);
    if (!is_array($j)) return null;
    $out = ['domain' => $domain];
    foreach (($j['events'] ?? []) as $ev) {
        $a = $ev['eventAction'] ?? '';
        if ($a === 'registration') $out['created'] = $ev['eventDate'] ?? null;
        if ($a === 'expiration') $out['expires'] = $ev['eventDate'] ?? null;
        if ($a === 'last changed') $out['changed'] = $ev['eventDate'] ?? null;
    }
    foreach (($j['entities'] ?? []) as $en) {
        if (in_array('registrar', $en['roles'] ?? [], true)) {
            foreach (($en['vcardArray'][1] ?? []) as $vc) if (($vc[0] ?? '') === 'fn') $out['registrar'] = mb_substr((string)$vc[3], 0, 120);
        }
    }
    return $out;
}

function cert_summary(array $cert): ?array
{
    $c = $cert[0] ?? null;
    if (!is_array($c)) return null;
    $issuer = (string)($c['Issuer'] ?? '');
    $subject = (string)($c['Subject'] ?? '');
    $org = preg_match('/O\s*=\s*([^,\/]+)/', $issuer, $m) ? trim($m[1]) : $issuer;
    $cn = preg_match('/CN\s*=\s*([^,\/]+)/', $subject, $m2) ? trim($m2[1]) : $subject;
    return ['issuer' => mb_substr($org, 0, 120), 'subject' => mb_substr($cn, 0, 160), 'from' => $c['Start date'] ?? null, 'to' => $c['Expire date'] ?? null];
}

$r = safe_get($url, FILE_MAX, 60, true);
if (isset($r['error'])) {
    if (!empty($r['certError'])) fail('Scan failed: ' . $r['error'], 400, ['certError' => true]);
    fail('Download failed: ' . $r['error']);
}
if (!$r['page'] && $r['code'] === 200 && preg_match('/^\s*(<!doctype html|<html|<head|<body)/i', substr($r['body'], 0, 512))) $r['page'] = true;

if (!$r['page']) {
    if ($r['truncated']) fail('Download failed: file is larger than 100 MB');
    if ($r['code'] !== 200) fail('Download failed: server answered with HTTP ' . $r['code']);
    $name = basename((string)parse_url($r['url'], PHP_URL_PATH)) ?: 'download.jar';
    header('Content-Type: application/octet-stream');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    header('X-File-Name: ' . rawurlencode(mb_substr(urldecode($name), 0, 120)));
    header('Content-Length: ' . strlen($r['body']));
    echo $r['body'];
    exit;
}

/* A web page: collect what is needed to judge it, as plain text. Nothing of it is ever run. */
$html = $r['body'];
$final = $r['url'];
$base = preg_match('/<base\b[^>]*\bhref\s*=\s*["\']?([^"\'\s>]+)/i', $html, $bm) ? resolve_url($final, $bm[1]) : $final;
$srcs = [];
if (preg_match_all('/<script\b[^>]*\bsrc\s*=\s*["\']?([^"\'\s>]+)/i', $html, $sm)) {
    foreach ($sm[1] as $s) { $u = resolve_url($base, $s); if (preg_match('#^https?://#i', $u) && !in_array($u, $srcs, true)) $srcs[] = $u; }
}
$scripts = [];
$t0 = microtime(true);
foreach (array_slice($srcs, 0, 15) as $s) {
    if (microtime(true) - $t0 > 25) { $scripts[] = ['url' => $s, 'skipped' => 'time limit']; continue; }
    $g = safe_get($s, SCRIPT_MAX, 8);
    if (isset($g['error'])) { $scripts[] = ['url' => $s, 'error' => $g['error']]; continue; }
    $scripts[] = ['url' => $s, 'final' => $g['url'], 'code' => $g['code'], 'size' => strlen($g['body']), 'truncated' => $g['truncated'], 'body' => utf8_clean($g['body'])];
}
foreach (array_slice($srcs, 15) as $s) $scripts[] = ['url' => $s, 'skipped' => 'limit'];

$host = strtolower((string)parse_url($final, PHP_URL_HOST));
$startHost = strtolower((string)parse_url($r['chain'][0]['url'] ?? $final, PHP_URL_HOST));
$domain = filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) ? null : rdap(reg_domain($host));
$startDomain = reg_domain($startHost) !== reg_domain($host) && !filter_var(trim($startHost, '[]'), FILTER_VALIDATE_IP) ? rdap(reg_domain($startHost)) : null;

json_out([
    'kind' => 'page',
    'url' => $r['chain'][0]['url'] ?? $final,
    'final' => $final,
    'code' => $r['code'],
    'ip' => $r['ip'],
    'chain' => $r['chain'],
    'headers' => $r['headers'],
    'cert' => str_starts_with($final, 'https:') ? cert_summary($r['cert']) : null,
    'domain' => $domain,
    'startDomain' => $startDomain,
    'truncated' => $r['truncated'],
    'html' => utf8_clean($html),
    'scripts' => $scripts,
]);
