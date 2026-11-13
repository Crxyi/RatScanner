<?php
declare(strict_types=1);

$GLOBALS['RS'] = require __DIR__ . '/config.php';

if (!function_exists('mb_substr')) {
    function mb_substr(string $s, int $start, ?int $length = null): string
    {
        return $length === null ? substr($s, $start) : substr($s, $start, $length);
    }
}

function cfg(string $k, $default = null)
{
    $v = $GLOBALS['RS'][$k] ?? null;
    return ($v === null || $v === '') ? $default : $v;
}

function json_out($data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(string $msg, int $code = 400, array $extra = []): void
{
    json_out(array_merge(['error' => $msg], $extra), $code);
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $pdo = new PDO('mysql:host=' . cfg('db_host') . ';dbname=' . cfg('db_name') . ';charset=utf8mb4', cfg('db_user'), cfg('db_pass'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } catch (Throwable $e) {
        fail('Database is not configured yet (api/config.php).', 500);
    }
    $pdo->exec("CREATE TABLE IF NOT EXISTS rs_users (
        id VARCHAR(25) PRIMARY KEY, username VARCHAR(64), global_name VARCHAR(64), avatar VARCHAR(64),
        first_seen INT NOT NULL DEFAULT 0, last_scan INT NOT NULL DEFAULT 0, scans INT NOT NULL DEFAULT 0,
        plan VARCHAR(20) NULL, plan_checked INT NOT NULL DEFAULT 0, plan_since INT NOT NULL DEFAULT 0
    ) CHARACTER SET utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS rs_user_files (
        user_id VARCHAR(25) NOT NULL, sha256 CHAR(64) NOT NULL, created INT NOT NULL, PRIMARY KEY (user_id, sha256)
    ) CHARACTER SET utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS rs_quota (
        k VARCHAR(80) NOT NULL, day CHAR(10) NOT NULL, n INT NOT NULL DEFAULT 0, PRIMARY KEY (k, day)
    ) CHARACTER SET utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS rs_tickets (
        token CHAR(32) PRIMARY KEY, sha256 CHAR(64) NOT NULL, user_id VARCHAR(25) NULL, created INT NOT NULL, used TINYINT NOT NULL DEFAULT 0
    ) CHARACTER SET utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS rs_reports (
        sha256 CHAR(64) PRIMARY KEY, file_name VARCHAR(160), verdict VARCHAR(12), score INT, type VARCHAR(60),
        first_seen INT NOT NULL, last_seen INT NOT NULL, submissions INT NOT NULL DEFAULT 1, summary MEDIUMTEXT
    ) CHARACTER SET utf8mb4");
    return $pdo;
}

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    session_name('rs_sess');
    session_set_cookie_params([
        'lifetime' => 60 * 60 * 24 * 30,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    ini_set('session.gc_maxlifetime', (string)(60 * 60 * 24 * 30));
    ini_set('session.use_strict_mode', '1');
    session_start();
}

function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') || (($_SERVER['SERVER_PORT'] ?? '') === '443');
}

function base_url(): string
{
    $u = cfg('public_url');
    if ($u) return rtrim($u, '/');
    return (is_https() ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost');
}

function current_user(): ?array
{
    start_session();
    $id = $_SESSION['uid'] ?? null;
    if (!$id) return null;
    $st = db()->prepare('SELECT * FROM rs_users WHERE id = ?');
    $st->execute([$id]);
    $u = $st->fetch();
    return $u ?: null;
}

function client_ip(): string
{
    if (cfg('trust_cloudflare') && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return (string)$_SERVER['HTTP_CF_CONNECTING_IP'];
    return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function ip_key(): string
{
    return 'ip:' . substr(hash_hmac('sha256', client_ip(), (string)cfg('secret_salt', 'ratscan')), 0, 40);
}

function require_post_same_origin(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') fail('Use POST', 405);
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '' && !empty($_SERVER['HTTP_REFERER'])) $origin = $_SERVER['HTTP_REFERER'];
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if ($origin === '' || parse_url($origin, PHP_URL_HOST) !== parse_url('http://' . $host, PHP_URL_HOST)) fail('Bad origin', 403);
}

function read_json(int $max = 400000): array
{
    $raw = file_get_contents('php://input', false, null, 0, $max + 1);
    if ($raw === false || strlen($raw) > $max) fail('Request too large', 413);
    $j = json_decode($raw, true);
    return is_array($j) ? $j : [];
}

function http_req(string $method, string $url, array $headers = [], ?string $body = null, int $timeout = 15): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    if ($body !== null) curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    $res = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return [$code, $res === false ? '' : (string)$res];
}

function plans(): array
{
    return [
        'enterprise' => ['name' => 'Enterprise', 'rank' => 3, 'perDay' => (int)cfg('limit_enterprise', 100000), 'role' => cfg('role_enterprise')],
        'pro' => ['name' => 'Pro', 'rank' => 2, 'perDay' => (int)cfg('limit_pro', 500), 'role' => cfg('role_pro')],
        'starter' => ['name' => 'Starter', 'rank' => 1, 'perDay' => (int)cfg('limit_starter', 100), 'role' => cfg('role_starter')],
    ];
}

function daily_limit(?array $u): int
{
    if (!$u) return (int)cfg('limit_guest_jars', 5);
    $p = plans()[$u['plan'] ?? ''] ?? null;
    return $p ? $p['perDay'] : (int)cfg('limit_free_user', 30);
}

function today(): string
{
    return gmdate('Y-m-d');
}

function quota_used(string $k): int
{
    $st = db()->prepare('SELECT n FROM rs_quota WHERE k = ? AND day = ?');
    $st->execute([$k, today()]);
    return (int)($st->fetchColumn() ?: 0);
}

function quota_take(string $k, int $limit): bool
{
    $pdo = db();
    $pdo->prepare('INSERT INTO rs_quota (k, day, n) VALUES (?, ?, 0) ON DUPLICATE KEY UPDATE n = n')->execute([$k, today()]);
    $st = $pdo->prepare('UPDATE rs_quota SET n = n + 1 WHERE k = ? AND day = ? AND n < ?');
    $st->execute([$k, today(), $limit]);
    if (mt_rand(1, 50) === 1) $pdo->exec("DELETE FROM rs_quota WHERE day < '" . gmdate('Y-m-d', time() - 3 * 86400) . "'");
    return $st->rowCount() === 1;
}

function bot_auth(): array
{
    return ['Authorization: Bot ' . cfg('discord_bot_token'), 'Content-Type: application/json'];
}

function refresh_plan(array &$u, bool $force = false): void
{
    $guild = cfg('discord_guild_id');
    $hasRoles = cfg('role_starter') || cfg('role_pro') || cfg('role_enterprise');
    if (!$guild || !cfg('discord_bot_token') || !$hasRoles) return;
    if (!$force && time() - (int)$u['plan_checked'] < 600) return;
    [$code, $body] = http_req('GET', 'https://discord.com/api/v10/guilds/' . $guild . '/members/' . $u['id'], bot_auth(), null, 8);
    $plan = $u['plan'];
    if ($code === 404) $plan = null;
    elseif ($code === 200) {
        $roles = json_decode($body, true)['roles'] ?? [];
        $plan = null;
        foreach (plans() as $id => $p) if ($p['role'] && in_array((string)$p['role'], $roles, true)) { $plan = $id; break; }
    } else {
        return;
    }
    $since = ($plan !== $u['plan']) ? ($plan ? time() : 0) : (int)$u['plan_since'];
    db()->prepare('UPDATE rs_users SET plan = ?, plan_checked = ?, plan_since = ? WHERE id = ?')->execute([$plan, time(), $since, $u['id']]);
    $u['plan'] = $plan;
    $u['plan_checked'] = time();
    $u['plan_since'] = $since;
}

function avatar_url(array $u): string
{
    if (!empty($u['avatar']) && preg_match('/^(a_)?[0-9a-f]{32}$/', $u['avatar'])) return 'https://cdn.discordapp.com/avatars/' . $u['id'] . '/' . $u['avatar'] . '.png?size=64';
    return 'https://cdn.discordapp.com/embed/avatars/' . ((int)substr($u['id'], -3) % 6) . '.png';
}

function public_user(array $u): array
{
    return ['name' => $u['global_name'] ?: $u['username'], 'username' => $u['username'], 'avatar' => avatar_url($u)];
}

function verify_turnstile(?string $token): bool
{
    $secret = cfg('turnstile_secret');
    if (!$secret || !cfg('turnstile_sitekey')) return true;
    if (!$token || strlen($token) > 4096) return false;
    [$code, $body] = http_req('POST', 'https://challenges.cloudflare.com/turnstile/v0/siteverify', ['Content-Type: application/x-www-form-urlencoded'],
        http_build_query(['secret' => $secret, 'response' => $token, 'remoteip' => client_ip()]), 10);
    $j = json_decode($body, true);
    return $code === 200 && !empty($j['success']);
}
