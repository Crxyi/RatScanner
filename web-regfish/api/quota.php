<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
require_post_same_origin();
$in = read_json(8000);
$sha = strtolower((string)($in['sha256'] ?? ''));
$kind = (string)($in['kind'] ?? '');
if (!preg_match('/^[0-9a-f]{64}$/', $sha)) fail('Invalid file hash');
$u = current_user();
if ($kind !== 'jar' && !$u) fail('Log in with Discord to scan .exe, .dll, scripts and other programs. Without login you can scan .jar files.', 403, ['needLogin' => true]);
if (!verify_turnstile(isset($in['turnstile']) ? (string)$in['turnstile'] : null)) fail('Security check failed. Please complete the Cloudflare check and try again.', 403);
if ($u) refresh_plan($u);
$limit = daily_limit($u);
$key = $u ? 'u:' . $u['id'] : ip_key();
if (!quota_take($key, $limit)) {
    fail($u ? "You reached your daily limit of $limit scans. It resets at midnight (UTC)." : "You reached the limit of $limit scans per day without login. Log in with Discord for more.", 429, ['needLogin' => !$u]);
}
$token = bin2hex(random_bytes(16));
db()->prepare('INSERT INTO rs_tickets (token, sha256, user_id, created) VALUES (?, ?, ?, ?)')->execute([$token, $sha, $u['id'] ?? null, time()]);
if (mt_rand(1, 50) === 1) db()->exec('DELETE FROM rs_tickets WHERE created < ' . (time() - 86400));
json_out(['ticket' => $token, 'left' => max(0, $limit - quota_used($key))]);
