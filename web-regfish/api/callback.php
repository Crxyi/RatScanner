<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
start_session();
$state = $_SESSION['oauth_state'] ?? '';
unset($_SESSION['oauth_state']);
$code = $_GET['code'] ?? '';
if (!$state || !is_string($_GET['state'] ?? null) || !hash_equals($state, $_GET['state']) || !is_string($code) || $code === '') {
    header('Location: /#/login-failed', true, 302);
    exit;
}
[$c, $body] = http_req('POST', 'https://discord.com/api/oauth2/token', ['Content-Type: application/x-www-form-urlencoded'], http_build_query([
    'client_id' => cfg('discord_client_id'), 'client_secret' => cfg('discord_client_secret'), 'grant_type' => 'authorization_code',
    'code' => $code, 'redirect_uri' => base_url() . '/api/callback.php',
]));
$tok = json_decode($body, true);
if ($c !== 200 || empty($tok['access_token'])) { header('Location: /#/login-failed', true, 302); exit; }
[$c, $body] = http_req('GET', 'https://discord.com/api/users/@me', ['Authorization: Bearer ' . $tok['access_token']]);
$me = json_decode($body, true);
if ($c !== 200 || empty($me['id']) || !preg_match('/^\d{15,22}$/', (string)$me['id'])) { header('Location: /#/login-failed', true, 302); exit; }
$id = (string)$me['id'];
if (cfg('discord_bot_token') && cfg('discord_guild_id') && strpos((string)($tok['scope'] ?? ''), 'guilds.join') !== false) {
    $payload = ['access_token' => $tok['access_token']];
    if (cfg('discord_join_role')) $payload['roles'] = [(string)cfg('discord_join_role')];
    http_req('PUT', 'https://discord.com/api/v10/guilds/' . cfg('discord_guild_id') . '/members/' . $id, bot_auth(), json_encode($payload));
}
db()->prepare('INSERT INTO rs_users (id, username, global_name, avatar, first_seen) VALUES (?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE username = VALUES(username), global_name = VALUES(global_name), avatar = VALUES(avatar)')
    ->execute([$id, mb_substr((string)($me['username'] ?? ''), 0, 64), mb_substr((string)($me['global_name'] ?? ''), 0, 64), mb_substr((string)($me['avatar'] ?? ''), 0, 64), time()]);
$st = db()->prepare('SELECT * FROM rs_users WHERE id = ?');
$st->execute([$id]);
$u = $st->fetch();
refresh_plan($u, true);
session_regenerate_id(true);
$_SESSION['uid'] = $id;
header('Location: /#/', true, 302);
