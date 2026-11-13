<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
$u = current_user();
$out = [
    'loggedIn' => (bool)$u,
    'discordEnabled' => (bool)(cfg('discord_client_id') && cfg('discord_client_secret')),
    'joinsServer' => (bool)(cfg('discord_bot_token') && cfg('discord_guild_id')),
    'turnstileSiteKey' => cfg('turnstile_sitekey'),
    'invite' => cfg('discord_invite'),
    'plansContact' => cfg('plans_contact', ''),
    'guestJarsPerDay' => (int)cfg('limit_guest_jars', 5),
];
if ($u) {
    refresh_plan($u);
    $files = (int)db()->query('SELECT COUNT(*) FROM rs_user_files WHERE user_id = ' . db()->quote($u['id']))->fetchColumn();
    $st = db()->prepare('SELECT COUNT(*) FROM (SELECT user_id, COUNT(*) c FROM rs_user_files GROUP BY user_id) t WHERE t.c > ?');
    $st->execute([$files]);
    $limit = daily_limit($u);
    $out['user'] = public_user($u) + [
        'files' => $files, 'scans' => (int)$u['scans'], 'rank' => $files > 0 ? (int)$st->fetchColumn() + 1 : 0,
        'plan' => plans()[$u['plan'] ?? '']['name'] ?? null, 'limit' => $limit, 'usedToday' => quota_used('u:' . $u['id']),
    ];
} else {
    $out['guestLeft'] = max(0, (int)cfg('limit_guest_jars', 5) - quota_used(ip_key()));
}
json_out($out);
