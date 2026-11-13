<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
$rows = db()->query('SELECT u.*, f.c AS files FROM rs_users u JOIN (SELECT user_id, COUNT(*) c FROM rs_user_files GROUP BY user_id) f ON f.user_id = u.id
    ORDER BY f.c DESC, u.scans DESC, u.first_seen ASC LIMIT 50')->fetchAll();
$out = [];
foreach ($rows as $i => $u) $out[] = public_user($u) + ['rank' => $i + 1, 'files' => (int)$u['files'], 'scans' => (int)$u['scans']];
json_out(['entries' => $out]);
