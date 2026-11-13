<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
$p = [];
foreach (plans() as $id => $x) $p[] = ['id' => $id, 'name' => $x['name'], 'perDay' => $x['perDay']];
json_out(['plans' => $p, 'freeUser' => (int)cfg('limit_free_user', 30), 'guest' => (int)cfg('limit_guest_jars', 5), 'invite' => cfg('discord_invite', ''), 'contact' => cfg('plans_contact', '')]);
