<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
$rank = ['enterprise' => 3, 'pro' => 2, 'starter' => 1];
$rows = db()->query("SELECT * FROM rs_users WHERE plan IS NOT NULL AND plan <> '' LIMIT 500")->fetchAll();
usort($rows, function ($a, $b) use ($rank) { return [($rank[$b['plan']] ?? 0), $a['plan_since']] <=> [($rank[$a['plan']] ?? 0), $b['plan_since']]; });
$out = [];
foreach ($rows as $u) $out[] = public_user($u) + ['plan' => plans()[$u['plan']]['name'] ?? $u['plan'], 'since' => (int)$u['plan_since']];
json_out(['entries' => $out]);
