<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
require_post_same_origin();
$in = read_json(300000);
$token = (string)($in['ticket'] ?? '');
$sha = strtolower((string)($in['sha256'] ?? ''));
if (!preg_match('/^[0-9a-f]{32}$/', $token) || !preg_match('/^[0-9a-f]{64}$/', $sha)) fail('Invalid request');
$pdo = db();
$upgrade = !empty($in['upgrade']);
$st = $pdo->prepare('UPDATE rs_tickets SET used = ? WHERE token = ? AND sha256 = ? AND used = ? AND created > ?');
$st->execute($upgrade ? [2, $token, $sha, 1, time() - 3600] : [1, $token, $sha, 0, time() - 3600]);
if ($st->rowCount() !== 1) fail('Ticket invalid or already used', 409);
$t = $pdo->prepare('SELECT user_id FROM rs_tickets WHERE token = ?');
$t->execute([$token]);
$uid = $t->fetchColumn() ?: null;
$order = ['CLEAN' => 0, 'CAUTION' => 1, 'SUSPICIOUS' => 2, 'MALICIOUS' => 3];
$verdict = (string)($in['verdict'] ?? '');
if (!isset($order[$verdict])) fail('Invalid verdict');
$score = max(0, min(100, (int)($in['score'] ?? 0)));
$name = mb_substr(preg_replace('/[\x00-\x1f]/', '', (string)($in['fileName'] ?? 'file')), 0, 160);
$type = mb_substr((string)($in['type'] ?? ''), 0, 60);
$summary = [];
foreach (array_slice(is_array($in['findings'] ?? null) ? $in['findings'] : [], 0, 40) as $f) {
    if (!is_array($f)) continue;
    $sev = (string)($f['severity'] ?? '');
    if (!in_array($sev, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'], true)) continue;
    $summary[] = ['severity' => $sev, 'title' => mb_substr((string)($f['title'] ?? ''), 0, 160), 'category' => mb_substr((string)($f['category'] ?? ''), 0, 40)];
}
if ($upgrade) {
    $pdo->prepare('UPDATE rs_reports SET verdict = IF(FIELD(verdict, \'CLEAN\', \'CAUTION\', \'SUSPICIOUS\', \'MALICIOUS\') < ?, ?, verdict), score = GREATEST(score, ?), summary = IF(FIELD(verdict, \'CLEAN\', \'CAUTION\', \'SUSPICIOUS\', \'MALICIOUS\') <= ?, ?, summary) WHERE sha256 = ?')
        ->execute([$order[$verdict] + 1, $verdict, $score, $order[$verdict] + 1, json_encode($summary), $sha]);
    json_out(['ok' => true]);
}
$ex = $pdo->prepare('SELECT verdict FROM rs_reports WHERE sha256 = ?');
$ex->execute([$sha]);
$old = $ex->fetchColumn();
if ($old === false) {
    $pdo->prepare('INSERT INTO rs_reports (sha256, file_name, verdict, score, type, first_seen, last_seen, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        ->execute([$sha, $name, $verdict, $score, $type, time(), time(), json_encode($summary)]);
} elseif ($order[$verdict] >= ($order[$old] ?? 0)) {
    $pdo->prepare('UPDATE rs_reports SET verdict = ?, score = GREATEST(score, ?), summary = ?, last_seen = ?, submissions = submissions + 1 WHERE sha256 = ?')
        ->execute([$verdict, $score, json_encode($summary), time(), $sha]);
} else {
    $pdo->prepare('UPDATE rs_reports SET last_seen = ?, submissions = submissions + 1 WHERE sha256 = ?')->execute([time(), $sha]);
}
if ($uid) {
    $pdo->prepare('INSERT IGNORE INTO rs_user_files (user_id, sha256, created) VALUES (?, ?, ?)')->execute([$uid, $sha, time()]);
    $pdo->prepare('UPDATE rs_users SET scans = scans + 1, last_scan = ? WHERE id = ?')->execute([time(), $uid]);
}
json_out(['ok' => true]);
