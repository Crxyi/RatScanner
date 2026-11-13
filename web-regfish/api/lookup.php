<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
$sha = strtolower((string)($_GET['sha256'] ?? ''));
if (!preg_match('/^[0-9a-f]{64}$/', $sha)) fail('Please enter a SHA-256 hash (64 hex characters).');
$st = db()->prepare('SELECT sha256, file_name, verdict, score, type, first_seen, last_seen, submissions, summary FROM rs_reports WHERE sha256 = ?');
$st->execute([$sha]);
$r = $st->fetch();
if (!$r) json_out(['found' => false, 'sha256' => $sha]);
$r['summary'] = json_decode((string)$r['summary'], true) ?: [];
json_out(['found' => true, 'report' => $r]);
