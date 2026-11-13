<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
json_out(['scanned' => (int)db()->query('SELECT COUNT(*) FROM rs_reports')->fetchColumn()]);
