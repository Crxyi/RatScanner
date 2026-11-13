<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
require_post_same_origin();
start_session();
$_SESSION = [];
session_destroy();
json_out(['ok' => true]);
