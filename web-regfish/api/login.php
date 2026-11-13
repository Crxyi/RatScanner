<?php
declare(strict_types=1);
require __DIR__ . '/lib.php';
if (!cfg('discord_client_id') || !cfg('discord_client_secret')) fail('Discord login is not configured.', 503);
start_session();
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;
$scope = (cfg('discord_bot_token') && cfg('discord_guild_id')) ? 'identify guilds.join' : 'identify';
header('Location: https://discord.com/oauth2/authorize?' . http_build_query([
    'response_type' => 'code', 'client_id' => cfg('discord_client_id'), 'scope' => $scope, 'prompt' => 'none',
    'redirect_uri' => base_url() . '/api/callback.php', 'state' => $state,
]), true, 302);
