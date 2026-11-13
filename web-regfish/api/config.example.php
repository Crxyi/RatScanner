<?php
return [
    // ---- Database (regfish dashboard -> Datenbank) ----
    'db_host' => '',
    'db_name' => '',
    'db_user' => '',
    'db_pass' => '',

    // ---- Website ----
    'public_url' => 'https://ratscan.org',
    'secret_salt' => '',

    // ---- Discord login / server ----
    'discord_client_id' => '',
    'discord_client_secret' => '',
    'discord_bot_token' => '',
    'discord_guild_id' => '',
    'discord_join_role' => '',
    'discord_invite' => ''

    // ---- Plans: Discord role IDs (right-click role -> Copy Role ID) ----
    'role_starter' => '',
    'role_pro' => '',
    'role_enterprise' => '',
    'plans_contact' => '',

    // ---- Daily scan limits ----
    'limit_guest_jars' => 5,
    'limit_free_user' => 30,
    'limit_starter' => 100,
    'limit_pro' => 500,
    'limit_enterprise' => 100000,
    'limit_url_fetch' => 20,

    // ---- Cloudflare (optional) ----
    'turnstile_sitekey' => '',
    'turnstile_secret' => '',
    'trust_cloudflare' => false,
];
