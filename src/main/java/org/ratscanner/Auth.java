package org.ratscanner;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.sun.net.httpserver.HttpExchange;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

final class Auth {

    static final class User {
        String id;
        String username;
        String globalName;
        String avatar;
        long firstSeen;
        long lastScan;
        int scans;
        Set<String> files = new LinkedHashSet<>();
        String plan;
        long planChecked;
        long planSince;
        String apiKeyHash;
        String apiKeyPrefix;
        long apiKeyCreated;
    }

    static final String CLIENT_ID = env("DISCORD_CLIENT_ID");
    static final String CLIENT_SECRET = env("DISCORD_CLIENT_SECRET");
    static final String PUBLIC_URL = Optional.ofNullable(env("PUBLIC_URL")).orElse("http://localhost:8080").replaceAll("/+$", "");
    static final String TURNSTILE_SITEKEY = env("TURNSTILE_SITEKEY");
    static final String TURNSTILE_SECRET = env("TURNSTILE_SECRET");
    static final boolean REQUIRE_LOGIN = env("REQUIRE_LOGIN") != null;
    static final boolean TRUST_CLOUDFLARE = env("TRUST_CLOUDFLARE") != null;
    static final int ANON_JARS_PER_DAY = Integer.parseInt(Optional.ofNullable(env("ANON_JARS_PER_DAY")).orElse("5"));
    static final String BOT_TOKEN = env("DISCORD_BOT_TOKEN");
    static final String GUILD_ID = env("DISCORD_GUILD_ID");
    static final String JOIN_ROLE_ID = env("DISCORD_JOIN_ROLE_ID");
    static final String GUILD_INVITE = env("DISCORD_INVITE_URL");

    static boolean autoJoinEnabled() {
        return discordEnabled() && BOT_TOKEN != null && GUILD_ID != null && GUILD_ID.matches("\\d{15,22}");
    }

    static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();
    private static final Gson GSON = new GsonBuilder().create();
    static final Map<String, User> USERS = new ConcurrentHashMap<>();
    private static final Map<String, Deque<Long>> RATE = new ConcurrentHashMap<>();
    private static byte[] secret;
    private static Path usersFile;

    private static final class Conf {
        static final Map<String, String> FILE = load();

        private static Map<String, String> load() {
            Map<String, String> m = new HashMap<>();
            Path p = Paths.get(Optional.ofNullable(System.getenv("RATSCANNER_CONFIG")).orElse("ratscanner.env"));
            if (!Files.exists(p)) return m;
            try {
                for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                    String l = line.trim();
                    if (l.isEmpty() || l.startsWith("#") || !l.contains("=")) continue;
                    String k = l.substring(0, l.indexOf('=')).trim();
                    String v = l.substring(l.indexOf('=') + 1).trim();
                    if (v.length() >= 2 && (v.startsWith("\"") && v.endsWith("\"") || v.startsWith("'") && v.endsWith("'"))) v = v.substring(1, v.length() - 1);
                    m.put(k, v);
                }
                System.out.println("Config loaded from " + p.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("Config " + p + ": " + e);
            }
            return m;
        }
    }

    static String env(String k) {
        String v = System.getenv(k);
        if (v == null || v.isBlank()) v = Conf.FILE.get(k);
        return v == null || v.isBlank() ? null : v.trim();
    }

    static boolean discordEnabled() {
        return CLIENT_ID != null && CLIENT_SECRET != null;
    }

    static boolean turnstileEnabled() {
        return TURNSTILE_SITEKEY != null && TURNSTILE_SECRET != null;
    }

    static void init(Path data) throws IOException {
        Path sf = data.resolve("session.key");
        String envSecret = env("SESSION_SECRET");
        if (envSecret != null) secret = envSecret.getBytes(StandardCharsets.UTF_8);
        else if (Files.exists(sf)) secret = Files.readAllBytes(sf);
        else {
            secret = new byte[32];
            Main.RNG.nextBytes(secret);
            Files.write(sf, secret);
            try {
                Files.setPosixFilePermissions(sf, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            } catch (Exception ignored) {
            }
        }
        usersFile = data.resolve("users.json");
        if (Files.exists(usersFile)) {
            Map<String, User> m = GSON.fromJson(Files.readString(usersFile), new TypeToken<Map<String, User>>() {
            }.getType());
            if (m != null) USERS.putAll(m);
        }
    }

    static synchronized void saveUsers() {
        try {
            Path tmp = usersFile.resolveSibling("users.json.tmp");
            Files.writeString(tmp, GSON.toJson(USERS));
            Files.move(tmp, usersFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            System.err.println("users.json: " + e);
        }
    }

    static String clientIp(HttpExchange ex) {
        if (TRUST_CLOUDFLARE) {
            String cf = ex.getRequestHeaders().getFirst("CF-Connecting-IP");
            if (cf != null && !cf.isBlank()) return cf.trim();
        }
        if (env("TRUST_PROXY") != null) {
            String fwd = ex.getRequestHeaders().getFirst("X-Forwarded-For");
            if (fwd != null && !fwd.isBlank()) return fwd.split(",")[0].trim();
        }
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }

    static boolean rateLimit(String key, int max, long windowMs) {
        Deque<Long> q = RATE.computeIfAbsent(key, k -> new ArrayDeque<>());
        long now = System.currentTimeMillis();
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) q.pollFirst();
            if (q.size() >= max) return false;
            q.addLast(now);
            return true;
        }
    }

    static int used(String key, long windowMs) {
        Deque<Long> q = RATE.get(key);
        if (q == null) return 0;
        long now = System.currentTimeMillis();
        synchronized (q) {
            while (!q.isEmpty() && now - q.peekFirst() > windowMs) q.pollFirst();
            return q.size();
        }
    }

    static boolean verifyTurnstile(String token, String ip) {
        if (!turnstileEnabled()) return true;
        if (token == null || token.isBlank() || token.length() > 4096) return false;
        try {
            String body = "secret=" + enc(TURNSTILE_SECRET) + "&response=" + enc(token) + "&remoteip=" + enc(ip);
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://challenges.cloudflare.com/turnstile/v0/siteverify"))
                    .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            JsonObject o = JsonParser.parseString(HTTP.send(req, HttpResponse.BodyHandlers.ofString()).body()).getAsJsonObject();
            return o.has("success") && o.get("success").getAsBoolean();
        } catch (Exception e) {
            System.err.println("Turnstile: " + e);
            return false;
        }
    }

    static User currentUser(HttpExchange ex) {
        String v = cookie(ex, "rs_session");
        if (v == null) return null;
        int dot = v.lastIndexOf('.');
        if (dot <= 0) return null;
        String payload = v.substring(0, dot);
        if (!MessageDigest.isEqual(sign(payload).getBytes(StandardCharsets.UTF_8), v.substring(dot + 1).getBytes(StandardCharsets.UTF_8))) return null;
        String[] p = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8).split("\\|");
        if (p.length != 2 || Long.parseLong(p[1]) < System.currentTimeMillis()) return null;
        return USERS.get(p[0]);
    }

    static void login(HttpExchange ex) throws IOException {
        if (!discordEnabled()) {
            Main.json(ex, 503, Map.of("error", "Discord login is not configured on this server (set DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET)."));
            return;
        }
        byte[] b = new byte[18];
        Main.RNG.nextBytes(b);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        setCookie(ex, "rs_state", state, 600);
        String scope = autoJoinEnabled() ? "identify%20guilds.join" : "identify";
        String url = "https://discord.com/oauth2/authorize?response_type=code&scope=" + scope + "&prompt=none"
                + "&client_id=" + enc(CLIENT_ID) + "&redirect_uri=" + enc(PUBLIC_URL + "/auth/callback") + "&state=" + enc(state);
        redirect(ex, url);
    }

    static void callback(HttpExchange ex, Map<String, String> q) throws IOException {
        String state = cookie(ex, "rs_state");
        setCookie(ex, "rs_state", "", 0);
        if (!discordEnabled() || state == null || !state.equals(q.get("state")) || q.get("code") == null) {
            redirect(ex, "/#/login-failed");
            return;
        }
        try {
            String form = "client_id=" + enc(CLIENT_ID) + "&client_secret=" + enc(CLIENT_SECRET) + "&grant_type=authorization_code"
                    + "&code=" + enc(q.get("code")) + "&redirect_uri=" + enc(PUBLIC_URL + "/auth/callback");
            HttpRequest tokenReq = HttpRequest.newBuilder(URI.create("https://discord.com/api/oauth2/token")).timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build();
            JsonObject tok = JsonParser.parseString(HTTP.send(tokenReq, HttpResponse.BodyHandlers.ofString()).body()).getAsJsonObject();
            if (!tok.has("access_token")) throw new IOException("no access token");
            HttpRequest meReq = HttpRequest.newBuilder(URI.create("https://discord.com/api/users/@me")).timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + tok.get("access_token").getAsString()).GET().build();
            JsonObject me = JsonParser.parseString(HTTP.send(meReq, HttpResponse.BodyHandlers.ofString()).body()).getAsJsonObject();
            String id = me.get("id").getAsString();
            if (autoJoinEnabled() && tok.has("scope") && tok.get("scope").getAsString().contains("guilds.join"))
                joinGuild(id, tok.get("access_token").getAsString());
            User u = USERS.computeIfAbsent(id, k -> {
                User n = new User();
                n.id = k;
                n.firstSeen = System.currentTimeMillis();
                return n;
            });
            u.username = str(me, "username");
            u.globalName = str(me, "global_name");
            u.avatar = str(me, "avatar");
            Plans.refresh(u, true);
            saveUsers();
            long exp = System.currentTimeMillis() + 30L * 24 * 3600 * 1000;
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString((id + "|" + exp).getBytes(StandardCharsets.UTF_8));
            setCookie(ex, "rs_session", payload + "." + sign(payload), 30 * 24 * 3600);
            redirect(ex, "/#/");
        } catch (Exception e) {
            System.err.println("Discord OAuth: " + e);
            redirect(ex, "/#/login-failed");
        }
    }

    private static void joinGuild(String userId, String accessToken) {
        try {
            JsonObject body = new JsonObject();
            body.addProperty("access_token", accessToken);
            if (JOIN_ROLE_ID != null && JOIN_ROLE_ID.matches("\\d{15,22}")) {
                JsonArray roles = new JsonArray();
                roles.add(JOIN_ROLE_ID);
                body.add("roles", roles);
            }
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://discord.com/api/v10/guilds/" + GUILD_ID + "/members/" + userId))
                    .timeout(Duration.ofSeconds(15)).header("Authorization", "Bot " + BOT_TOKEN).header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(body.toString())).build();
            HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            int c = res.statusCode();
            if (c == 201) System.out.println("Discord: added user " + userId + " to the server");
            else if (c == 204) {
                if (JOIN_ROLE_ID != null && JOIN_ROLE_ID.matches("\\d{15,22}")) {
                    HttpRequest role = HttpRequest.newBuilder(URI.create("https://discord.com/api/v10/guilds/" + GUILD_ID + "/members/" + userId + "/roles/" + JOIN_ROLE_ID))
                            .timeout(Duration.ofSeconds(15)).header("Authorization", "Bot " + BOT_TOKEN).PUT(HttpRequest.BodyPublishers.noBody()).build();
                    HTTP.send(role, HttpResponse.BodyHandlers.discarding());
                }
            } else System.err.println("Discord guild join failed: HTTP " + c + " " + res.body().replaceAll("\\s+", " ").substring(0, Math.min(200, res.body().length())));
        } catch (Exception e) {
            System.err.println("Discord guild join: " + e);
        }
    }

    static void logout(HttpExchange ex) throws IOException {
        setCookie(ex, "rs_session", "", 0);
        Main.json(ex, 200, Map.of("ok", true));
    }

    static Map<String, Object> me(HttpExchange ex) {
        Map<String, Object> m = new LinkedHashMap<>();
        User u = currentUser(ex);
        m.put("loggedIn", u != null);
        m.put("discordEnabled", discordEnabled());
        m.put("requireLogin", REQUIRE_LOGIN);
        m.put("turnstileSiteKey", turnstileEnabled() ? TURNSTILE_SITEKEY : null);
        m.put("joinsServer", autoJoinEnabled());
        m.put("anonJarsPerDay", ANON_JARS_PER_DAY);
        if (u == null) m.put("anonJarsLeft", Math.max(0, ANON_JARS_PER_DAY - used("day:" + clientIp(ex), 86_400_000L)));
        if (GUILD_INVITE != null && GUILD_INVITE.matches("https://(discord\\.gg|discord\\.com/invite)/[A-Za-z0-9-]+")) m.put("invite", GUILD_INVITE);
        if (u != null) {
            Plans.refresh(u, false);
            Map<String, Object> um = publicUser(u);
            um.put("rank", rankOf(u));
            um.putAll(Plans.accountInfo(u));
            m.put("user", um);
        }
        m.put("plansContact", Plans.CONTACT);
        return m;
    }

    static void recordScan(String userId, String sha256) {
        if (userId == null || sha256 == null) return;
        User u = USERS.get(userId);
        if (u == null) return;
        synchronized (u) {
            u.scans++;
            u.files.add(sha256);
            u.lastScan = System.currentTimeMillis();
        }
        saveUsers();
    }

    static List<Map<String, Object>> leaderboard(int limit) {
        List<User> list = new ArrayList<>(USERS.values());
        list.removeIf(u -> u.files.isEmpty());
        list.sort(Comparator.comparingInt((User u) -> u.files.size()).reversed().thenComparingInt(u -> -u.scans).thenComparingLong(u -> u.firstSeen));
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, list.size()); i++) {
            Map<String, Object> m = publicUser(list.get(i));
            m.put("rank", i + 1);
            out.add(m);
        }
        return out;
    }

    private static int rankOf(User u) {
        if (u.files.isEmpty()) return 0;
        int rank = 1;
        for (User o : USERS.values()) if (o != u && (o.files.size() > u.files.size() || (o.files.size() == u.files.size() && o.scans > u.scans))) rank++;
        return rank;
    }

    static Map<String, Object> publicUser(User u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", u.globalName != null ? u.globalName : u.username);
        m.put("username", u.username);
        m.put("avatar", u.avatar != null && u.avatar.matches("^(a_)?[0-9a-f]{32}$")
                ? "https://cdn.discordapp.com/avatars/" + u.id + "/" + u.avatar + ".png?size=64"
                : "https://cdn.discordapp.com/embed/avatars/" + (Long.parseLong(u.id) >> 22) % 6 + ".png");
        m.put("files", u.files.size());
        m.put("scans", u.scans);
        return m;
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
    }

    private static String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String cookie(HttpExchange ex, String name) {
        for (String h : ex.getRequestHeaders().getOrDefault("Cookie", List.of())) {
            for (String part : h.split(";")) {
                String p = part.trim();
                if (p.startsWith(name + "=")) return p.substring(name.length() + 1);
            }
        }
        return null;
    }

    private static void setCookie(HttpExchange ex, String name, String value, int maxAge) {
        boolean secure = PUBLIC_URL.startsWith("https://");
        ex.getResponseHeaders().add("Set-Cookie", name + "=" + value + "; Path=/; Max-Age=" + maxAge + "; HttpOnly; SameSite=Lax" + (secure ? "; Secure" : ""));
    }

    private static void redirect(HttpExchange ex, String url) throws IOException {
        ex.getResponseHeaders().set("Location", url);
        ex.sendResponseHeaders(302, -1);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }
}
