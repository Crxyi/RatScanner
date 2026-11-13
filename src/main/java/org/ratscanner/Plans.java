package org.ratscanner;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;

final class Plans {

    record Plan(String id, String name, int rank, int apiPerDay, String roleId) {
    }

    static final String CONTACT = Optional.ofNullable(Auth.env("PLANS_CONTACT")).orElse("");
    static final List<Plan> PLANS = List.of(
            new Plan("enterprise", "Enterprise", 3, intEnv("PLAN_ENTERPRISE_API_PER_DAY", 1000), Auth.env("DISCORD_ROLE_ENTERPRISE")),
            new Plan("pro", "Pro", 2, intEnv("PLAN_PRO_API_PER_DAY", 500), Auth.env("DISCORD_ROLE_PRO")),
            new Plan("starter", "Starter", 1, intEnv("PLAN_STARTER_API_PER_DAY", 100), Auth.env("DISCORD_ROLE_STARTER")));
    private static final long DAY = 86_400_000L;
    private static final long RECHECK = 10 * 60_000L;

    private static int intEnv(String k, int def) {
        try {
            return Integer.parseInt(Optional.ofNullable(Auth.env(k)).orElse(String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    static boolean rolesConfigured() {
        return Auth.BOT_TOKEN != null && Auth.GUILD_ID != null && PLANS.stream().anyMatch(p -> p.roleId() != null);
    }

    static Plan of(Auth.User u) {
        if (u == null || u.plan == null) return null;
        for (Plan p : PLANS) if (p.id().equals(u.plan)) return p;
        return null;
    }

    static int priority(Auth.User u) {
        Plan p = of(u);
        return p == null ? 0 : p.rank();
    }

    static void refresh(Auth.User u, boolean force) {
        if (u == null || !rolesConfigured()) return;
        long now = System.currentTimeMillis();
        if (!force && now - u.planChecked < RECHECK) return;
        u.planChecked = now;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://discord.com/api/v10/guilds/" + Auth.GUILD_ID + "/members/" + u.id))
                    .timeout(Duration.ofSeconds(10)).header("Authorization", "Bot " + Auth.BOT_TOKEN).GET().build();
            HttpResponse<String> res = Auth.HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            String before = u.plan;
            if (res.statusCode() == 404) u.plan = null;
            else if (res.statusCode() == 200) {
                JsonArray roles = JsonParser.parseString(res.body()).getAsJsonObject().getAsJsonArray("roles");
                Set<String> have = new HashSet<>();
                roles.forEach(r -> have.add(r.getAsString()));
                u.plan = null;
                for (Plan p : PLANS) if (p.roleId() != null && have.contains(p.roleId())) {
                    u.plan = p.id();
                    break;
                }
            } else return;
            if (!Objects.equals(before, u.plan)) {
                u.planSince = u.plan == null ? 0 : now;
                Auth.saveUsers();
            }
        } catch (Exception e) {
            System.err.println("Plan check: " + e);
        }
    }

    static Map<String, Object> accountInfo(Auth.User u) {
        Map<String, Object> m = new LinkedHashMap<>();
        Plan p = of(u);
        m.put("plan", p == null ? null : p.name());
        m.put("apiBudget", p == null ? 0 : p.apiPerDay());
        m.put("apiUsedToday", Auth.used("api:" + u.id, DAY));
        m.put("apiKeyPrefix", u.apiKeyPrefix);
        m.put("apiKeyCreated", u.apiKeyCreated);
        return m;
    }

    static Auth.User userByKey(String header) {
        if (header == null || !header.startsWith("Bearer rsk_")) return null;
        String key = header.substring(7).trim();
        if (key.length() > 100) return null;
        String h = hash(key);
        for (Auth.User u : Auth.USERS.values())
            if (u.apiKeyHash != null && MessageDigest.isEqual(u.apiKeyHash.getBytes(StandardCharsets.UTF_8), h.getBytes(StandardCharsets.UTF_8))) return u;
        return null;
    }

    static String apiGate(Auth.User u) {
        refresh(u, false);
        Plan p = of(u);
        int budget = p == null ? 0 : p.apiPerDay();
        if (budget <= 0) return "This API key has no daily budget. Get a plan in our Discord to use the API.";
        if (!Auth.rateLimit("api:" + u.id, budget, DAY)) return "Daily API budget of " + budget + " scans used up. It refills over the next 24 hours.";
        return null;
    }

    static void handleKey(HttpExchange ex) throws java.io.IOException {
        Auth.User u = Auth.currentUser(ex);
        if (u == null) {
            Main.json(ex, 401, Map.of("error", "Log in with Discord first."));
            return;
        }
        switch (ex.getRequestMethod()) {
            case "POST" -> {
                byte[] b = new byte[24];
                Main.RNG.nextBytes(b);
                String key = "rsk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(b);
                u.apiKeyHash = hash(key);
                u.apiKeyPrefix = key.substring(0, 10);
                u.apiKeyCreated = System.currentTimeMillis();
                Auth.saveUsers();
                Main.json(ex, 200, Map.of("key", key, "prefix", u.apiKeyPrefix));
            }
            case "DELETE" -> {
                u.apiKeyHash = null;
                u.apiKeyPrefix = null;
                u.apiKeyCreated = 0;
                Auth.saveUsers();
                Main.json(ex, 200, Map.of("ok", true));
            }
            default -> Main.json(ex, 405, Map.of("error", "Use POST or DELETE"));
        }
    }

    static List<Map<String, Object>> supporters() {
        List<Auth.User> list = new ArrayList<>();
        for (Auth.User u : Auth.USERS.values()) if (of(u) != null) list.add(u);
        list.sort(Comparator.comparingInt((Auth.User u) -> -of(u).rank()).thenComparingLong(u -> u.planSince));
        List<Map<String, Object>> out = new ArrayList<>();
        for (Auth.User u : list) {
            Map<String, Object> m = Auth.publicUser(u);
            m.remove("files");
            m.remove("scans");
            m.put("plan", of(u).name());
            m.put("since", u.planSince);
            out.add(m);
        }
        return out;
    }

    static Map<String, Object> publicInfo() {
        List<Map<String, Object>> ps = new ArrayList<>();
        for (Plan p : PLANS) ps.add(Map.of("id", p.id(), "name", p.name(), "apiPerDay", p.apiPerDay()));
        return Map.of("plans", ps, "rolesConfigured", rolesConfigured(), "contact", CONTACT,
                "invite", Optional.ofNullable(Auth.GUILD_INVITE).orElse(""));
    }

    private static String hash(String key) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
