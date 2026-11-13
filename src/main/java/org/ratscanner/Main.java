package org.ratscanner;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public final class Main {

    static final long MAX_UPLOAD = 100L << 20;
    static final int MAX_JOBS_IN_MEMORY = 24;
    static final int SCANS_PER_HOUR_IP = Integer.parseInt(Optional.ofNullable(System.getenv("SCANS_PER_HOUR")).orElse("40"));
    static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    static final Gson GSON_PRETTY = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    static final SecureRandom RNG = new SecureRandom();
    static final Map<String, ScanJob> JOBS = Collections.synchronizedMap(new LinkedHashMap<>(32, 0.75f, true) {
        protected boolean removeEldestEntry(Map.Entry<String, ScanJob> eldest) {
            if (size() > MAX_JOBS_IN_MEMORY && !eldest.getValue().status.equals("running")) {
                eldest.getValue().cleanup();
                return true;
            }
            return false;
        }
    });
    static final Map<String, AtomicInteger> ACTIVE_PER_IP = new ConcurrentHashMap<>();
    static final Semaphore UPLOADS = new Semaphore(Integer.parseInt(Optional.ofNullable(System.getenv("MAX_PARALLEL_UPLOADS")).orElse("6")));
    static ThreadPoolExecutor SCAN_POOL;
    static final java.util.concurrent.atomic.AtomicLong SEQ = new java.util.concurrent.atomic.AtomicLong();

    record Task(int priority, long seq, Runnable body) implements Runnable, Comparable<Task> {
        public void run() {
            body.run();
        }

        public int compareTo(Task o) {
            return priority != o.priority ? Integer.compare(o.priority, priority) : Long.compare(seq, o.seq);
        }
    }
    static Path DATA;

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(Optional.ofNullable(System.getenv("PORT")).orElse("8080"));
        int workers = Integer.parseInt(Optional.ofNullable(System.getenv("SCAN_WORKERS")).orElse("2"));
        java.security.Security.setProperty("networkaddress.cache.ttl", "120");
        java.security.Security.setProperty("networkaddress.cache.negative.ttl", "10");
        DATA = Paths.get(Optional.ofNullable(System.getenv("DATA_DIR")).orElse("data"));
        Files.createDirectories(DATA.resolve("reports"));
        Auth.init(DATA);
        SCAN_POOL = new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS, new PriorityBlockingQueue<>());
        System.out.println("Rules loaded: " + Rules.STRING_RULES.size() + " string rules, " + Rules.COMBOS.size() + " combination rules, " + Rules.FAMILIES.size() + " malware families");
        System.out.println("Discord login: " + (Auth.discordEnabled() ? "on" : "off") + " · Cloudflare Turnstile: " + (Auth.turnstileEnabled() ? "on" : "off")
                + " · Cloudflare IP header: " + (Auth.TRUST_CLOUDFLARE ? "trusted" : "ignored"));

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 64);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.createContext("/", Main::handle);
        server.start();
        System.out.println("RatScanner running on http://localhost:" + port);
    }

    private static void handle(HttpExchange ex) {
        try (ex) {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            ex.getResponseHeaders().add("X-Content-Type-Options", "nosniff");
            ex.getResponseHeaders().add("Referrer-Policy", "no-referrer");
            ex.getResponseHeaders().add("X-Frame-Options", "DENY");
            ex.getResponseHeaders().add("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
            ex.getResponseHeaders().add("Cross-Origin-Opener-Policy", "same-origin");
            if (Auth.PUBLIC_URL.startsWith("https://")) ex.getResponseHeaders().add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
            switch (path) {
                case "/auth/login" -> {
                    Auth.login(ex);
                    return;
                }
                case "/auth/callback" -> {
                    Auth.callback(ex, query(ex));
                    return;
                }
                case "/auth/logout" -> {
                    if (method.equals("POST")) Auth.logout(ex);
                    else json(ex, 405, Map.of("error", "Use POST"));
                    return;
                }
                case "/api/me" -> {
                    json(ex, 200, Auth.me(ex));
                    return;
                }
                case "/api/key" -> {
                    Plans.handleKey(ex);
                    return;
                }
                case "/api/plans" -> {
                    json(ex, 200, Plans.publicInfo());
                    return;
                }
                case "/api/supporters" -> {
                    json(ex, 200, Map.of("entries", Plans.supporters()));
                    return;
                }
                case "/api/leaderboard" -> {
                    json(ex, 200, Map.of("entries", Auth.leaderboard(50)));
                    return;
                }
                default -> {
                }
            }
            if (method.equals("GET") && !path.startsWith("/api/")) {
                serveStatic(ex, path);
                return;
            }
            if (path.equals("/api/scan") && method.equals("POST")) {
                upload(ex);
                return;
            }
            if (path.equals("/api/scan-url") && method.equals("POST")) {
                scanUrl(ex);
                return;
            }
            if (path.startsWith("/api/hash/") && method.equals("GET")) {
                hashLookup(ex, path.substring("/api/hash/".length()).toLowerCase(Locale.ROOT));
                return;
            }
            if (path.equals("/api/stats") && method.equals("GET")) {
                json(ex, 200, Map.of("rules", Rules.STRING_RULES.size() + Rules.COMBOS.size() + Rules.CAPS.size(), "families", Rules.FAMILIES.size(),
                        "scanned", countReports()));
                return;
            }
            if (path.startsWith("/api/job/") && method.equals("GET")) {
                String rest = path.substring("/api/job/".length());
                String id = rest.contains("/") ? rest.substring(0, rest.indexOf('/')) : rest;
                String sub = rest.contains("/") ? rest.substring(rest.indexOf('/') + 1) : "";
                ScanJob job = JOBS.get(id);
                if (job == null) {
                    json(ex, 404, Map.of("error", "Scan not found or expired"));
                    return;
                }
                switch (sub) {
                    case "" -> json(ex, 200, job.status());
                    case "source" -> source(ex, job);
                    case "report.json" -> {
                        if (job.report == null) {
                            json(ex, 409, Map.of("error", "Not finished yet"));
                            return;
                        }
                        ex.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"ratscanner-" + job.id + ".json\"");
                        send(ex, 200, "application/json; charset=utf-8", GSON_PRETTY.toJson(job.report).getBytes(StandardCharsets.UTF_8));
                    }
                    default -> json(ex, 404, Map.of("error", "Unknown"));
                }
                return;
            }
            json(ex, 404, Map.of("error", "Not found"));
        } catch (Throwable t) {
            t.printStackTrace();
            try {
                json(ex, 500, Map.of("error", "Internal error: " + t.getClass().getSimpleName()));
            } catch (Exception ignored) {
            }
        }
    }

    private static String gate(HttpExchange ex, String turnstileToken) {
        Auth.User user = Auth.currentUser(ex);
        if (Auth.REQUIRE_LOGIN && user == null) return "Please log in with Discord to scan files.";
        String ip = Auth.clientIp(ex);
        if (!Auth.verifyTurnstile(turnstileToken, ip)) return "Security check failed. Please complete the Cloudflare check and try again.";
        if (!Auth.rateLimit("ip:" + ip, SCANS_PER_HOUR_IP, 3_600_000L)) return "Too many scans from your network. Please try again later.";
        if (user != null && !Auth.rateLimit("user:" + user.id, SCANS_PER_HOUR_IP * 2, 3_600_000L)) return "Too many scans on your account. Please try again later.";
        return null;
    }

    private static void upload(HttpExchange ex) throws IOException {
        Map<String, String> q = query(ex);
        String authz = ex.getRequestHeaders().getFirst("Authorization");
        Auth.User apiUser = Plans.userByKey(authz);
        if (authz != null && apiUser == null) {
            ex.getRequestBody().close();
            json(ex, 401, Map.of("error", "Invalid API key"));
            return;
        }
        String deny = apiUser != null ? Plans.apiGate(apiUser) : gate(ex, ex.getRequestHeaders().getFirst("X-Turnstile-Token"));
        if (deny != null) {
            ex.getRequestBody().close();
            json(ex, 403, Map.of("error", deny));
            return;
        }
        String name = sanitizeName(q.getOrDefault("name", "upload.bin"));
        long len = Optional.ofNullable(ex.getRequestHeaders().getFirst("Content-Length")).map(Long::parseLong).orElse(-1L);
        if (len > MAX_UPLOAD) {
            json(ex, 413, Map.of("error", "File too large (max. 100 MB)"));
            return;
        }
        if (!UPLOADS.tryAcquire()) {
            ex.getRequestBody().close();
            json(ex, 503, Map.of("error", "The server is busy right now. Please try again in a moment."));
            return;
        }
        byte[] data;
        try (InputStream in = ex.getRequestBody()) {
            data = Scanner.readLimited(in, MAX_UPLOAD);
        } catch (IOException e) {
            json(ex, 413, Map.of("error", "File too large (max. 100 MB)"));
            return;
        } finally {
            UPLOADS.release();
        }
        if (data.length < 4) {
            json(ex, 400, Map.of("error", "Empty or invalid file"));
            return;
        }
        submit(ex, name, data, !"0".equals(q.get("full")), apiUser);
    }

    private static void scanUrl(HttpExchange ex) throws IOException {
        String body = new String(Scanner.readLimited(ex.getRequestBody(), 16384), StandardCharsets.UTF_8);
        String url, token;
        boolean full;
        try {
            JsonObject o = JsonParser.parseString(body).getAsJsonObject();
            url = o.get("url").getAsString();
            full = !o.has("full") || o.get("full").getAsBoolean();
            token = o.has("turnstile") && !o.get("turnstile").isJsonNull() ? o.get("turnstile").getAsString() : null;
        } catch (Exception e) {
            json(ex, 400, Map.of("error", "Invalid request"));
            return;
        }
        String authz = ex.getRequestHeaders().getFirst("Authorization");
        Auth.User apiUser = Plans.userByKey(authz);
        if (authz != null && apiUser == null) {
            json(ex, 401, Map.of("error", "Invalid API key"));
            return;
        }
        String deny = apiUser != null ? Plans.apiGate(apiUser) : gate(ex, token);
        if (deny != null) {
            json(ex, 403, Map.of("error", deny));
            return;
        }
        String ip = Auth.clientIp(ex);
        if (!acquire(ip)) {
            json(ex, 429, Map.of("error", "Too many concurrent scans. Please wait."));
            return;
        }
        UrlFetcher.Download d;
        try {
            d = UrlFetcher.fetch(url, MAX_UPLOAD);
        } catch (Exception e) {
            json(ex, 400, Map.of("error", "Download failed: " + e.getMessage()));
            return;
        } finally {
            release(ip);
        }
        submit(ex, sanitizeName(d.fileName()), d.data(), full, apiUser);
    }

    static boolean isArchive(byte[] d) {
        return d.length > 4 && d[0] == 'P' && d[1] == 'K' && (d[2] == 3 || d[2] == 5 || d[2] == 7);
    }

    private static void submit(HttpExchange ex, String name, byte[] data, boolean full, Auth.User apiUser) throws IOException {
        String ip = Auth.clientIp(ex);
        Auth.User who = apiUser != null ? apiUser : Auth.currentUser(ex);
        if (who == null) {
            if (!isArchive(data)) {
                json(ex, 403, Map.of("error", "Log in with Discord to scan .exe, .dll, scripts and other programs. Without login you can scan .jar files.", "needLogin", true));
                return;
            }
            if (Auth.used("day:" + ip, 86_400_000L) >= Auth.ANON_JARS_PER_DAY) {
                json(ex, 429, Map.of("error", "You reached the limit of " + Auth.ANON_JARS_PER_DAY + " scans per day without login. Log in with Discord for more.", "needLogin", true));
                return;
            }
        }
        if (!acquire(ip)) {
            json(ex, 429, Map.of("error", "Too many concurrent scans. Please wait."));
            return;
        }
        if (who == null && !Auth.rateLimit("day:" + ip, Auth.ANON_JARS_PER_DAY, 86_400_000L)) {
            release(ip);
            json(ex, 429, Map.of("error", "You reached the limit of " + Auth.ANON_JARS_PER_DAY + " scans per day without login. Log in with Discord for more.", "needLogin", true));
            return;
        }
        Auth.User user = who;
        String id = newId();
        ScanJob job;
        try {
            job = new ScanJob(id, name, data, full);
        } catch (IOException e) {
            release(ip);
            throw e;
        }
        job.userId = user == null ? null : user.id;
        JOBS.put(id, job);
        SCAN_POOL.execute(new Task(Plans.priority(user), SEQ.incrementAndGet(), () -> {
            job.status = "running";
            try {
                Scanner sc = new Scanner(job);
                job.scanner = sc;
                sc.run();
                job.status = "done";
                persist(job);
                Auth.recordScan(job.userId, job.sha256);
            } catch (Throwable t) {
                job.status = "error";
                job.error = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
                if (!(t instanceof IOException)) t.printStackTrace();
            } finally {
                job.data = null;
                release(ip);
            }
        }));
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("id", id);
        resp.put("owner", job.ownerToken);
        resp.put("queued", SCAN_POOL.getQueue().size());
        if (Plans.priority(user) > 0) resp.put("priority", true);
        json(ex, 202, resp);
    }

    private static void source(HttpExchange ex, ScanJob job) throws IOException {
        Map<String, String> q = query(ex);
        String engine = q.getOrDefault("engine", "vineflower");
        if (!Set.of("vineflower", "cfr", "asm").contains(engine)) {
            json(ex, 400, Map.of("error", "Unknown engine"));
            return;
        }
        String owner = ex.getRequestHeaders().getFirst("X-Owner-Token");
        Auth.User viewer = Auth.currentUser(ex);
        boolean isOwner = (owner != null && java.security.MessageDigest.isEqual(owner.getBytes(StandardCharsets.UTF_8), job.ownerToken.getBytes(StandardCharsets.UTF_8)))
                || (viewer != null && viewer.id.equals(job.userId));
        if (!isOwner) {
            json(ex, 403, Map.of("error", "The code view is only available to the person who uploaded this file."));
            return;
        }
        Scanner sc = job.scanner;
        if (sc == null || job.report == null) {
            json(ex, 409, Map.of("error", "Scan not finished yet"));
            return;
        }
        String container = q.getOrDefault("container", "");
        String cls = q.get("cls");
        if (cls == null) {
            json(ex, 400, Map.of("error", "cls missing"));
            return;
        }
        ClassInfo ci = sc.classes.get(Scanner.key(container, cls));
        String top = ci != null ? ci.top : cls;
        try {
            String src = sc.sourceFor(engine, container, top);
            json(ex, 200, Map.of("engine", engine, "top", top, "source", src));
        } catch (Exception e) {
            json(ex, 200, Map.of("engine", engine, "top", top, "source", "// Decompilation failed: " + e.getMessage()));
        }
    }

    private static void persist(ScanJob job) {
        try {
            Path p = DATA.resolve("reports").resolve(job.sha256 + ".json");
            Files.writeString(p, GSON.toJson(job.report), StandardCharsets.UTF_8);
        } catch (Exception e) {
            System.err.println("Saving report failed: " + e);
        }
    }

    private static void hashLookup(HttpExchange ex, String hash) throws IOException {
        if (!hash.matches("^[0-9a-f]{64}$")) {
            json(ex, 400, Map.of("error", "Please enter a SHA-256 hash (64 hex characters)."));
            return;
        }
        Path p = DATA.resolve("reports").resolve(hash + ".json");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sha256", hash);
        out.put("knownBad", Rules.BAD_HASHES.contains(hash));
        if (Files.exists(p)) {
            JsonObject rep = JsonParser.parseString(Files.readString(p, StandardCharsets.UTF_8)).getAsJsonObject();
            out.put("found", true);
            out.put("report", rep);
            String id = rep.has("id") ? rep.get("id").getAsString() : null;
            out.put("live", id != null && JOBS.containsKey(id));
        } else out.put("found", false);
        json(ex, 200, out);
    }

    private static long countReports() {
        try (var s = Files.list(DATA.resolve("reports"))) {
            return s.count();
        } catch (IOException e) {
            return 0;
        }
    }

    private static boolean acquire(String ip) {
        AtomicInteger c = ACTIVE_PER_IP.computeIfAbsent(ip, k -> new AtomicInteger());
        if (c.incrementAndGet() > 3) {
            c.decrementAndGet();
            return false;
        }
        return true;
    }

    private static void release(String ip) {
        AtomicInteger c = ACTIVE_PER_IP.get(ip);
        if (c != null && c.decrementAndGet() <= 0) ACTIVE_PER_IP.remove(ip, c);
    }

    private static String newId() {
        byte[] b = new byte[9];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String sanitizeName(String n) {
        n = n.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_");
        if (n.length() > 120) n = n.substring(0, 120);
        return n.isBlank() ? "upload.bin" : n;
    }

    static Map<String, String> query(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return m;
        for (String part : q.split("&")) {
            int i = part.indexOf('=');
            if (i <= 0) continue;
            m.put(URLDecoder.decode(part.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(part.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static final Map<String, String> STATIC = Map.of(
            "/", "index.html", "/index.html", "index.html", "/app.js", "app.js", "/style.css", "style.css", "/favicon.svg", "favicon.svg");

    private static void serveStatic(HttpExchange ex, String path) throws IOException {
        String file = STATIC.get(path);
        if (file == null) file = "index.html";
        try (InputStream in = Main.class.getResourceAsStream("/web/" + file)) {
            if (in == null) {
                send(ex, 404, "text/plain", "not found".getBytes());
                return;
            }
            String type = file.endsWith(".js") ? "application/javascript; charset=utf-8" : file.endsWith(".css") ? "text/css; charset=utf-8"
                    : file.endsWith(".svg") ? "image/svg+xml" : "text/html; charset=utf-8";
            ex.getResponseHeaders().add("Cache-Control", "no-cache");
            if (file.equals("index.html"))
                ex.getResponseHeaders().add("Content-Security-Policy", "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; "
                        + "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://cdn.discordapp.com; "
                        + "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
            send(ex, 200, type, in.readAllBytes());
        }
    }

    static void json(HttpExchange ex, int code, Object body) throws IOException {
        send(ex, code, "application/json; charset=utf-8", GSON.toJson(body).getBytes(StandardCharsets.UTF_8));
    }

    static void send(HttpExchange ex, int code, String type, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }
}
