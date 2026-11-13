package org.ratscanner;

import com.google.gson.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class Scanner {

    static final long MAX_ENTRY = 64L << 20;
    static final long MAX_TOTAL = 512L << 20;
    static final long MAX_CLASS_BYTES = 256L << 20;
    long classBytes;
    static final int MAX_ENTRIES = 80_000;
    static final int MAX_DEPTH = 3;
    static final int DECOMPILE_CAP = 2500;
    static final int BATCH = 250;
    static final long ENGINE_BUDGET_MS = 240_000;

    final ScanJob job;
    final List<Container> containers = new ArrayList<>();
    final Map<String, ClassInfo> classes = new LinkedHashMap<>();
    final List<Finding> resourceFindings = new ArrayList<>();
    final Set<String> jarTags = new HashSet<>();
    final Map<String, Evidence> jarTagEvidence = new HashMap<>();
    final JsonObject meta = new JsonObject();
    final List<String> entrypoints = new ArrayList<>();
    final List<Map<String, Object>> resources = new ArrayList<>();
    long totalBytes;
    int entryCount;
    String type = "Java archive";

    Scanner(ScanJob job) {
        this.job = job;
    }

    static String key(String container, String cls) {
        return container + "!" + cls;
    }

    void run() throws Exception {
        long start = System.currentTimeMillis();
        job.stage("Unpacking", 2);
        File outer = new File(job.dir, "upload.jar");
        Files.write(outer.toPath(), job.data);
        Map<String, Object> hashes = new LinkedHashMap<>();
        hashes.put("sha256", hex("SHA-256", job.data));
        hashes.put("sha1", hex("SHA-1", job.data));
        hashes.put("md5", hex("MD5", job.data));
        job.sha256 = (String) hashes.get("sha256");
        byte[] head = job.data;
        boolean zip = head.length > 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 3 || head[2] == 5 || head[2] == 7);
        if (zip) loadContainer("", outer, 0);
        else {
            job.stage("Binary analysis", 5);
            binaryInfo = BinaryScanner.scan(this, head, job.fileName);
        }
        job.data = null;

        job.stage("ASM bytecode analysis", 10);
        int total = containers.stream().mapToInt(c -> c.classes.size()).sum();
        int done = 0;
        for (Container c : containers) {
            Set<String> names = c.classes.keySet();
            for (Map.Entry<String, byte[]> e : new ArrayList<>(c.classes.entrySet())) {
                ClassInfo ci = Analyzer.analyze(c.path, e.getKey() + ".class", e.getValue(), hiddenClasses.contains(key(c.path, e.getKey())), names);
                classes.put(key(c.path, ci.name), ci);
                if (++done % 200 == 0) job.progress(10 + (int) (25.0 * done / Math.max(1, total)));
            }
        }
        markEntrypoints();
        job.stage("Obfuscation & resources", 36);
        obfuscationChecks();

        Map<String, Object> engines = new LinkedHashMap<>();
        engines.put("asm", Map.of("status", "ok", "classes", classes.size()));
        if (job.fullDecompile) {
            decompileAll(engines);
        } else {
            engines.put("vineflower", Map.of("status", "on-demand"));
            engines.put("cfr", Map.of("status", "on-demand"));
        }

        job.stage("Scoring", 95);
        evaluateCombos();
        job.report = buildReport(hashes, engines, System.currentTimeMillis() - start);
        job.stage("Done", 100);
    }

    final Set<String> hiddenClasses = new HashSet<>();
    Map<String, Object> binaryInfo;

    void loadEmbedded(String path, File file) throws IOException {
        loadContainer(path, file, 1);
    }

    void addFinding(String container, String rule, Severity sev, String cat, String title, String desc, String evidence) {
        Finding f = new Finding(rule, sev, cat, title, desc);
        f.container = container;
        f.evidence = evidence;
        f.source = "binary";
        resourceFindings.add(f);
    }

    void mergeHolder(ClassInfo holder) {
        applyCombos(holder);
        for (Finding f : holder.findings.values()) {
            f.cls = null;
            f.source = "binary";
            resourceFindings.add(f);
        }
        holder.tags.forEach(this::tagJar);
    }

    private void loadContainer(String path, File file, int depth) throws IOException {
        Container c = new Container(path, file, depth);
        containers.add(c);
        try (ZipFile zf = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                if (++entryCount > MAX_ENTRIES) throw new IOException("Too many entries in the archive (zip bomb?)");
                if (ze.isDirectory()) {
                    if (ze.getName().endsWith(".class/")) {
                        resourceFinding(path, ze.getName(), "CLASS_DIR_TRICK", Severity.LOW, "Obfuscation", "Folder named like a .class file",
                                "A folder is named like a class file – a known trick to confuse decompilers/unzippers.");
                    }
                    continue;
                }
                String name = ze.getName();
                byte[] data;
                try (InputStream in = zf.getInputStream(ze)) {
                    data = readLimited(in, MAX_ENTRY);
                }
                totalBytes += data.length;
                if (totalBytes > MAX_TOTAL) throw new IOException("Unpacked size exceeds 512 MB (zip bomb?)");
                handleEntry(c, name, data, depth);
            }
        } catch (java.util.zip.ZipException ze) {
            if (depth == 0) throw new IOException("Not a valid JAR/ZIP file: " + ze.getMessage());
            resourceFinding(path, path, "BROKEN_NESTED", Severity.LOW, "Obfuscation", "Broken nested archive", ze.getMessage());
        }
    }

    private void handleEntry(Container c, String name, byte[] data, int depth) throws IOException {
        String lower = name.toLowerCase(Locale.ROOT);
        boolean classMagic = data.length > 10 && (data[0] & 0xff) == 0xCA && (data[1] & 0xff) == 0xFE && (data[2] & 0xff) == 0xBA && (data[3] & 0xff) == 0xBE;
        int major = data.length > 8 ? ((data[6] & 0xff) << 8) | (data[7] & 0xff) : 0;
        boolean isClass = classMagic && major >= 45 && major <= 90 && data[4] == 0 && data[5] == 0 || classMagic && major >= 45 && major <= 90;
        if (lower.endsWith(".class")) {
            if (!classMagic) {
                resourceFinding(c.path, name, "FAKE_CLASS", Severity.LOW, "Obfuscation", "Invalid .class file",
                        "The file ends in .class but is not a Java class (encrypted or a decoy).");
                tagJar("R_BLOB", new Evidence(null, 0, name, null));
                return;
            }
            String cname = classNameOf(data, name.substring(0, name.length() - 6));
            if ((classBytes += data.length) > MAX_CLASS_BYTES) throw new IOException("Too much class data (> 256 MB) – refusing to analyse");
            c.classes.putIfAbsent(cname, data);
            return;
        }
        if (isClass) {
            String cname = classNameOf(data, name);
            c.classes.putIfAbsent(cname, data);
            hiddenClasses.add(key(c.path, cname));
            resourceFinding(c.path, name, "HIDDEN_CLASS", Severity.HIGH, "Evasion", "Class disguised as a resource",
                    "'" + name + "' is actually the Java class '" + cname + "'. Such classes are not loaded normally but by custom loader code.");
            tagJar("R_HIDDENCLASS", new Evidence(null, 0, name, null));
            return;
        }
        boolean zipMagic = data.length > 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4;
        if (zipMagic && (lower.endsWith(".jar") || lower.endsWith(".zip") || lower.endsWith(".litemod") || !lower.matches(".*\\.(png|jpg|ogg|nbt|mcpack|mcworld|xlsx|docx)$"))) {
            if (depth + 1 > MAX_DEPTH) {
                resourceFinding(c.path, name, "DEEP_NESTING", Severity.LOW, "Obfuscation", "Very deeply nested archives", "Not unpacked further.");
                return;
            }
            if (!lower.endsWith(".jar") && !lower.endsWith(".zip") && !lower.endsWith(".litemod")) {
                resourceFinding(c.path, name, "DISGUISED_ARCHIVE", Severity.MEDIUM, "Evasion", "Disguised archive",
                        "'" + name + "' is a ZIP/JAR archive with a fake file extension.");
            }
            File nested = File.createTempFile("nested", ".jar", job.dir);
            Files.write(nested.toPath(), data);
            String np = c.path.isEmpty() ? name : c.path + "!/" + name;
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("container", c.path);
            r.put("path", name);
            r.put("size", data.length);
            r.put("kind", "nested-jar");
            resources.add(r);
            loadContainer(np, nested, depth + 1);
            return;
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("container", c.path);
        r.put("path", name);
        r.put("size", data.length);
        String kind = resourceKind(c, name, lower, data);
        r.put("kind", kind);
        if (resources.size() < 5000) resources.add(r);
        if (depth == 0) parseMeta(name, data);
    }

    private String resourceKind(Container c, String name, String lower, byte[] data) {
        String ext = lower.contains(".") ? lower.substring(lower.lastIndexOf('.') + 1) : "";
        boolean mz = data.length > 64 && data[0] == 'M' && data[1] == 'Z';
        boolean elf = data.length > 16 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
        int m = data.length > 4 ? ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) | (data[3] & 0xff) : 0;
        boolean macho = m == 0xFEEDFACE || m == 0xFEEDFACF || m == 0xCEFAEDFE || m == 0xCFFAEDFE || m == 0xCAFEBABE;
        if (mz || elf || macho) {
            boolean nativeExt = Set.of("dll", "so", "dylib", "jnilib", "node", "sys").contains(ext);
            boolean exeExt = Set.of("exe", "scr", "com", "bin", "msi").contains(ext);
            boolean knownLib = lower.matches(".*(lwjgl|jna|sqlite|natives?|discord|jinput|openal|glfw|jemalloc|netty|zstd|lz4|snappy|brotli|conpty|pty4j|jnativehook|oshi|win32-x86|linux-x86|darwin|osx|macos|aarch64|amd64|x86_64|arm64).*");
            if (!nativeExt && !exeExt) {
                resourceFinding(c.path, name, "DISGUISED_BINARY", Severity.HIGH, "Evasion", "Disguised executable",
                        "'" + name + "' is a native program (" + (mz ? "Windows PE" : elf ? "Linux ELF" : "macOS Mach-O") + ") with a harmless-looking extension.");
            } else if (exeExt || (mz && ext.equals("exe"))) {
                resourceFinding(c.path, name, "EMBEDDED_EXE", Severity.HIGH, "Execution", "Embedded program (.exe)",
                        "The JAR contains an executable program. Mods almost never need this – it is often started secretly.");
            } else if (!knownLib) {
                resourceFinding(c.path, name, "EMBEDDED_NATIVE", Severity.MEDIUM, "Execution", "Unknown native library",
                        "Native library that does not belong to a known library (LWJGL, JNA, SQLite …).");
            } else {
                resourceFinding(c.path, name, "EMBEDDED_NATIVE_KNOWN", Severity.INFO, "Execution", "Native library (known)",
                        "Native library of a known library.");
            }
            return "binary";
        }
        if (Set.of("bat", "cmd", "ps1", "vbs", "vbe", "hta", "wsf", "jse", "lnk", "reg").contains(ext)) {
            resourceFinding(c.path, name, "EMBEDDED_SCRIPT", Severity.MEDIUM, "Execution", "Embedded Windows script",
                    "Batch/PowerShell/VBS scripts in a mod are often used to run malicious code.");
            scanText(c, name, data);
            return "script";
        }
        if (ext.equals("sh") || ext.equals("command")) {
            resourceFinding(c.path, name, "EMBEDDED_SHELL", Severity.LOW, "Execution", "Embedded shell script", "Shell script inside the JAR.");
            scanText(c, name, data);
            return "script";
        }
        if (Set.of("json", "txt", "yml", "yaml", "properties", "cfg", "toml", "xml", "mf", "js", "lua", "conf", "ini", "json5", "info", "md", "html", "py", "kts", "gradle").contains(ext)
                || (ext.isEmpty() && data.length < 200_000 && Analyzer.printableRatio(new String(data, 0, Math.min(data.length, 4096), StandardCharsets.ISO_8859_1)) > 0.95)) {
            if (data.length < 2_000_000) scanText(c, name, data);
            return "text";
        }
        if (data.length > 2048 && !Set.of("png", "jpg", "jpeg", "gif", "ogg", "mp3", "wav", "gz", "nbt", "ttf", "otf", "woff", "woff2", "webp", "zip", "jar", "xz", "bz2", "zst", "lz4", "fsh", "vsh", "glsl", "bdmodel", "bbmodel", "icns", "ico", "tga", "dds", "pack", "mcmeta", "schem", "schematic", "litematic", "mca", "dat", "bin", "ser", "res", "brotli", "br", "zlib", "lzma", "7z", "rar", "jfr", "pdf", "svg", "pdn", "psd", "blob", "frag", "vert", "material", "qoi", "kotlin_module", "kotlin_builtins", "rsa", "dsa", "sf", "ec", "p7s", "sig", "asc").contains(ext) && !lower.startsWith("meta-inf/")) {
            double ent = entropy(data);
            if (ent > 7.6) {
                resourceFinding(c.path, name, "ENCRYPTED_BLOB", Severity.LOW, "Obfuscation", "Data that looks encrypted",
                        String.format(Locale.ROOT, "'%s' has an entropy of %.2f bits/byte – encrypted or packed.", name, ent));
                tagJar("R_BLOB", new Evidence(null, 0, name, null));
                return "blob";
            }
        }
        return "file";
    }

    private void scanText(Container c, String name, byte[] data) {
        String text = new String(data, StandardCharsets.UTF_8);
        String pseudo = "res:" + name;
        ClassInfo holder = new ClassInfo(c.path, pseudo, pseudo, false, false, name);
        int n = 0;
        for (String line : text.split("\\R")) {
            if (++n > 20_000) break;
            String t = line.trim();
            if (t.isEmpty()) continue;
            Analyzer.processString(holder, t.length() > 4000 ? t.substring(0, 4000) : t, new Evidence(null, n, t, t), "resource", 1);
            for (String q : quoted(t)) if (!q.equals(t)) Analyzer.processString(holder, q, new Evidence(null, n, q, q), "resource", 0);
        }
        for (Finding f : holder.findings.values()) {
            f.cls = null;
            f.method = null;
            f.title = f.title + " (in resource)";
            f.source = "resource";
            f.evidence = name + ":" + f.line + "  " + f.evidence;
            resourceFindings.add(f);
        }
        holder.tags.forEach(this::tagJar);
    }

    private static final Pattern QUOTED = Pattern.compile("\"((?:[^\"\\\\]|\\\\.){3,2000})\"");

    static List<String> quoted(String s) {
        List<String> out = new ArrayList<>();
        Matcher m = QUOTED.matcher(s);
        while (m.find()) out.add(m.group(1).replace("\\\\", "\\").replace("\\/", "/"));
        return out;
    }

    private void tagJar(String tag, Evidence ev) {
        if (jarTags.add(tag)) jarTagEvidence.put(tag, ev);
    }

    private void resourceFinding(String container, String path, String rule, Severity sev, String cat, String title, String desc) {
        Finding f = new Finding(rule, sev, cat, title, desc);
        f.container = container;
        f.evidence = path;
        f.source = "resource";
        f.needle = path;
        resourceFindings.add(f);
    }

    private void parseMeta(String name, byte[] data) {
        String text = new String(data, StandardCharsets.UTF_8);
        try {
            switch (name) {
                case "fabric.mod.json", "quilt.mod.json" -> {
                    JsonObject o = JsonParser.parseString(text).getAsJsonObject();
                    boolean quilt = name.startsWith("quilt");
                    type = quilt ? "Quilt-Mod" : "Fabric-Mod";
                    JsonObject base = quilt && o.has("quilt_loader") ? o.getAsJsonObject("quilt_loader") : o;
                    putMeta("id", base, "id");
                    putMeta("version", base, "version");
                    JsonObject md = quilt && base.has("metadata") ? base.getAsJsonObject("metadata") : o;
                    putMeta("name", md, "name");
                    putMeta("description", md, "description");
                    if (md.has("authors")) meta.addProperty("authors", flatten(md.get("authors")));
                    if (md.has("contributors")) meta.addProperty("contributors", flatten(md.get("contributors")));
                    if (base.has("entrypoints") && base.get("entrypoints").isJsonObject()) {
                        for (Map.Entry<String, JsonElement> e : base.getAsJsonObject("entrypoints").entrySet()) {
                            JsonElement v = e.getValue();
                            List<JsonElement> items = new ArrayList<>();
                            if (v.isJsonArray()) v.getAsJsonArray().forEach(items::add);
                            else items.add(v);
                            for (JsonElement it : items) {
                                String cls = it.isJsonPrimitive() ? it.getAsString() : it.isJsonObject() && it.getAsJsonObject().has("value") ? it.getAsJsonObject().get("value").getAsString() : null;
                                if (cls != null) entrypoints.add(e.getKey() + ": " + cls);
                            }
                        }
                    }
                    if (o.has("mixins")) meta.addProperty("mixins", flatten(o.get("mixins")));
                    if (o.has("depends")) meta.addProperty("depends", String.join(", ", o.getAsJsonObject("depends").keySet()));
                }
                case "META-INF/mods.toml", "META-INF/neoforge.mods.toml" -> {
                    type = name.contains("neoforge") ? "NeoForge-Mod" : "Forge-Mod";
                    tomlMeta(text, "modId", "id");
                    tomlMeta(text, "displayName", "name");
                    tomlMeta(text, "version", "version");
                    tomlMeta(text, "authors", "authors");
                    tomlMeta(text, "description", "description");
                }
                case "mcmod.info" -> {
                    if (type.equals("Java archive")) type = "Forge-Mod (Legacy)";
                    JsonElement el = JsonParser.parseString(text);
                    JsonObject o = el.isJsonArray() && !el.getAsJsonArray().isEmpty() ? el.getAsJsonArray().get(0).getAsJsonObject()
                            : el.isJsonObject() && el.getAsJsonObject().has("modList") ? el.getAsJsonObject().getAsJsonArray("modList").get(0).getAsJsonObject() : null;
                    if (o != null) {
                        putMeta("id", o, "modid");
                        putMeta("name", o, "name");
                        putMeta("version", o, "version");
                        if (o.has("authorList")) meta.addProperty("authors", flatten(o.get("authorList")));
                    }
                }
                case "plugin.yml", "paper-plugin.yml", "bungee.yml" -> {
                    type = name.equals("bungee.yml") ? "BungeeCord-Plugin" : name.startsWith("paper") ? "Paper-Plugin" : "Bukkit/Spigot/Paper-Plugin";
                    yamlMeta(text, "name", "name");
                    yamlMeta(text, "version", "version");
                    yamlMeta(text, "main", "main");
                    yamlMeta(text, "author", "authors");
                    yamlMeta(text, "authors", "authors");
                    yamlMeta(text, "description", "description");
                    yamlMeta(text, "website", "website");
                    if (meta.has("main")) entrypoints.add("main: " + meta.get("main").getAsString());
                }
                case "velocity-plugin.json" -> {
                    type = "Velocity-Plugin";
                    JsonObject o = JsonParser.parseString(text).getAsJsonObject();
                    putMeta("id", o, "id");
                    putMeta("name", o, "name");
                    putMeta("version", o, "version");
                    putMeta("main", o, "main");
                    if (o.has("authors")) meta.addProperty("authors", flatten(o.get("authors")));
                    if (meta.has("main")) entrypoints.add("main: " + meta.get("main").getAsString());
                }
                case "META-INF/MANIFEST.MF" -> {
                    Manifest mf = new Manifest(new ByteArrayInputStream(data));
                    Attributes a = mf.getMainAttributes();
                    for (String k : List.of("Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class", "Created-By", "Implementation-Title", "Implementation-Version", "Built-By", "Class-Path", "Can-Redefine-Classes", "Can-Retransform-Classes")) {
                        String v = a.getValue(k);
                        if (v != null) meta.addProperty("manifest." + k, v);
                    }
                    String main = a.getValue("Main-Class");
                    if (main != null) entrypoints.add("Main-Class: " + main);
                    for (String k : List.of("Premain-Class", "Agent-Class", "Launcher-Agent-Class")) {
                        String v = a.getValue(k);
                        if (v != null) {
                            entrypoints.add(k + ": " + v);
                            resourceFinding("", name, "JAVA_AGENT", Severity.MEDIUM, "Code loading", "Java agent (" + k + ")",
                                    "The JAR can hook into the JVM as a Java agent and modify other classes while they load.");
                        }
                    }
                    String cp = a.getValue("Class-Path");
                    if (cp != null && cp.matches("(?i).*(https?|ftp):.*")) {
                        resourceFinding("", name, "REMOTE_CLASSPATH", Severity.HIGH, "Downloader", "Classpath points to the internet",
                                "The manifest Class-Path contains a remote URL: " + cp);
                    }
                    if (main != null && type.equals("Java archive")) type = "Java application";
                }
                default -> {
                }
            }
        } catch (Exception e) {
            meta.addProperty("parseError." + name, e.getClass().getSimpleName());
        }
    }

    private void putMeta(String key, JsonObject o, String field) {
        if (o.has(field) && o.get(field).isJsonPrimitive()) meta.addProperty(key, o.get(field).getAsString());
    }

    private static String flatten(JsonElement e) {
        if (e.isJsonPrimitive()) return e.getAsString();
        List<String> out = new ArrayList<>();
        if (e.isJsonArray()) for (JsonElement x : e.getAsJsonArray()) {
            if (x.isJsonPrimitive()) out.add(x.getAsString());
            else if (x.isJsonObject() && x.getAsJsonObject().has("name")) out.add(x.getAsJsonObject().get("name").getAsString());
            else if (x.isJsonObject() && x.getAsJsonObject().has("config")) out.add(x.getAsJsonObject().get("config").getAsString());
        }
        else if (e.isJsonObject()) out.addAll(e.getAsJsonObject().keySet());
        return String.join(", ", out);
    }

    private void tomlMeta(String text, String key, String target) {
        Matcher m = Pattern.compile("(?m)^\\s*" + key + "\\s*=\\s*(?:\"([^\"]*)\"|'''([\\s\\S]*?)'''|'([^']*)')").matcher(text);
        if (m.find() && !meta.has(target)) {
            String v = m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
            meta.addProperty(target, v.trim());
        }
    }

    private void yamlMeta(String text, String key, String target) {
        Matcher m = Pattern.compile("(?m)^" + key + "\\s*:\\s*(.+)$").matcher(text);
        if (m.find() && !meta.has(target)) meta.addProperty(target, m.group(1).trim().replaceAll("^[\"']|[\"']$", ""));
    }

    private void markEntrypoints() {
        Set<String> eps = new HashSet<>();
        for (String e : entrypoints) {
            String cls = e.substring(e.indexOf(':') + 1).trim();
            if (cls.contains("::")) cls = cls.substring(0, cls.indexOf("::"));
            eps.add(cls.replace('.', '/'));
        }
        for (ClassInfo ci : classes.values()) {
            if (ci.modAnnotation) {
                eps.add(ci.name);
                entrypoints.add("@Mod: " + ci.name.replace('/', '.'));
            }
            if (eps.contains(ci.name) || eps.contains(ci.top)) {
                ci.entrypoint = true;
                for (Finding f : ci.findings.values()) f.entrypoint = true;
            }
        }
        if (entrypoints.stream().anyMatch(s -> s.startsWith("preLaunch"))) {
            resourceFinding("", "fabric.mod.json", "PRELAUNCH", Severity.INFO, "Start", "Runs before the game starts (preLaunch)",
                    "The mod uses the preLaunch entrypoint and runs before Minecraft itself is loaded.");
        }
    }

    private void obfuscationChecks() {
        int own = 0, weird = 0, indy = 0, decryptors = 0;
        for (ClassInfo ci : classes.values()) {
            if (ci.library) continue;
            own++;
            String simple = ci.name.substring(ci.name.lastIndexOf('/') + 1);
            if (simple.matches("^[Il1|_]{4,}$") || !simple.matches("^[\\x20-\\x7e]+$") || simple.matches("^[a-z]{1,2}$") || simple.matches(".*\\s.*")
                    || Set.of("if", "do", "for", "int", "new", "con", "nul", "aux", "prn", "com1", "lpt1").contains(simple.toLowerCase(Locale.ROOT))) weird++;
            indy += ci.customIndy;
            decryptors += ci.decryptors;
        }
        if (own >= 5 && weird > own * 0.3) {
            resourceFinding("", weird + " of " + own + " classes", "OBF_NAMES", Severity.LOW, "Obfuscation", "Class names are obfuscated",
                    "Many classes have meaningless names (IlIl, Unicode, a/b/c, reserved Windows names). Obfuscation is not automatically malware, but it hides what the code does.");
            tagJar("OBFUSCATED", null);
        }
        if (indy > 0) {
            resourceFinding("", indy + " calls", "OBF_INDY", indy > 20 ? Severity.MEDIUM : Severity.LOW, "Obfuscation", "InvokeDynamic obfuscation",
                    "Method calls go through custom bootstrap methods, so decompilers cannot show which method is really called – popular with obfuscators and malware.");
            tagJar("OBFUSCATED", null);
        }
        int enc = 0;
        for (ClassInfo ci : classes.values()) if (!ci.library) enc += ci.encryptedStrings;
        if (enc >= 20) {
            resourceFinding("", enc + " strings", "OBF_CHARSTRINGS", Severity.MEDIUM, "Obfuscation", "Character-by-character encrypted strings",
                    "Strings are built character by character from arithmetic (e.g. (char)(47932 - 47815)). RatScanner decrypted and checked them via emulation – but the technique itself is mostly used by malware to hide URLs and commands.");
            tagJar("OBFUSCATED", null);
        }
        if (decryptors > 0) {
            resourceFinding("", decryptors + " methods", "OBF_STRINGS", Severity.LOW, "Obfuscation", "String encryption",
                    "Methods that decrypt strings with XOR – URLs/commands are not visible in plain text, so this scan may be incomplete.");
            tagJar("OBFUSCATED", null);
        }
        for (ClassInfo ci : classes.values()) {
            if (!ci.name.startsWith("net/minecraft/") || ci.library) continue;
            if (!type.contains("Mod")) continue;
            resourceFinding(ci.container, ci.name, "MC_SHADOW", Severity.MEDIUM, "Evasion", "Mod ships Minecraft classes",
                    "Classes in net/minecraft belong to the game. A mod that ships its own can override game classes.");
            break;
        }
    }

    private void decompileAll(Map<String, Object> engines) {
        List<Map.Entry<Container, List<String>>> work = new ArrayList<>();
        int planned = 0;
        for (Container c : containers) {
            LinkedHashSet<String> flagged = new LinkedHashSet<>();
            LinkedHashSet<String> rest = new LinkedHashSet<>();
            for (ClassInfo ci : classes.values()) {
                if (!ci.container.equals(c.path) || ci.broken) continue;
                if (!ci.findings.isEmpty() || interesting(ci)) flagged.add(ci.top);
                else if (!ci.library) rest.add(ci.top);
            }
            rest.removeAll(flagged);
            List<String> list = new ArrayList<>(flagged);
            list.addAll(rest);
            if (planned + list.size() > DECOMPILE_CAP) list = list.subList(0, Math.max(0, DECOMPILE_CAP - planned));
            planned += list.size();
            if (!list.isEmpty()) work.add(Map.entry(c, list));
        }
        final int plannedTotal = planned;
        int[] doneVf = {0}, doneCfr = {0};
        Map<String, Object> vfStat = new ConcurrentHashMap<>(), cfrStat = new ConcurrentHashMap<>();
        Runnable vfTask = () -> runEngine("vineflower", work, vfStat, doneVf, doneCfr, plannedTotal);
        Runnable cfrTask = () -> runEngine("cfr", work, cfrStat, doneCfr, doneVf, plannedTotal);
        job.stage("Decompiling (Vineflower + CFR)", 38);
        CompletableFuture<Void> a = CompletableFuture.runAsync(vfTask);
        CompletableFuture<Void> b = CompletableFuture.runAsync(cfrTask);
        CompletableFuture.allOf(a, b).join();
        engines.put("vineflower", vfStat);
        engines.put("cfr", cfrStat);

        job.stage("Source analysis", 92);
        for (Map.Entry<String, String> e : job.sources.entrySet()) {
            String k = e.getKey();
            String engine = k.substring(0, k.indexOf('|'));
            String rest = k.substring(k.indexOf('|') + 1);
            String container = rest.substring(0, rest.lastIndexOf('!'));
            String top = rest.substring(rest.lastIndexOf('!') + 1);
            ClassInfo ci = classes.get(key(container, top));
            if (ci == null) continue;
            SourceScanner.scan(ci, e.getValue(), engine);
        }
    }

    private static boolean interesting(ClassInfo ci) {
        for (String t : ci.tags.keySet()) {
            if (!Set.of("NET", "FILE_READ", "FILE_WRITE", "REFLECT", "ENV", "FILE_WALK", "S_UUID", "S_MODSDIR", "S_JAREXT", "MC_SESSION", "FILE_DELETE", "B64", "DESKTOP").contains(t)) return true;
        }
        return false;
    }

    private void runEngine(String engine, List<Map.Entry<Container, List<String>>> work, Map<String, Object> stat, int[] mine, int[] other, int planned) {
        long start = System.currentTimeMillis();
        int ok = 0, failed = 0;
        String status = "ok";
        outer:
        for (Map.Entry<Container, List<String>> w : work) {
            Container c = w.getKey();
            List<String> tops = w.getValue();
            for (int i = 0; i < tops.size(); i += BATCH) {
                long left = ENGINE_BUDGET_MS - (System.currentTimeMillis() - start);
                if (left < 5000) {
                    status = "budget";
                    break outer;
                }
                List<String> batch = tops.subList(i, Math.min(tops.size(), i + BATCH));
                File jar = null;
                try {
                    jar = Decompilers.writeBatch(job.dir, c, batch);
                    Map<String, String> out = engine.equals("vineflower") ? Decompilers.vineflower(jar, c.file, Math.min(left, 120_000)) : Decompilers.cfr(jar, c.file, Math.min(left, 120_000));
                    for (Map.Entry<String, String> e : out.entrySet()) {
                        job.sources.put(engine + "|" + c.path + "!" + e.getKey(), e.getValue());
                        ok++;
                    }
                    failed += Math.max(0, batch.size() - out.size());
                } catch (Exception ex) {
                    failed += batch.size();
                    status = ex instanceof TimeoutException ? "timeout" : "error";
                } finally {
                    if (jar != null) Decompilers.deleteQuietly(jar);
                }
                synchronized (job) {
                    mine[0] += batch.size();
                    job.progress(38 + (int) (54.0 * (mine[0] + other[0]) / Math.max(1, planned * 2)));
                }
            }
        }
        stat.put("status", status);
        stat.put("classes", ok);
        stat.put("failed", failed);
        stat.put("ms", System.currentTimeMillis() - start);
    }

    private void applyCombos(ClassInfo ci) {
            for (Rules.Combo co : Rules.COMBOS) {
                if (co.id().endsWith("_B") && ci.findings.containsKey("COMBO_" + co.id().substring(0, co.id().length() - 2))) continue;
                if (matches(co, ci.tags.keySet())) {
                    Finding f = new Finding("COMBO_" + co.id(), co.severity(), co.category(), co.title(), co.description());
                    List<String> used = new ArrayList<>(co.all());
                    for (String t : co.any()) if (ci.tags.containsKey(t)) used.add(t);
                    Evidence first = ci.tags.get(used.get(0));
                    f.at(ci.container, ci.name, first, "asm");
                    f.related = new ArrayList<>();
                    for (String t : used) {
                        Evidence ev = ci.tags.get(t);
                        if (ev != null) f.related.add(evMap(t, ci.name, ev));
                    }
                    ci.add(f);
                }
            }
    }

    private void evaluateCombos() {
        Map<String, Set<String>> unionTags = new HashMap<>();
        for (ClassInfo ci : classes.values()) {
            applyCombos(ci);
            if (!ci.library || !ci.findings.isEmpty()) {
                for (String t : ci.tags.keySet()) {
                    unionTags.computeIfAbsent(t, k -> new LinkedHashSet<>()).add(ci.name);
                    if (!jarTagEvidence.containsKey(t)) jarTagEvidence.put(t, ci.tags.get(t));
                }
            }
        }
        Set<String> all = new HashSet<>(unionTags.keySet());
        all.addAll(jarTags);
        Set<String> firedIds = new HashSet<>();
        for (ClassInfo ci : classes.values()) for (String r : ci.findings.keySet()) firedIds.add(r);
        for (Rules.Combo co : Rules.COMBOS) {
            if (!co.jarLevel() || !matches(co, all)) continue;
            String baseId = co.id().replaceAll("_B$", "");
            if (firedIds.contains("COMBO_" + co.id()) || firedIds.contains("COMBO_" + baseId)) continue;
            boolean onlyResourceTags = true;
            for (String t : co.all()) if (!t.startsWith("R_")) onlyResourceTags = false;
            Severity sev = co.id().equals("FORCE_OP") || co.id().equals("BLOB_LOADER") || co.id().equals("HIDDEN_CLASS_LOADER") || onlyResourceTags ? co.severity() : co.severity().lower();
            Finding f = new Finding("JAR_" + co.id(), sev, co.category(), co.title() + " (across classes)",
                    co.description() + " The pieces are spread over several classes – a common trick to dodge scanners.");
            f.related = new ArrayList<>();
            List<String> used = new ArrayList<>(co.all());
            for (String t : co.any()) if (all.contains(t)) used.add(t);
            for (String t : used) {
                Evidence ev = jarTagEvidence.get(t);
                Set<String> where = unionTags.getOrDefault(t, Set.of());
                String cls = where.isEmpty() ? null : where.iterator().next();
                f.related.add(evMap(t, cls, ev));
            }
            if (!f.related.isEmpty()) {
                Map<String, String> r0 = f.related.get(0);
                f.cls = r0.get("cls");
                f.evidence = r0.get("evidence");
                f.needle = r0.get("needle");
                f.method = r0.get("method");
            }
            f.source = "asm";
            resourceFindings.add(f);
            firedIds.add("JAR_" + co.id());
        }
        injectedEntrypoints();
        if (Rules.BAD_HASHES.contains(job.sha256)) {
            resourceFinding("", job.sha256, "KNOWN_BAD_HASH", Severity.CRITICAL, "Known malware", "File is known malware",
                    "The SHA-256 hash is on the list of known malware.");
        }
        Evidence obf = jarTagEvidence.get("OBFUSCATED");
        if (jarTags.contains("OBFUSCATED") && obf == null) jarTagEvidence.remove("OBFUSCATED");
    }

    private void injectedEntrypoints() {
        Map<String, Integer> roots = new HashMap<>();
        int own = 0;
        for (ClassInfo ci : classes.values()) {
            if (!ci.container.isEmpty() || ci.library) continue;
            own++;
            roots.merge(root(ci.name), 1, Integer::sum);
        }
        if (own < 20) return;
        for (String e : entrypoints) {
            String cls = e.substring(e.indexOf(':') + 1).trim();
            if (cls.contains("::")) cls = cls.substring(0, cls.indexOf("::"));
            String internal = cls.replace('.', '/');
            int share = roots.getOrDefault(root(internal), 0);
            if (share * 20 >= own) continue;
            ClassInfo ci = classes.get(key("", internal));
            Severity max = ci == null ? null : ci.maxSeverity();
            boolean bad = max != null && max.atLeast(Severity.HIGH) || (ci != null && ci.tags.containsKey("SPOOF_PKG"));
            Finding f = new Finding("INJECTED_ENTRYPOINT", bad ? Severity.CRITICAL : Severity.MEDIUM, "Infection", bad ? "Injected entrypoint" : "Foreign entrypoint",
                    "The entrypoint '" + e + "' points to a package that has almost nothing to do with the rest of the mod (" + share + " of " + own + " classes). "
                            + (bad ? "The code there is suspicious itself – typical for a mod that was infected afterwards (e.g. the SilentNet injector): the real mod keeps working but also starts malware." : "Can be harmless (compatibility module), but it is also the pattern of injected mods."));
            f.container = "";
            f.cls = internal;
            f.evidence = e;
            f.needle = internal.substring(internal.lastIndexOf('/') + 1);
            f.source = "resource";
            f.entrypoint = true;
            resourceFindings.add(f);
        }
    }

    private static String root(String internal) {
        String[] p = internal.split("/");
        return p.length >= 3 ? p[0] + "/" + p[1] : p.length == 2 ? p[0] : "";
    }

    private static Map<String, String> evMap(String tag, String cls, Evidence ev) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("tag", tag);
        Rules.CapInfo ci = Rules.CAPS.get(tag);
        m.put("label", ci != null ? ci.label() : tagLabel(tag));
        if (cls != null) m.put("cls", cls);
        if (ev != null) {
            if (ev.method() != null) m.put("method", ev.method());
            m.put("evidence", ev.text());
            if (ev.needle() != null) m.put("needle", ev.needle());
        }
        return m;
    }

    static String tagLabel(String tag) {
        return switch (tag) {
            case "S_EXFIL" -> "Webhook/exfil address";
            case "S_REMOTE" -> "Suspicious download address";
            case "S_IPGRAB" -> "IP lookup";
            case "S_STEAL" -> "Credential paths";
            case "S_BROWSER" -> "Browser profiles";
            case "S_CRYPTOADDR" -> "Crypto addresses";
            case "S_PERSIST" -> "Autostart";
            case "S_EVASION" -> "Anti-analysis";
            case "S_SHELL" -> "Shell commands";
            case "S_EXECEXT" -> ".exe/.bat file names";
            case "S_MINER" -> "Mining";
            case "S_SYSINFO" -> "System info";
            case "S_MODSDIR" -> "mods/plugins folder";
            case "S_JAREXT" -> ".jar files";
            case "S_UUID" -> "Hard-coded UUID";
            case "S_TOKENWORD" -> "Token keywords";
            case "S_PAY" -> "/pay command";
            case "S_OPCMD" -> "OP/permission command";
            case "R_BLOB" -> "Encrypted resource";
            case "R_HIDDENCLASS" -> "Disguised class";
            case "S_B64STR" -> "Base64 strings";
            case "S_BYTEARRAY_STR" -> "Strings from byte arrays";
            default -> tag;
        };
    }

    private static boolean matches(Rules.Combo co, Set<String> tags) {
        for (String t : co.all()) if (!tags.contains(t)) return false;
        if (co.any().isEmpty()) return true;
        for (String t : co.any()) if (tags.contains(t)) return true;
        return false;
    }

    private Map<String, Object> buildReport(Map<String, Object> hashes, Map<String, Object> engines, long ms) {
        List<Finding> findings = new ArrayList<>(resourceFindings);
        for (ClassInfo ci : classes.values()) {
            for (Finding f : ci.findings.values()) {
                if (ci.library && Rules.CAPS.values().stream().anyMatch(c -> c.title() != null && c.title().equals(f.title))) continue;
                findings.add(f);
            }
            for (Map.Entry<String, Evidence> t : ci.tags.entrySet()) {
                Rules.CapInfo cap = Rules.CAPS.get(t.getKey());
                if (cap == null || cap.alone() == null || ci.library) continue;
                Finding f = new Finding("CAP_" + t.getKey(), cap.alone(), cap.category(), cap.title(), cap.description())
                        .at(ci.container, ci.name, t.getValue(), "asm");
                f.entrypoint = ci.entrypoint;
                findings.add(f);
            }
        }
        findings.sort(Comparator.comparing((Finding f) -> f.severity.ordinal()).thenComparing(f -> f.library).thenComparing(f -> f.title));

        Map<String, Integer> ruleCount = new LinkedHashMap<>();
        Map<String, Finding> ruleFirst = new LinkedHashMap<>();
        for (Finding f : findings) {
            String base = f.rule.replaceFirst("^JAR_", "COMBO_");
            ruleCount.merge(base, f.occurrences, Integer::sum);
            ruleFirst.putIfAbsent(base, f);
        }
        double score = 0;
        int crit = 0, high = 0;
        Set<String> highTitles = new HashSet<>();
        for (Map.Entry<String, Finding> e : ruleFirst.entrySet()) {
            Finding f = e.getValue();
            double w = f.severity.weight * (1 + Math.min(ruleCount.get(e.getKey()) - 1, 4) * 0.08);
            if (f.library) w *= 0.5;
            score += w;
            if (f.severity == Severity.CRITICAL && !f.library) crit++;
            if (f.severity == Severity.HIGH) highTitles.add(f.category + f.title);
            if (f.severity.atLeast(Severity.HIGH) && f.library && f.severity == Severity.CRITICAL) high++;
        }
        high += highTitles.size();
        boolean obfuscated = jarTags.contains("OBFUSCATED");
        if (obfuscated && (crit > 0 || high > 0)) score *= 1.15;
        String verdict;
        if (crit > 0 || high >= 3 || score >= 70) verdict = "MALICIOUS";
        else if (high > 0 || score >= 22) verdict = "SUSPICIOUS";
        else if (score >= 6) verdict = "CAUTION";
        else verdict = "CLEAN";

        Map<String, Integer> sevCounts = new LinkedHashMap<>();
        for (Severity s : Severity.values()) sevCounts.put(s.name(), 0);
        for (Finding f : findings) sevCounts.merge(f.severity.name(), 1, Integer::sum);

        Map<String, Integer> capCounts = new LinkedHashMap<>();
        for (ClassInfo ci : classes.values()) {
            if (ci.library) continue;
            for (String t : ci.tags.keySet()) if (Rules.CAPS.containsKey(t)) capCounts.merge(t, 1, Integer::sum);
        }
        List<Map<String, Object>> caps = new ArrayList<>();
        for (Map.Entry<String, Integer> e : capCounts.entrySet()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("tag", e.getKey());
            m.put("label", Rules.CAPS.get(e.getKey()).label());
            m.put("category", Rules.CAPS.get(e.getKey()).category());
            m.put("classes", e.getValue());
            caps.add(m);
        }

        List<Map<String, Object>> classList = new ArrayList<>();
        Map<String, Severity> topSev = new HashMap<>();
        for (ClassInfo ci : classes.values()) {
            Severity s = ci.maxSeverity();
            for (Map.Entry<String, Evidence> t : ci.tags.entrySet()) {
                Rules.CapInfo cap = Rules.CAPS.get(t.getKey());
                if (cap != null && cap.alone() != null && !ci.library && (s == null || cap.alone().ordinal() < s.ordinal())) s = cap.alone();
            }
            if (s != null) topSev.merge(key(ci.container, ci.top), s, (x, y) -> x.ordinal() < y.ordinal() ? x : y);
        }
        for (ClassInfo ci : classes.values()) {
            if (!ci.name.equals(ci.top)) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("c", ci.container);
            m.put("n", ci.name);
            Severity s = topSev.get(key(ci.container, ci.name));
            if (s != null) m.put("s", s.name());
            if (ci.library) m.put("lib", true);
            if (ci.hidden) m.put("hidden", true);
            if (ci.entrypoint) m.put("entry", true);
            classList.add(m);
        }

        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("id", job.id);
        rep.put("fileName", job.fileName);
        rep.put("size", job.size);
        rep.put("hashes", hashes);
        rep.put("scannedAt", new Date().toInstant().toString());
        rep.put("durationMs", ms);
        rep.put("type", type);
        rep.put("meta", meta);
        rep.put("entrypoints", entrypoints);
        rep.put("verdict", verdict);
        rep.put("score", (int) Math.min(100, Math.round(score)));
        rep.put("obfuscated", obfuscated);
        rep.put("severityCounts", sevCounts);
        rep.put("capabilities", caps);
        rep.put("findings", findings);
        rep.put("classes", classList);
        rep.put("classCount", classes.size());
        List<Map<String, Object>> cs = new ArrayList<>();
        for (Container c : containers) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("path", c.path.isEmpty() ? "(main JAR)" : c.path);
            m.put("raw", c.path);
            m.put("classes", c.classes.size());
            m.put("depth", c.depth);
            cs.add(m);
        }
        rep.put("containers", cs);
        rep.put("resources", resources.size() > 1500 ? resources.subList(0, 1500) : resources);
        rep.put("resourceCount", resources.size());
        rep.put("engines", engines);
        if (binaryInfo != null) rep.put("binary", binaryInfo);
        return rep;
    }

    static byte[] readLimited(InputStream in, long max) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        long total = 0;
        int r;
        while ((r = in.read(buf)) != -1) {
            total += r;
            if (total > max) throw new IOException("Entry too large (> " + (max >> 20) + " MB)");
            bos.write(buf, 0, r);
        }
        return bos.toByteArray();
    }

    static String classNameOf(byte[] data, String fallback) {
        try {
            return new org.objectweb.asm.ClassReader(data).getClassName();
        } catch (Throwable t) {
            return fallback;
        }
    }

    static double entropy(byte[] data) {
        int[] f = new int[256];
        int n = Math.min(data.length, 1 << 20);
        for (int i = 0; i < n; i++) f[data[i] & 0xff]++;
        double e = 0;
        for (int c : f) {
            if (c == 0) continue;
            double p = c / (double) n;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }

    static String hex(String algo, byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance(algo).digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    String sourceFor(String engine, String container, String top) throws Exception {
        String k = engine + "|" + container + "!" + top;
        String cached = job.sources.get(k);
        if (cached != null) return cached;
        Container c = containers.stream().filter(x -> x.path.equals(container)).findFirst().orElse(null);
        if (c == null) throw new IllegalArgumentException("Unknown archive");
        if (engine.equals("asm")) {
            String bc = Decompilers.bytecode(c, top);
            job.sources.put(k, bc);
            return bc;
        }
        File jar = Decompilers.writeBatch(job.dir, c, List.of(top));
        try {
            Map<String, String> out = engine.equals("vineflower") ? Decompilers.vineflower(jar, c.file, 60_000) : Decompilers.cfr(jar, c.file, 60_000);
            for (Map.Entry<String, String> e : out.entrySet()) job.sources.put(engine + "|" + c.path + "!" + e.getKey(), e.getValue());
            String s = out.get(top);
            if (s == null && !out.isEmpty()) s = out.values().iterator().next();
            if (s == null) s = "// " + engine + " could not decompile this class.";
            job.sources.put(k, s);
            return s;
        } finally {
            Decompilers.deleteQuietly(jar);
        }
    }
}
