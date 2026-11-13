package org.ratscanner;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

final class ScanJob {
    final String id;
    final String fileName;
    final long size;
    final File dir;
    final boolean fullDecompile;
    final long created = System.currentTimeMillis();
    final Map<String, String> sources = new ConcurrentHashMap<>();
    volatile byte[] data;
    volatile String status = "queued";
    volatile String stage = "Queued";
    volatile int progress;
    volatile String error;
    volatile String sha256;
    volatile Map<String, Object> report;
    volatile Scanner scanner;
    volatile String userId;
    final String ownerToken = newToken();

    private static String newToken() {
        byte[] b = new byte[18];
        Main.RNG.nextBytes(b);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    ScanJob(String id, String fileName, byte[] data, boolean fullDecompile) throws IOException {
        this.id = id;
        this.fileName = fileName;
        this.data = data;
        this.size = data.length;
        this.fullDecompile = fullDecompile;
        File d;
        try {
            d = Files.createTempDirectory("ratscan-" + id, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))).toFile();
        } catch (UnsupportedOperationException e) {
            d = Files.createTempDirectory("ratscan-" + id).toFile();
        }
        this.dir = d;
    }

    void stage(String s, int p) {
        stage = s;
        progress = Math.max(progress, p);
    }

    void progress(int p) {
        progress = Math.max(progress, Math.min(99, p));
    }

    Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("status", status);
        m.put("stage", stage);
        m.put("progress", progress);
        m.put("fileName", fileName);
        if (error != null) m.put("error", error);
        if (report != null) m.put("report", report);
        return m;
    }

    void cleanup() {
        sources.clear();
        scanner = null;
        try (var walk = Files.walk(dir.toPath())) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                }
            });
        } catch (IOException ignored) {
        }
    }
}
