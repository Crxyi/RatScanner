package org.ratscanner;

import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.jetbrains.java.decompiler.main.decompiler.BaseDecompiler;
import org.jetbrains.java.decompiler.main.extern.IFernflowerLogger;
import org.jetbrains.java.decompiler.main.extern.IResultSaver;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.util.Textifier;
import org.objectweb.asm.util.TraceClassVisitor;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class Decompilers {

    private static final ExecutorService WORKERS = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "decompiler");
        t.setDaemon(true);
        return t;
    });

    static final java.util.concurrent.atomic.AtomicInteger RUNNING = new java.util.concurrent.atomic.AtomicInteger();
    static final int MAX_RUNNING = Integer.parseInt(java.util.Optional.ofNullable(System.getenv("MAX_DECOMPILER_THREADS")).orElse("8"));

    private static Future<?> start(Runnable r) {
        if (RUNNING.get() >= MAX_RUNNING) throw new RejectedExecutionException("Decompilers are busy (too many stuck jobs) – try again later");
        RUNNING.incrementAndGet();
        return WORKERS.submit(() -> {
            try {
                r.run();
            } finally {
                RUNNING.decrementAndGet();
            }
        });
    }

    static File writeBatch(File dir, Container c, Collection<String> tops) throws IOException {
        File out = File.createTempFile("batch", ".jar", dir);
        Set<String> wanted = new HashSet<>(tops);
        try (ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(out)))) {
            for (Map.Entry<String, byte[]> e : c.classes.entrySet()) {
                String name = e.getKey();
                String top = Analyzer.topLevel(name, c.classes.keySet());
                if (!wanted.contains(top)) continue;
                zos.putNextEntry(new ZipEntry(name + ".class"));
                zos.write(e.getValue());
                zos.closeEntry();
            }
        }
        return out;
    }

    static Map<String, String> vineflower(File batch, File library, long timeoutMs) throws Exception {
        Map<String, String> result = new ConcurrentHashMap<>();
        IResultSaver saver = new IResultSaver() {
            public void saveFolder(String path) {
            }

            public void copyFile(String source, String path, String entryName) {
            }

            public void saveClassFile(String path, String qualifiedName, String entryName, String content, int[] mapping) {
                if (content != null) result.put(qualifiedName, content);
            }

            public void createArchive(String path, String archiveName, Manifest manifest) {
            }

            public void saveDirEntry(String path, String archiveName, String entryName) {
            }

            public void copyEntry(String source, String path, String archiveName, String entry) {
            }

            public void saveClassEntry(String path, String archiveName, String qualifiedName, String entryName, String content) {
                if (content != null && qualifiedName != null) result.put(qualifiedName, content);
            }

            public void closeArchive(String path, String archiveName) {
            }
        };
        Map<String, Object> opts = new HashMap<>();
        opts.put("dgs", "1");
        opts.put("rsy", "1");
        opts.put("rbr", "1");
        opts.put("ind", "    ");
        opts.put("mpm", "15");
        opts.put("log", "ERROR");
        opts.put("thr", "1");
        IFernflowerLogger logger = new IFernflowerLogger() {
            public void writeMessage(String message, Severity severity) {
            }

            public void writeMessage(String message, Severity severity, Throwable t) {
            }
        };
        Future<?> f = start(() -> {
            BaseDecompiler d = new BaseDecompiler(saver, opts, logger);
            d.addSource(batch);
            if (library != null) d.addLibrary(library);
            d.decompileContext();
        });
        await(f, timeoutMs);
        return result;
    }

    static Map<String, String> cfr(File batch, File library, long timeoutMs) throws Exception {
        Map<String, String> result = new ConcurrentHashMap<>();
        OutputSinkFactory sink = new OutputSinkFactory() {
            public List<SinkClass> getSupportedSinks(SinkType type, Collection<SinkClass> available) {
                if (type == SinkType.JAVA && available.contains(SinkClass.DECOMPILED)) return List.of(SinkClass.DECOMPILED);
                return List.of(SinkClass.STRING);
            }

            @SuppressWarnings("unchecked")
            public <T> Sink<T> getSink(SinkType type, SinkClass sinkClass) {
                if (type == SinkType.JAVA && sinkClass == SinkClass.DECOMPILED) {
                    return x -> {
                        SinkReturns.Decompiled d = (SinkReturns.Decompiled) x;
                        String pkg = d.getPackageName();
                        String key = pkg == null || pkg.isEmpty() ? d.getClassName() : pkg.replace('.', '/') + "/" + d.getClassName();
                        result.put(key, d.getJava());
                    };
                }
                return x -> {
                };
            }
        };
        Map<String, String> opts = new HashMap<>();
        opts.put("showversion", "false");
        opts.put("silent", "true");
        opts.put("comments", "false");
        if (library != null) opts.put("extraclasspath", library.getAbsolutePath());
        Future<?> f = start(() -> new CfrDriver.Builder().withOptions(opts).withOutputSink(sink).build().analyse(List.of(batch.getAbsolutePath())));
        await(f, timeoutMs);
        return result;
    }

    private static void await(Future<?> f, long timeoutMs) throws Exception {
        try {
            f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new TimeoutException("Time limit exceeded");
        } catch (ExecutionException e) {
            Throwable c = e.getCause();
            if (c instanceof Exception ex) throw ex;
            throw new RuntimeException(c);
        }
    }

    static String bytecode(Container c, String top) {
        StringBuilder sb = new StringBuilder();
        List<String> names = new ArrayList<>();
        for (String n : c.classes.keySet()) if (n.equals(top) || Analyzer.topLevel(n, c.classes.keySet()).equals(top)) names.add(n);
        names.sort(Comparator.comparing(n -> n.equals(top) ? "" : n));
        for (String n : names) {
            try {
                StringWriter sw = new StringWriter();
                new ClassReader(c.classes.get(n)).accept(new TraceClassVisitor(null, new Textifier(), new PrintWriter(sw)), ClassReader.SKIP_FRAMES);
                sb.append("// ===== ").append(n).append(" =====\n").append(sw).append('\n');
            } catch (Throwable t) {
                sb.append("// ===== ").append(n).append(" =====\n// ASM could not read the class: ").append(t).append("\n\n");
            }
        }
        return sb.toString();
    }

    static void deleteQuietly(File f) {
        try {
            Files.deleteIfExists(f.toPath());
        } catch (IOException ignored) {
        }
    }
}
