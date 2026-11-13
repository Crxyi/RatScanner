package org.ratscanner;

import java.util.*;

enum Severity {
    CRITICAL(40), HIGH(18), MEDIUM(7), LOW(2), INFO(0);

    final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    Severity lower() {
        return this == CRITICAL ? HIGH : this == HIGH ? MEDIUM : this == MEDIUM ? LOW : INFO;
    }

    boolean atLeast(Severity other) {
        return ordinal() <= other.ordinal();
    }
}

record Evidence(String method, int line, String text, String needle) {
}

final class Finding {
    String rule;
    Severity severity;
    String category;
    String title;
    String description;
    String container;
    String cls;
    String method;
    int line;
    String evidence;
    String needle;
    String source;
    boolean library;
    boolean entrypoint;
    int occurrences = 1;
    List<Map<String, String>> related;

    Finding(String rule, Severity severity, String category, String title, String description) {
        this.rule = rule;
        this.severity = severity;
        this.category = category;
        this.title = title;
        this.description = description;
    }

    Finding at(String container, String cls, Evidence ev, String source) {
        this.container = container;
        this.cls = cls;
        if (ev != null) {
            this.method = ev.method();
            this.line = ev.line();
            this.evidence = ev.text();
            this.needle = ev.needle();
        }
        this.source = source;
        return this;
    }
}

final class ClassInfo {
    final String container;
    final String name;
    final String top;
    final boolean library;
    final boolean hidden;
    final String entryPath;
    final Map<String, Evidence> tags = new LinkedHashMap<>();
    final Map<String, Finding> findings = new LinkedHashMap<>();
    int customIndy;
    int decryptors;
    int encryptedStrings;
    boolean broken;
    boolean entrypoint;
    boolean modAnnotation;

    ClassInfo(String container, String name, String top, boolean library, boolean hidden, String entryPath) {
        this.container = container;
        this.name = name;
        this.top = top;
        this.library = library;
        this.hidden = hidden;
        this.entryPath = entryPath;
    }

    void tag(String tag, Evidence ev) {
        tags.putIfAbsent(tag, ev);
    }

    void add(Finding f) {
        Finding prev = findings.get(f.rule);
        if (prev != null) {
            prev.occurrences++;
            return;
        }
        f.library = library;
        f.entrypoint = entrypoint;
        findings.put(f.rule, f);
    }

    Severity maxSeverity() {
        Severity max = null;
        for (Finding f : findings.values()) if (max == null || f.severity.ordinal() < max.ordinal()) max = f.severity;
        return max;
    }
}

final class Container {
    final String path;
    final java.io.File file;
    final Map<String, byte[]> classes = new LinkedHashMap<>();
    final int depth;

    Container(String path, java.io.File file, int depth) {
        this.path = path;
        this.file = file;
        this.depth = depth;
    }
}
