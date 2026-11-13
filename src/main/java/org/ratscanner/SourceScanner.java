package org.ratscanner;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class SourceScanner {

    private static final Pattern LITERAL = Pattern.compile("\"((?:[^\"\\\\\\n]|\\\\.)*)\"");
    private static final Pattern CONCAT = Pattern.compile("\"\\s*\\+\\s*\"");
    private static final Pattern CHAR_CODES = Pattern.compile("new (?:byte|char)\\[\\]\\s*\\{([\\d\\s,\\-()a-z']+)}");

    static void scan(ClassInfo ci, String source, String engine) {
        ClassInfo tmp = new ClassInfo(ci.container, ci.name, ci.top, ci.library, ci.hidden, ci.entryPath);
        String[] lines = source.split("\n", -1);
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.indexOf('"') < 0 && !line.contains("new byte[]") && !line.contains("new char[]")) continue;
            String folded = CONCAT.matcher(line).replaceAll("");
            Matcher m = LITERAL.matcher(folded);
            while (m.find()) {
                String s = unescape(m.group(1));
                if (s.length() < 3 || !seen.add(s)) continue;
                Analyzer.processString(tmp, s, new Evidence(null, i + 1, s, firstLiteral(line, s)), "source", 0);
            }
            Matcher cm = CHAR_CODES.matcher(line);
            while (cm.find()) {
                String rebuilt = fromCodes(cm.group(1));
                if (rebuilt != null && rebuilt.length() >= 4 && seen.add(rebuilt)) {
                    Analyzer.processString(tmp, rebuilt, new Evidence(null, i + 1, rebuilt, "new "), "bytearray", 0);
                }
            }
        }
        for (Map.Entry<String, Evidence> t : tmp.tags.entrySet()) ci.tag(t.getKey(), t.getValue());
        for (Finding f : tmp.findings.values()) {
            if (ci.findings.containsKey(f.rule)) continue;
            f.source = engine;
            f.title = f.title + " (" + (engine.equals("cfr") ? "CFR" : "Vineflower") + ")";
            ci.add(f);
        }
    }

    private static String firstLiteral(String line, String s) {
        String probe = s.length() > 24 ? s.substring(0, 24) : s;
        return line.contains(probe) ? probe : s.length() > 12 ? s.substring(0, 12) : s;
    }

    private static String fromCodes(String body) {
        StringBuilder sb = new StringBuilder();
        for (String part : body.split(",")) {
            String p = part.trim().replaceAll("^\\((byte|char)\\)\\s*", "");
            if (p.isEmpty()) continue;
            try {
                int v;
                if (p.startsWith("'") && p.endsWith("'") && p.length() == 3) v = p.charAt(1);
                else v = Integer.parseInt(p);
                sb.append((char) (v & 0xff));
            } catch (NumberFormatException e) {
                return null;
            }
        }
        String s = sb.toString();
        return Analyzer.printableRatio(s) > 0.9 ? s : null;
    }

    static String unescape(String s) {
        if (s.indexOf('\\') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char n = s.charAt(++i);
            switch (n) {
                case 'n' -> sb.append('\n');
                case 't' -> sb.append('\t');
                case 'r' -> sb.append('\r');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case '0' -> sb.append('\0');
                case 'u' -> {
                    if (i + 4 < s.length()) {
                        try {
                            sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException e) {
                            sb.append("\\u");
                        }
                    }
                }
                default -> sb.append(n);
            }
        }
        return sb.toString();
    }
}
