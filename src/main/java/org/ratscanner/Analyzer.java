package org.ratscanner;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class Analyzer {

    private static final Pattern B64 = Pattern.compile("^[A-Za-z0-9+/_-]{12,}={0,2}$");
    private static final Pattern HEX = Pattern.compile("^(?:[0-9a-fA-F]{2}){8,}$");

    static ClassInfo analyze(String container, String entryPath, byte[] bytes, boolean hidden, Set<String> containerClassNames) {
        ClassNode node = new ClassNode();
        String name;
        try {
            ClassReader reader = new ClassReader(bytes);
            name = reader.getClassName();
            reader.accept(node, ClassReader.SKIP_FRAMES);
        } catch (Throwable t) {
            String fallback = entryPath.endsWith(".class") ? entryPath.substring(0, entryPath.length() - 6) : entryPath;
            ClassInfo ci = new ClassInfo(container, fallback, fallback, Rules.isLibrary(fallback), hidden, entryPath);
            ci.broken = true;
            ci.add(new Finding("BROKEN_CLASS", Severity.LOW, "Obfuscation", "Tampered class file",
                    "ASM could not read the class (" + t.getClass().getSimpleName() + "). Obfuscators corrupt classes on purpose to break decompilers.")
                    .at(container, fallback, new Evidence(null, 0, entryPath, null), "asm"));
            for (String s : rawStrings(bytes)) processString(ci, s, new Evidence(null, 0, s, s), "raw", 0);
            return ci;
        }
        String top = topLevel(name, containerClassNames);
        ClassInfo ci = new ClassInfo(container, name, top, Rules.isLibrary(name), hidden, entryPath);

        if (!hidden && entryPath.endsWith(".class") && !entryPath.contains("META-INF/versions/")) {
            String expected = entryPath.substring(0, entryPath.length() - 6);
            if (!expected.equals(name)) {
                ci.add(new Finding("NAME_MISMATCH", Severity.LOW, "Obfuscation", "File name does not match the class",
                        "The file '" + entryPath + "' actually contains the class '" + name + "'.").at(container, name, new Evidence(null, 0, entryPath, null), "asm"));
            }
        }
        if (name.startsWith("java/") || name.startsWith("jdk/") || name.startsWith("sun/")) {
            ci.add(new Finding("JDK_SHADOW", Severity.HIGH, "Evasion", "Class inside a JDK package",
                    "The JAR ships a class in the java/jdk/sun package – an attempt to disguise itself as a system class.")
                    .at(container, name, new Evidence(null, 0, name, null), "asm"));
        }
        String spoof = spoofedPackage(name);
        if (spoof != null) {
            ci.tag("SPOOF_PKG", new Evidence(null, 0, name, null));
            ci.add(new Finding("SPOOF_PACKAGE", Severity.HIGH, "Evasion", "Fake package: imitates " + spoof,
                    "The class lives in a package that looks like " + spoof + " but does not belong to it (e.g. net/fabric instead of net/fabricmc). Injected malware hides between real libraries this way.")
                    .at(container, name, new Evidence(null, 0, name.replace('/', '.'), null), "asm"));
        }
        for (Rules.Family fam : Rules.FAMILIES) {
            for (String prefix : fam.classPrefixes()) {
                if (name.startsWith(prefix)) {
                    ci.add(new Finding("FAMILY_" + fam.name().toUpperCase(Locale.ROOT), fam.severity(), "Known malware", "Known malware: " + fam.name(),
                            fam.description() + " (class name matches the known family.)").at(container, name, new Evidence(null, 0, name, null), "asm"));
                }
            }
        }
        if (node.visibleAnnotations != null) {
            for (AnnotationNode an : node.visibleAnnotations) {
                if (an.desc.equals("Lnet/minecraftforge/fml/common/Mod;") || an.desc.equals("Lnet/neoforged/fml/common/Mod;")) ci.modAnnotation = true;
            }
        }

        if (node.fields != null) {
            for (FieldNode f : node.fields) {
                if (f.value instanceof String s) processString(ci, s, new Evidence("<field " + f.name + ">", 0, s, s), "ldc", 0);
            }
        }

        if (node.methods != null) {
            for (MethodNode m : node.methods) analyzeMethod(ci, m);
        }
        return ci;
    }

    private static void analyzeMethod(ClassInfo ci, MethodNode m) {
        String mname = m.name + m.desc;
        int line = 0;
        int xors = 0;
        boolean charOps = false;
        List<String> tags = new ArrayList<>(4);
        String[] prev = new String[1];
        AbstractInsnNode[] insns = m.instructions.toArray();
        for (int i = 0; i < insns.length; i++) {
            AbstractInsnNode in = insns[i];
            if (in instanceof LineNumberNode ln) {
                line = ln.line;
                continue;
            }
            tags.clear();
            switch (in) {
                case MethodInsnNode mi -> {
                    Rules.callTags(mi.owner, mi.name, tags);
                    if (!tags.isEmpty()) {
                        String simple = mi.owner.substring(mi.owner.lastIndexOf('/') + 1);
                        String needle = mi.name.equals("<init>") ? "new " + simple.substring(simple.lastIndexOf('$') + 1) : mi.name + "(";
                        Evidence ev = new Evidence(mname, line, simple + "." + mi.name, needle);
                        for (String t : tags) ci.tag(t, ev);
                    }
                    if (mi.owner.equals("java/lang/String") && (mi.name.equals("toCharArray") || mi.name.equals("charAt"))) charOps = true;
                    if (mi.owner.equals("java/lang/ClassLoader") && mi.name.equals("loadClass")) {
                        String prevLdc = previousString(insns, i);
                        if (prevLdc != null && prevLdc.equals("Utility")) {
                            ci.add(new Finding("FRACTUREISER_STAGE0", Severity.CRITICAL, "Known malware", "fractureiser Stage-0-Loader",
                                    "Loads a class named 'Utility' through a ClassLoader – exactly the pattern of the fractureiser worm.")
                                    .at(ci.container, ci.name, new Evidence(mname, line, "loadClass(\"Utility\")", "Utility"), "asm"));
                        }
                    }
                }
                case FieldInsnNode fi -> {
                    Rules.fieldTags(fi.owner, fi.name, tags);
                    for (String t : tags) ci.tag(t, new Evidence(mname, line, fi.owner.substring(fi.owner.lastIndexOf('/') + 1) + "." + fi.name, fi.name));
                }
                case TypeInsnNode ti -> {
                    if (ti.getOpcode() == Opcodes.NEW) {
                        Rules.typeTags(ti.desc, tags);
                        for (String t : tags) ci.tag(t, new Evidence(mname, line, "new " + ti.desc, ti.desc.substring(ti.desc.lastIndexOf('/') + 1)));
                    }
                }
                case LdcInsnNode ldc -> {
                    if (ldc.cst instanceof String s) {
                        processString(ci, s, new Evidence(mname, line, s, s), "ldc", 0);
                        joinWithPrevious(ci, prev, s, mname, line);
                        prev[0] = s;
                    }
                }
                case InvokeDynamicInsnNode indy -> {
                    Handle bsm = indy.bsm;
                    if (!Rules.STANDARD_BOOTSTRAPS.contains(bsm.getOwner())) ci.customIndy++;
                    if (indy.bsmArgs != null) {
                        for (Object a : indy.bsmArgs) {
                            if (a instanceof String s) {
                                for (String part : s.split("[\\u0001\\u0002]")) {
                                    if (part.length() >= 3) {
                                        processString(ci, part, new Evidence(mname, line, part, part), "indy", 0);
                                        joinWithPrevious(ci, prev, part, mname, line);
                                        prev[0] = part;
                                    }
                                }
                            }
                        }
                    }
                }
                case InsnNode x -> {
                    if (x.getOpcode() == Opcodes.IXOR || x.getOpcode() == Opcodes.LXOR) xors++;
                }
                default -> {
                }
            }
        }
        List<StringEmulator.Decoded> decoded = StringEmulator.decode(m);
        if (!decoded.isEmpty()) {
            String[] dprev = new String[1];
            StringBuilder all = new StringBuilder();
            int hidden = 0;
            for (StringEmulator.Decoded d : decoded) {
                if (!isPlainConstant(m, d.value())) hidden++;
                processString(ci, d.value(), new Evidence(mname, d.line(), d.value(), null), "decrypted", 0);
                joinWithPrevious(ci, dprev, d.value(), mname, d.line());
                dprev[0] = d.value();
                if (all.length() < 20_000) all.append(d.value());
            }
            if (hidden >= 3) {
                ci.encryptedStrings += hidden;
                ci.tag("S_ENCSTR", new Evidence(mname, decoded.get(0).line(), decoded.get(0).value(), null));
            }
            scanConcatenation(ci, all.toString(), mname, decoded.get(0).line());
        }
        Type ret = Type.getReturnType(m.desc);
        if (ret.getSort() == Type.OBJECT && ret.getInternalName().equals("java/lang/String") && (m.access & Opcodes.ACC_STATIC) != 0
                && m.desc.startsWith("(Ljava/lang/String;") && xors >= 1 && charOps) {
            ci.decryptors++;
        }
    }

    private static boolean isPlainConstant(MethodNode m, String s) {
        for (AbstractInsnNode in = m.instructions.getFirst(); in != null; in = in.getNext())
            if (in instanceof LdcInsnNode l && s.equals(l.cst)) return true;
        return false;
    }

    private static void scanConcatenation(ClassInfo ci, String all, String mname, int line) {
        if (all.length() < 8) return;
        String lower = all.toLowerCase(Locale.ROOT);
        for (Rules.Family fam : Rules.FAMILIES) {
            for (String ioc : fam.strings()) {
                if (lower.contains(ioc)) {
                    ci.tag("S_EXFIL", new Evidence(mname, line, ioc, null));
                    ci.add(new Finding("FAMILY_" + fam.name().toUpperCase(Locale.ROOT), fam.severity(), "Known malware", "Known malware: " + fam.name(),
                            fam.description() + " (indicator: " + ioc + ")").at(ci.container, ci.name, new Evidence(mname, line, "[decrypted] " + ioc, null), "asm"));
                }
            }
        }
        for (Rules.StrRule r : Rules.STRING_RULES) {
            if (r.severity() == null || !JOIN_TAGS.contains(r.tag()) || ci.findings.containsKey("STR_" + r.id() + "_DECRYPTED") || ci.findings.containsKey("STR_" + r.id() + "_JOINED")) continue;
            java.util.regex.Matcher mt = r.pattern().matcher(all);
            if (!mt.find()) continue;
            String hit = all.substring(Math.max(0, mt.start() - 20), Math.min(all.length(), mt.end() + 40));
            ci.tag(r.tag(), new Evidence(mname, line, hit, null));
            ci.add(new Finding("STR_" + r.id() + "_JOINED", r.severity(), r.category(), r.title() + " (hidden: encrypted + split)", r.description()
                    + " The string is encrypted and only assembled from pieces at runtime.")
                    .at(ci.container, ci.name, new Evidence(mname, line, "[decrypted] " + clip(hit), null), "asm"));
        }
    }

    private static final Set<String> JOIN_TAGS = Set.of("S_EXFIL", "S_REMOTE", "S_IPGRAB", "S_STEAL", "S_MINER", "S_EVASION", "S_PERSIST", "S_SHELL");

    private static void joinWithPrevious(ClassInfo ci, String[] prev, String s, String mname, int line) {
        if (prev[0] == null || prev[0].length() + s.length() > 600) return;
        String joined = prev[0] + s;
        Evidence ev = new Evidence(mname, line, joined, s);
        String jl = joined.toLowerCase(Locale.ROOT);
        for (Rules.Family fam : Rules.FAMILIES) {
            for (String ioc : fam.strings()) {
                if (jl.contains(ioc) && !prev[0].toLowerCase(Locale.ROOT).contains(ioc) && !s.toLowerCase(Locale.ROOT).contains(ioc)) {
                    ci.tag("S_EXFIL", ev);
                    ci.add(new Finding("FAMILY_" + fam.name().toUpperCase(Locale.ROOT), fam.severity(), "Known malware", "Known malware: " + fam.name(),
                            fam.description() + " (indicator: " + ioc + ")").at(ci.container, ci.name, new Evidence(mname, line, "[joined] " + clip(joined), clip(s)), "asm"));
                }
            }
        }
        for (Rules.StrRule r : Rules.STRING_RULES) {
            if (r.severity() == null || !JOIN_TAGS.contains(r.tag())) continue;
            if (!r.pattern().matcher(joined).find() || r.pattern().matcher(prev[0]).find() || r.pattern().matcher(s).find()) continue;
            ci.tag(r.tag(), ev);
            ci.add(new Finding("STR_" + r.id() + "_JOINED", r.severity(), r.category(), r.title() + " (hidden: split into pieces)", r.description()
                    + " The string is assembled from several pieces at runtime so simple scanners miss it.")
                    .at(ci.container, ci.name, new Evidence(mname, line, "[joined] " + clip(joined), clip(s)), "asm"));
        }
    }

    private static String previousString(AbstractInsnNode[] insns, int idx) {
        for (int k = idx - 1; k >= 0 && k > idx - 4; k--) if (insns[k] instanceof LdcInsnNode l && l.cst instanceof String s) return s;
        return null;
    }

    static String spoofedPackage(String name) {
        int slash = name.lastIndexOf('/');
        if (slash < 0) return null;
        String pkg = name.substring(0, slash + 1);
        if (pkg.equals("net/fabric/") || (pkg.startsWith("net/fabric/") && !pkg.startsWith("net/fabricmc/"))) return "Fabric (net.fabricmc)";
        if (pkg.startsWith("net/fabricmc/") && !pkg.startsWith("net/fabricmc/fabric/") && !pkg.startsWith("net/fabricmc/loader/") && !pkg.startsWith("net/fabricmc/api/")
                && !pkg.startsWith("net/fabricmc/mappingio/") && !pkg.startsWith("net/fabricmc/tinyremapper/") && !pkg.startsWith("net/fabricmc/accesswidener/")
                && !pkg.startsWith("net/fabricmc/mapping/") && !pkg.startsWith("net/fabricmc/devlaunchinjector/") && !pkg.startsWith("net/fabricmc/classtweaker/")) return null;
        if (pkg.startsWith("net/minecraftforge/") || pkg.startsWith("net/neoforged/")) return null;
        if (pkg.equals("net/minecraft/") && name.matches("net/minecraft/[a-z]{1,3}")) return null;
        if (pkg.startsWith("com/mojang/") && !pkg.matches("com/mojang/(authlib|brigadier|datafixers|serialization|blaze3d|logging|math|realmsclient|text2speech|bridge|jtracy|jvm|util)/.*")) return "Mojang (com.mojang)";
        if (pkg.startsWith("org/spongepowered/") && !pkg.startsWith("org/spongepowered/asm/") && !pkg.startsWith("org/spongepowered/tools/")) return "Mixin (org.spongepowered)";
        if (pkg.startsWith("net/minecraft/client/") || pkg.startsWith("net/minecraft/server/")) return null;
        return null;
    }

    static double printableRatio(String s) {
        if (s.isEmpty()) return 0;
        int ok = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' || (c >= 0xa0 && c < 0x2000)) ok++;
        }
        return ok / (double) s.length();
    }

    static void processString(ClassInfo ci, String s, Evidence ev, String origin, int depth) {
        if (s == null || s.isEmpty()) return;
        if (s.length() > 8192) s = s.substring(0, 8192);
        String trimmed = s.trim();
        String lower = trimmed.toLowerCase(Locale.ROOT);
        Evidence shown = new Evidence(ev.method(), ev.line(), clip(origin.equals("ldc") || origin.equals("source") || origin.equals("resource") || origin.equals("indy") ? trimmed : "[" + origin + "] " + trimmed), ev.needle() == null ? null : clip(ev.needle()));
        for (Rules.StrRule r : Rules.STRING_RULES) {
            Matcher mt = r.pattern().matcher(trimmed);
            if (!mt.find()) continue;
            if (origin.equals("reversed") && r.severity() == null) continue;
            ci.tag(r.tag(), shown);
            if (r.severity() != null) {
                Severity sev = r.severity();
                String title = r.title();
                if (!origin.equals("ldc") && !origin.equals("source") && !origin.equals("indy") && !origin.equals("resource")) {
                    title = title + " (hidden: " + originLabel(origin) + ")";
                    if (sev.ordinal() > Severity.HIGH.ordinal() && !origin.equals("raw")) sev = Severity.values()[sev.ordinal() - 1];
                }
                ci.add(new Finding("STR_" + r.id() + (title.equals(r.title()) ? "" : "_" + origin.toUpperCase(Locale.ROOT)), sev, r.category(), title, r.description())
                        .at(ci.container, ci.name, shown, origin.equals("source") ? "decompiler" : "asm"));
            }
        }
        for (Rules.Family fam : Rules.FAMILIES) {
            for (String ioc : fam.strings()) {
                if (lower.contains(ioc)) {
                    ci.tag("S_EXFIL", shown);
                    ci.add(new Finding("FAMILY_" + fam.name().toUpperCase(Locale.ROOT), fam.severity(), "Known malware", "Known malware: " + fam.name(),
                            fam.description() + " (indicator: " + ioc + ")").at(ci.container, ci.name, shown, "asm"));
                }
            }
        }
        if (depth > 1) return;
        if (trimmed.length() >= 12 && B64.matcher(trimmed).matches() && !trimmed.matches("^[a-z]+$") && !trimmed.matches("^[A-Z_]+$")) {
            try {
                byte[] dec = (trimmed.indexOf('-') >= 0 || trimmed.indexOf('_') >= 0 ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(padded(trimmed));
                String d = new String(dec, StandardCharsets.UTF_8);
                if (d.length() >= 4 && printableRatio(d) > 0.92) {
                    ci.tag("S_B64STR", shown);
                    processString(ci, d, ev, "base64", depth + 1);
                }
            } catch (IllegalArgumentException ignored) {
            }
        }
        if (HEX.matcher(trimmed).matches()) {
            byte[] dec = new byte[trimmed.length() / 2];
            for (int i = 0; i < dec.length; i++) dec[i] = (byte) Integer.parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
            String d = new String(dec, StandardCharsets.UTF_8);
            if (printableRatio(d) > 0.95) processString(ci, d, ev, "hex", depth + 1);
        }
        if (depth == 0 && trimmed.length() >= 10 && (trimmed.indexOf('/') >= 0 || trimmed.indexOf('.') >= 0)) {
            processString(ci, new StringBuilder(trimmed).reverse().toString(), ev, "reversed", 2);
        }
    }

    private static String originLabel(String origin) {
        return switch (origin) {
            case "base64" -> "Base64-encoded";
            case "hex" -> "hex-encoded";
            case "reversed" -> "written backwards";
            case "bytearray" -> "built from a byte array";
            case "decrypted" -> "encrypted, decrypted by emulation";
            case "raw" -> "from a corrupted class";
            default -> origin;
        };
    }

    private static String padded(String s) {
        if (s.indexOf('=') >= 0) return s;
        int pad = (4 - s.length() % 4) % 4;
        return s + "=".repeat(pad == 3 ? 0 : pad);
    }

    static String clip(String s) {
        return s.length() > 220 ? s.substring(0, 217) + "…" : s;
    }

    static String topLevel(String name, Set<String> all) {
        int idx = name.indexOf('$');
        while (idx > 0) {
            String cand = name.substring(0, idx);
            if (all.contains(cand)) return cand;
            idx = name.indexOf('$', idx + 1);
        }
        return name;
    }

    static List<String> rawStrings(byte[] data) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            int c = b & 0xff;
            if (c >= 0x20 && c < 0x7f) sb.append((char) c);
            else {
                if (sb.length() >= 6) out.add(sb.toString());
                sb.setLength(0);
            }
            if (out.size() > 20_000) break;
        }
        if (sb.length() >= 6) out.add(sb.toString());
        return out;
    }
}
