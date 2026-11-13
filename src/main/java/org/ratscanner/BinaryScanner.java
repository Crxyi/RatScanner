package org.ratscanner;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

final class BinaryScanner {

    private static final Map<String, String> IMPORT_TAGS = new HashMap<>();
    private static final Map<String, String> IMPORT_CAPS = new LinkedHashMap<>();

    static {
        for (String f : List.of("CryptUnprotectData", "BCryptDecrypt", "NCryptUnprotectSecret")) IMPORT_TAGS.put(f, "DPAPI");
        for (String f : List.of("SetWindowsHookExA", "SetWindowsHookExW")) IMPORT_TAGS.put(f, "W_HOOK");
        for (String f : List.of("GetAsyncKeyState", "GetKeyboardState", "GetKeyState", "MapVirtualKeyA", "MapVirtualKeyW")) IMPORT_TAGS.put(f, "W_KEYS");
        for (String f : List.of("SetClipboardData")) IMPORT_TAGS.put(f, "CLIPBOARD_WRITE");
        for (String f : List.of("GetClipboardData")) IMPORT_TAGS.put(f, "CLIPBOARD_READ");
        for (String f : List.of("VirtualAllocEx", "VirtualAlloc2")) IMPORT_TAGS.put(f, "W_ALLOCEX");
        for (String f : List.of("WriteProcessMemory", "NtWriteVirtualMemory")) IMPORT_TAGS.put(f, "W_WRITEMEM");
        for (String f : List.of("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread")) IMPORT_TAGS.put(f, "W_REMOTETHREAD");
        for (String f : List.of("NtUnmapViewOfSection", "ZwUnmapViewOfSection")) IMPORT_TAGS.put(f, "W_UNMAP");
        for (String f : List.of("SetThreadContext", "Wow64SetThreadContext")) IMPORT_TAGS.put(f, "W_SETCTX");
        for (String f : List.of("CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread")) IMPORT_TAGS.put(f, "W_ANTIDEBUG");
        for (String f : List.of("URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW")) IMPORT_TAGS.put(f, "W_URLDOWNLOAD");
        for (String f : List.of("WinExec")) IMPORT_TAGS.put(f, "W_WINEXEC");
        for (String f : List.of("AdjustTokenPrivileges")) IMPORT_TAGS.put(f, "W_PRIV");
        for (String f : List.of("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW")) IMPORT_TAGS.put(f, "W_REGWRITE");
        for (String f : List.of("BitBlt", "GetDIBits")) IMPORT_TAGS.put(f, "W_BITBLT");
        for (String f : List.of("capCreateCaptureWindowA", "capCreateCaptureWindowW")) IMPORT_TAGS.put(f, "W_WEBCAM");
        for (String f : List.of("waveInOpen", "mciSendStringA", "mciSendStringW")) IMPORT_TAGS.put(f, "W_MIC");

        IMPORT_CAPS.put("InternetOpenA|InternetOpenW|InternetOpenUrlA|InternetOpenUrlW|HttpSendRequestA|HttpSendRequestW|WinHttpOpen|WinHttpSendRequest|URLDownloadToFileA|URLDownloadToFileW|connect|WSAConnect|send|recv", "Network access");
        IMPORT_CAPS.put("CreateProcessA|CreateProcessW|ShellExecuteA|ShellExecuteW|ShellExecuteExA|ShellExecuteExW|WinExec|CreateProcessAsUserW", "Starts processes");
        IMPORT_CAPS.put("CryptUnprotectData|BCryptDecrypt", "Decrypts protected data (DPAPI)");
        IMPORT_CAPS.put("SetWindowsHookExA|SetWindowsHookExW|GetAsyncKeyState|GetKeyboardState", "Keyboard input / hooks");
        IMPORT_CAPS.put("GetClipboardData|SetClipboardData", "Clipboard");
        IMPORT_CAPS.put("VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetThreadContext", "Writes into other processes");
        IMPORT_CAPS.put("RegSetValueExA|RegSetValueExW|RegCreateKeyExA|RegCreateKeyExW", "Writes the registry");
        IMPORT_CAPS.put("IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess", "Debugger detection");
        IMPORT_CAPS.put("BitBlt|GetDIBits", "Screen capture (GDI)");
        IMPORT_CAPS.put("CryptEncrypt|BCryptEncrypt|CryptAcquireContextA|CryptAcquireContextW", "Encryption");
        IMPORT_CAPS.put("LoadLibraryA|LoadLibraryW|LoadLibraryExA|LoadLibraryExW|GetProcAddress", "Dynamic API loading");
    }

    static Map<String, Object> scan(Scanner sc, byte[] data, String fileName) throws Exception {
        Map<String, Object> info = new LinkedHashMap<>();
        String lower = fileName.toLowerCase(Locale.ROOT);
        ClassInfo holder = new ClassInfo("", "file:" + fileName, "file:" + fileName, false, false, fileName);
        boolean mz = data.length > 0x40 && data[0] == 'M' && data[1] == 'Z';
        boolean elf = data.length > 16 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
        int magic = data.length > 4 ? ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt() : 0;
        boolean macho = magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFAEDFE;
        boolean text = Analyzer.printableRatio(new String(data, 0, Math.min(data.length, 8192), StandardCharsets.ISO_8859_1)) > 0.92;

        List<String> notes = new ArrayList<>();
        if (mz) {
            sc.type = "Windows program (PE)";
            parsePe(sc, data, info, holder, notes);
        } else if (elf) {
            sc.type = "Linux program (ELF)";
            info.put("format", "ELF");
        } else if (macho) {
            sc.type = "macOS program (Mach-O)";
            info.put("format", "Mach-O");
        } else if (text) {
            sc.type = scriptType(lower);
            info.put("format", "Text / script");
        } else {
            sc.type = "Unknown binary file";
            info.put("format", "Unknown");
        }

        if (text) {
            String t = new String(data, StandardCharsets.UTF_8);
            int n = 0;
            for (String line : t.split("\\R")) {
                if (++n > 50_000) break;
                String s = line.trim();
                if (s.isEmpty()) continue;
                Analyzer.processString(holder, s.length() > 4000 ? s.substring(0, 4000) : s, new Evidence(null, n, s, s), "resource", 1);
                for (String q : Scanner.quoted(s)) if (!q.equals(s)) Analyzer.processString(holder, q, new Evidence(null, n, q, q), "resource", 0);
            }
            scriptHeuristics(sc, t, lower);
        } else {
            int count = 0;
            for (String s : extractStrings(data)) {
                if (++count > 60_000) break;
                Analyzer.processString(holder, s, new Evidence(null, 0, s, s), "resource", 2);
            }
            info.put("strings", count);
            String all = new String(data, StandardCharsets.ISO_8859_1);
            if (all.contains("MEI\f\013\n\013\016") || all.contains("pyi-runtime-tmpdir") || all.contains("_MEIPASS")) {
                notes.add("PyInstaller");
                sc.addFinding("", "PYINSTALLER", Severity.MEDIUM, "Packing", "Python program packed with PyInstaller",
                        "The file is a Python script bundled into an .exe. Most Discord/browser stealers on the market are built exactly like this. Not malicious by itself, but a strong reason to be careful.", fileName);
            }
            if (all.contains("Nuitka") || all.contains("__nuitka")) notes.add("Nuitka (Python)");
            if (all.contains("Go build ID:") || all.contains("runtime.gopanic")) notes.add("Go");
            if (all.contains("Nullsoft") || all.contains("NSIS Error")) notes.add("NSIS installer");
            if (all.contains("Inno Setup")) notes.add("Inno Setup installer");
            if (all.contains("electron.asar") || all.contains("app.asar")) notes.add("Electron");
            if (all.contains("launch4j") || all.contains("Launch4j")) notes.add("Launch4j (Java wrapper)");
            int pk = indexOf(data, new byte[]{'P', 'K', 3, 4}, mz ? 0x200 : 0);
            if (pk >= 0 && indexOf(data, "META-INF/".getBytes(StandardCharsets.US_ASCII), pk) > 0) {
                byte[] zip = Arrays.copyOfRange(data, pk, data.length);
                File f = File.createTempFile("embedded", ".jar", sc.job.dir);
                Files.write(f.toPath(), zip);
                try {
                    sc.loadEmbedded("[embedded-jar@" + pk + "]", f);
                    notes.add("Contains a Java archive");
                    sc.addFinding("", "EMBEDDED_JAR", Severity.LOW, "Packing", "Program contains a Java archive",
                            "A JAR was found inside the program (offset " + pk + "). It was unpacked and scanned with all Java engines – see the classes below.", fileName);
                } catch (Exception ignored) {
                }
            }
        }
        info.put("notes", notes);

        applyWindowsTags(sc, holder, fileName);
        sc.mergeHolder(holder);
        return info;
    }

    private static String scriptType(String lower) {
        if (lower.endsWith(".bat") || lower.endsWith(".cmd")) return "Batch script";
        if (lower.endsWith(".ps1") || lower.endsWith(".psm1")) return "PowerShell script";
        if (lower.endsWith(".vbs") || lower.endsWith(".vbe")) return "VBScript";
        if (lower.endsWith(".js") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "JavaScript";
        if (lower.endsWith(".py") || lower.endsWith(".pyw")) return "Python script";
        if (lower.endsWith(".sh") || lower.endsWith(".command")) return "Shell script";
        if (lower.endsWith(".hta")) return "HTML application (HTA)";
        if (lower.endsWith(".lnk")) return "Windows shortcut";
        return "Text file";
    }

    private static void scriptHeuristics(Scanner sc, String t, String lower) {
        String l = t.toLowerCase(Locale.ROOT);
        if ((l.contains("frombase64string") || l.contains("-encodedcommand") || l.contains("[convert]::")) && (l.contains("iex") || l.contains("invoke-expression"))) {
            sc.addFinding("", "SCRIPT_ENCODED_EXEC", Severity.HIGH, "Execution", "Decodes and runs hidden code",
                    "The script decodes Base64 data and runs it with Invoke-Expression – the classic way to hide a malicious payload.", null);
        }
        if (lower.endsWith(".py") && (l.contains("exec(") || l.contains("eval(")) && (l.contains("base64") || l.contains("zlib") || l.contains("marshal"))) {
            sc.addFinding("", "PY_OBFUSCATED_EXEC", Severity.HIGH, "Execution", "Python runs decoded/compressed code",
                    "exec/eval on base64/zlib/marshal data – typical for obfuscated Python stealers.", null);
        }
        if (lower.endsWith(".js") && l.contains("child_process") && (l.contains("http") || l.contains("fetch("))) {
            sc.addFinding("", "JS_DOWNLOAD_EXEC", Severity.MEDIUM, "Execution", "JavaScript with network access and process execution",
                    "The script can download data and start programs.", null);
        }
    }

    private static void applyWindowsTags(Scanner sc, ClassInfo h, String fileName) {
        Set<String> t = h.tags.keySet();
        if (t.contains("W_ALLOCEX") && t.contains("W_WRITEMEM") && t.contains("W_REMOTETHREAD"))
            sc.addFinding("", "WIN_INJECTION", Severity.HIGH, "Injection", "Process injection",
                    "Imports VirtualAllocEx + WriteProcessMemory + CreateRemoteThread – the textbook way to inject code into another running program (e.g. a browser to steal cookies).", fileName);
        if (t.contains("W_UNMAP") && t.contains("W_SETCTX"))
            sc.addFinding("", "WIN_HOLLOWING", Severity.HIGH, "Injection", "Process hollowing",
                    "NtUnmapViewOfSection + SetThreadContext: replaces the code of a legit process with its own – used to hide malware inside trusted programs.", fileName);
        if (t.contains("W_HOOK") && t.contains("W_KEYS")) {
            h.tag("KEYHOOK", h.tags.get("W_HOOK"));
            sc.addFinding("", "WIN_KEYHOOK", Severity.MEDIUM, "Spying", "Keyboard hooks",
                    "SetWindowsHookEx together with key-state functions – can record keystrokes system-wide.", fileName);
        }
        if (t.contains("W_URLDOWNLOAD"))
            sc.addFinding("", "WIN_URLDOWNLOAD", Severity.MEDIUM, "Download", "Downloads files directly to disk",
                    "URLDownloadToFile saves a file from the internet in one call – popular with droppers.", fileName);
        if (t.contains("W_WINEXEC"))
            sc.addFinding("", "WIN_WINEXEC", Severity.LOW, "Execution", "Uses WinExec",
                    "Legacy API to run commands, rarely used by modern legit software but common in droppers.", fileName);
        if (t.contains("W_ANTIDEBUG"))
            sc.addFinding("", "WIN_ANTIDEBUG", Severity.LOW, "Evasion", "Debugger detection",
                    "Checks whether it is being debugged – often used to hide behaviour from analysts.", fileName);
        if (t.contains("W_WEBCAM"))
            sc.addFinding("", "WIN_WEBCAM", Severity.HIGH, "Spying", "Webcam capture",
                    "Imports the Video-for-Windows capture API – can take webcam pictures.", fileName);
        if (t.contains("W_REGWRITE") && t.contains("S_PERSIST")) h.tag("EXEC", h.tags.get("W_REGWRITE"));
    }

    private static void parsePe(Scanner sc, byte[] d, Map<String, Object> info, ClassInfo holder, List<String> notes) {
        ByteBuffer b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN);
        try {
            int pe = b.getInt(0x3C);
            if (pe <= 0 || pe + 24 > d.length || b.getInt(pe) != 0x4550) {
                info.put("format", "MZ (no valid PE header)");
                return;
            }
            int machine = b.getShort(pe + 4) & 0xffff;
            int nSec = b.getShort(pe + 6) & 0xffff;
            long ts = b.getInt(pe + 8) & 0xffffffffL;
            int optSize = b.getShort(pe + 20) & 0xffff;
            int chars = b.getShort(pe + 22) & 0xffff;
            int opt = pe + 24;
            int optMagic = b.getShort(opt) & 0xffff;
            boolean pe64 = optMagic == 0x20b;
            int subsystem = b.getShort(opt + 68) & 0xffff;
            int ddBase = opt + (pe64 ? 112 : 96);
            info.put("format", (chars & 0x2000) != 0 ? "PE DLL" : "PE executable");
            info.put("arch", switch (machine) {
                case 0x14c -> "x86 (32-bit)";
                case 0x8664 -> "x64";
                case 0xaa64 -> "ARM64";
                default -> String.format("0x%x", machine);
            });
            info.put("subsystem", subsystem == 2 ? "GUI" : subsystem == 3 ? "Console" : String.valueOf(subsystem));
            info.put("compiled", ts > 0 ? new Date(ts * 1000).toInstant().toString() : "unknown");
            if (ts * 1000 > System.currentTimeMillis() + 86_400_000L) notes.add("Timestamp in the future (faked)");

            List<int[]> secs = new ArrayList<>();
            List<Map<String, Object>> secList = new ArrayList<>();
            int sh = opt + optSize;
            long lastRaw = 0;
            for (int i = 0; i < nSec && i < 96; i++) {
                int o = sh + i * 40;
                if (o + 40 > d.length) break;
                String name = new String(d, o, 8, StandardCharsets.US_ASCII).replace("\0", "");
                int vsize = b.getInt(o + 8), va = b.getInt(o + 12), rsize = b.getInt(o + 16), rptr = b.getInt(o + 20);
                secs.add(new int[]{va, Math.max(vsize, rsize), rptr, rsize});
                lastRaw = Math.max(lastRaw, (long) rptr + rsize);
                double ent = rsize > 0 && rptr >= 0 && rptr + (long) rsize <= d.length ? Scanner.entropy(Arrays.copyOfRange(d, rptr, rptr + rsize)) : 0;
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("name", name);
                m.put("size", rsize);
                m.put("entropy", Math.round(ent * 100) / 100.0);
                secList.add(m);
                String n = name.toLowerCase(Locale.ROOT);
                if (n.startsWith("upx")) addOnce(notes, "UPX packed");
                if (n.contains("themida") || n.contains("winlice")) addOnce(notes, "Themida/WinLicense");
                if (n.startsWith(".vmp")) addOnce(notes, "VMProtect");
                if (n.contains("enigma")) addOnce(notes, "Enigma Protector");
                if (n.contains("aspack") || n.contains("adata")) addOnce(notes, "ASPack");
                if (n.contains("mpress")) addOnce(notes, "MPRESS");
                if (ent > 7.4 && rsize > 4096 && !n.equals(".rsrc")) addOnce(notes, "High-entropy section (packed/encrypted code)");
            }
            info.put("sections", secList);
            if (lastRaw > 0 && lastRaw < d.length) info.put("overlay", d.length - lastRaw);

            int impRva = b.getInt(ddBase + 8);
            Map<String, List<String>> imports = new LinkedHashMap<>();
            int impOff = rvaToOff(secs, impRva);
            int total = 0;
            if (impOff > 0) {
                for (int i = 0; i < 512; i++) {
                    int o = impOff + i * 20;
                    if (o + 20 > d.length) break;
                    int oft = b.getInt(o), nameRva = b.getInt(o + 12), ft = b.getInt(o + 16);
                    if (oft == 0 && nameRva == 0 && ft == 0) break;
                    String dll = cstr(d, rvaToOff(secs, nameRva));
                    if (dll == null) break;
                    List<String> fns = new ArrayList<>();
                    int thunk = rvaToOff(secs, oft != 0 ? oft : ft);
                    for (int k = 0; thunk > 0 && k < 4000; k++) {
                        int to = thunk + k * (pe64 ? 8 : 4);
                        if (to + 8 > d.length) break;
                        long v = pe64 ? b.getLong(to) : b.getInt(to) & 0xffffffffL;
                        if (v == 0) break;
                        boolean ordinal = pe64 ? (v & 0x8000000000000000L) != 0 : (v & 0x80000000L) != 0;
                        if (ordinal) {
                            fns.add("#" + (v & 0xffff));
                            continue;
                        }
                        String fn = cstr(d, rvaToOff(secs, (int) v) + 2);
                        if (fn == null) break;
                        fns.add(fn);
                        total++;
                        String tag = IMPORT_TAGS.get(fn);
                        if (tag != null) holder.tag(tag, new Evidence(null, 0, dll + "!" + fn, fn));
                    }
                    imports.put(dll, fns);
                }
            }
            info.put("importCount", total);
            Map<String, List<String>> shown = new LinkedHashMap<>();
            imports.forEach((k, v) -> shown.put(k, v.size() > 60 ? v.subList(0, 60) : v));
            info.put("imports", shown);
            Set<String> allFns = new HashSet<>();
            imports.values().forEach(allFns::addAll);
            List<String> caps = new ArrayList<>();
            for (Map.Entry<String, String> e : IMPORT_CAPS.entrySet())
                for (String fn : e.getKey().split("\\|"))
                    if (allFns.contains(fn)) {
                        caps.add(e.getValue());
                        break;
                    }
            info.put("capabilities", caps);
            if (total < 8 && !imports.isEmpty()) addOnce(notes, "Very few imports (APIs are resolved at runtime – packer/loader)");
            int clrRva = b.getInt(ddBase + 14 * 8);
            if (clrRva != 0) {
                addOnce(notes, ".NET assembly");
                sc.type = "Windows .NET program";
            }
            if (notes.stream().anyMatch(n -> n.startsWith("UPX") || n.startsWith("Themida") || n.startsWith("VMProtect") || n.startsWith("Enigma") || n.startsWith("MPRESS") || n.startsWith("ASPack"))) {
                sc.addFinding("", "PACKED_BINARY", Severity.MEDIUM, "Packing", "Packed / protected program",
                        "The program is compressed or protected with " + String.join(", ", notes) + ". The real code is only unpacked at runtime, so static scans see very little. Very common for malware.", null);
            }
        } catch (IndexOutOfBoundsException | java.nio.BufferUnderflowException e) {
            notes.add("Malformed PE header");
        }
    }

    private static void addOnce(List<String> l, String s) {
        if (!l.contains(s)) l.add(s);
    }

    private static int rvaToOff(List<int[]> secs, int rva) {
        if (rva <= 0) return -1;
        for (int[] s : secs) if (rva >= s[0] && rva < s[0] + s[1]) {
            long off = (long) s[2] + (rva - s[0]);
            return off >= 0 && off < Integer.MAX_VALUE ? (int) off : -1;
        }
        return -1;
    }

    private static String cstr(byte[] d, int off) {
        if (off < 0 || off >= d.length) return null;
        int e = off;
        while (e < d.length && d[e] != 0 && e - off < 256) e++;
        String s = new String(d, off, e - off, StandardCharsets.US_ASCII);
        return s.isEmpty() || !s.matches("[\\x20-\\x7e]+") ? null : s;
    }

    static int indexOf(byte[] d, byte[] p, int from) {
        outer:
        for (int i = Math.max(0, from); i <= d.length - p.length; i++) {
            for (int k = 0; k < p.length; k++) if (d[i + k] != p[k]) continue outer;
            return i;
        }
        return -1;
    }

    static List<String> extractStrings(byte[] d) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte value : d) {
            int c = value & 0xff;
            if (c >= 0x20 && c < 0x7f) sb.append((char) c);
            else {
                if (sb.length() >= 6) out.add(sb.toString());
                sb.setLength(0);
            }
        }
        if (sb.length() >= 6) out.add(sb.toString());
        sb.setLength(0);
        for (int i = 0; i + 1 < d.length; i += 2) {
            int c = (d[i] & 0xff) | ((d[i + 1] & 0xff) << 8);
            if (c >= 0x20 && c < 0x7f) sb.append((char) c);
            else {
                if (sb.length() >= 6) out.add(sb.toString());
                sb.setLength(0);
            }
        }
        if (sb.length() >= 6) out.add(sb.toString());
        return out;
    }
}
