"use strict";
const RatEngine = (() => {
  const SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const WEIGHT = { CRITICAL: 40, HIGH: 18, MEDIUM: 7, LOW: 2, INFO: 0 };
  const lower = s => SEV[Math.min(4, SEV.indexOf(s) + 1)];
  const atLeast = (a, b) => SEV.indexOf(a) <= SEV.indexOf(b);
  const LIMITS = { entries: 400000, entry: 256 << 20, total: 6144 * 1048576, classBytes: 512 << 20, depth: 3, deepStrings: 250000 };
  const td = new TextDecoder("utf-8");
  const latin = new TextDecoder("latin1");
  let R = null, STR = null;

  function init(rules) {
    R = rules;
    STR = rules.strings.map(s => ({ ...s, rx: new RegExp(s.re, s.ci ? "i" : "") }));
  }

  /* ---------------- helpers ---------------- */
  const clip = s => s.length > 220 ? s.slice(0, 217) + "…" : s;
  function printableRatio(s) {
    if (!s.length) return 0;
    let ok = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if ((c >= 0x20 && c < 0x7f) || c === 10 || c === 13 || c === 9 || (c >= 0xa0 && c < 0x2000)) ok++;
    }
    return ok / s.length;
  }
  function entropy(u8) {
    const f = new Uint32Array(256), n = Math.min(u8.length, 1 << 20);
    for (let i = 0; i < n; i++) f[u8[i]]++;
    let e = 0;
    for (const c of f) if (c) { const p = c / n; e -= p * Math.log2(p); }
    return e;
  }
  const isLibrary = name => R.libraries.some(p => name.startsWith(p));
  const B64 = /^[A-Za-z0-9+/_-]{12,}={0,2}$/, HEX = /^(?:[0-9a-fA-F]{2}){8,}$/;
  function b64decode(s) {
    let t = s.replace(/-/g, "+").replace(/_/g, "/");
    if (!t.includes("=")) { const pad = (4 - t.length % 4) % 4; if (pad !== 3) t += "=".repeat(pad); }
    const bin = atob(t);
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return td.decode(u);
  }

  /* ---------------- model ---------------- */
  function newClass(container, name, top, library, hidden, entryPath) {
    return { container, name, top, library, hidden, entryPath, tags: new Map(), findings: new Map(), customIndy: 0, decryptors: 0, encryptedStrings: 0, broken: false, entrypoint: false, modAnnotation: false };
  }
  const tag = (ci, t, ev) => { if (!ci.tags.has(t)) ci.tags.set(t, ev); };
  function finding(rule, severity, category, title, description) { return { rule, severity, category, title, description, occurrences: 1 }; }
  function at(f, container, cls, ev, source) {
    f.container = container; f.cls = cls; f.source = source;
    if (ev) { f.method = ev.method; f.line = ev.line; f.evidence = ev.text; f.needle = ev.needle; }
    return f;
  }
  function add(ci, f) {
    const p = ci.findings.get(f.rule);
    if (p) { p.occurrences++; return; }
    f.library = ci.library; f.entrypoint = ci.entrypoint;
    ci.findings.set(f.rule, f);
  }
  const ev = (method, line, text, needle) => ({ method, line, text, needle });

  /* ---------------- call tagging (port of Rules.callTags) ---------------- */
  function callTags(owner, name, out) {
    const N = n => name === n, any = (...a) => a.includes(name);
    switch (owner) {
      case "java/lang/Runtime": if (N("exec")) out.push("EXEC"); if (any("load", "loadLibrary")) out.push("NATIVE"); break;
      case "java/lang/ProcessBuilder": if (any("<init>", "start", "command", "startPipeline")) out.push("EXEC"); break;
      case "java/lang/System": if (any("load", "loadLibrary")) out.push("NATIVE"); if (N("getenv")) out.push("ENV"); break;
      case "java/net/URL": if (any("openConnection", "openStream", "getContent")) out.push("NET"); break;
      case "java/net/HttpURLConnection": case "javax/net/ssl/HttpsURLConnection": case "java/net/URLConnection": case "java/net/http/HttpClient":
      case "java/net/http/HttpClient$Builder": case "okhttp3/OkHttpClient": case "okhttp3/Call": case "java/net/http/WebSocket$Builder":
      case "org/apache/http/impl/client/CloseableHttpClient": case "org/apache/http/client/HttpClient": case "org/apache/hc/client5/http/impl/classic/CloseableHttpClient":
      case "org/java_websocket/client/WebSocketClient": if (!N("<clinit>")) out.push("NET"); break;
      case "java/net/Socket": case "java/net/DatagramSocket": case "javax/net/SocketFactory": case "javax/net/ssl/SSLSocketFactory": if (any("<init>", "connect", "createSocket")) out.push("SOCKET"); break;
      case "java/nio/channels/SocketChannel": case "java/nio/channels/AsynchronousSocketChannel": if (any("open", "connect")) out.push("SOCKET"); break;
      case "java/net/ServerSocket": case "java/nio/channels/ServerSocketChannel": if (any("<init>", "open", "bind")) out.push("SERVER_SOCKET"); break;
      case "com/sun/net/httpserver/HttpServer": if (N("create")) out.push("SERVER_SOCKET"); break;
      case "java/io/FileOutputStream": case "java/io/FileWriter": if (N("<init>")) out.push("FILE_WRITE"); break;
      case "java/nio/file/Files":
        if (any("write", "writeString", "copy", "newOutputStream", "newBufferedWriter", "move", "createFile")) out.push("FILE_WRITE");
        else if (any("readAllBytes", "readString", "readAllLines", "newInputStream", "newBufferedReader", "lines")) out.push("FILE_READ");
        else if (any("walk", "list", "find", "walkFileTree", "newDirectoryStream")) out.push("FILE_WALK");
        else if (any("delete", "deleteIfExists")) out.push("FILE_DELETE");
        break;
      case "java/io/File": if (any("listFiles", "list")) out.push("FILE_WALK"); if (any("delete", "deleteOnExit")) out.push("FILE_DELETE"); break;
      case "java/io/FileInputStream": case "java/io/FileReader": case "java/io/RandomAccessFile": if (N("<init>")) out.push("FILE_READ"); break;
      case "org/apache/commons/io/FileUtils":
        if (name.startsWith("copyURLToFile")) out.push("NET", "FILE_WRITE");
        else if (name.startsWith("write") || name.startsWith("copy")) out.push("FILE_WRITE");
        else if (name.startsWith("read")) out.push("FILE_READ");
        break;
      case "java/net/URLClassLoader": if (any("<init>", "newInstance")) out.push("CLASSLOAD"); break;
      case "java/lang/invoke/MethodHandles$Lookup": if (any("defineClass", "defineHiddenClass", "defineHiddenClassWithClassData")) out.push("DEFINE_CLASS"); break;
      case "sun/misc/Unsafe": case "jdk/internal/misc/Unsafe": out.push("UNSAFE"); if (any("defineClass", "defineAnonymousClass")) out.push("DEFINE_CLASS"); break;
      case "java/lang/reflect/Method": if (N("invoke")) out.push("REFLECT"); break;
      case "java/lang/Class": if (any("forName", "getDeclaredMethod", "getMethod")) out.push("REFLECT"); break;
      case "java/util/Base64$Decoder": case "javax/xml/bind/DatatypeConverter": case "org/apache/commons/codec/binary/Base64": case "sun/misc/BASE64Decoder":
        if (name.startsWith("decode") || any("parseBase64Binary", "decodeBuffer")) out.push("B64"); break;
      case "javax/crypto/Cipher": if (any("getInstance", "doFinal")) out.push("CRYPTO"); break;
      case "java/awt/Robot": if (any("createScreenCapture", "createMultiResolutionScreenCapture")) out.push("SCREEN"); break;
      case "java/awt/Toolkit": if (N("getSystemClipboard")) out.push("CLIPBOARD_READ"); break;
      case "java/awt/datatransfer/Clipboard": if (N("setContents")) out.push("CLIPBOARD_WRITE"); if (any("getContents", "getData")) out.push("CLIPBOARD_READ"); break;
      case "org/lwjgl/glfw/GLFW": if (N("glfwSetClipboardString")) out.push("CLIPBOARD_WRITE"); if (N("glfwGetClipboardString")) out.push("CLIPBOARD_READ"); break;
      case "java/util/zip/ZipOutputStream": case "java/util/jar/JarOutputStream": if (N("<init>")) out.push("ZIP_WRITE"); break;
      case "java/util/jar/JarFile": case "java/util/zip/ZipFile": case "java/util/jar/JarInputStream": case "java/util/zip/ZipInputStream": if (N("<init>")) out.push("JAR_READ"); break;
      case "java/nio/file/FileSystems": if (N("newFileSystem")) out.push("JAR_READ"); break;
      case "java/security/ProtectionDomain": case "java/security/CodeSource": if (any("getCodeSource", "getLocation")) out.push("CODESOURCE"); break;
      case "java/net/NetworkInterface": if (N("getHardwareAddress")) out.push("SYSINFO"); break;
      case "java/net/InetAddress": if (N("getLocalHost")) out.push("SYSINFO"); break;
      case "com/sun/tools/attach/VirtualMachine": if (any("attach", "loadAgent")) out.push("ATTACH"); break;
      case "java/lang/instrument/Instrumentation": if (any("redefineClasses", "retransformClasses", "addTransformer")) out.push("INSTRUMENT"); break;
      case "java/awt/Desktop": if (any("browse", "open")) out.push("DESKTOP"); break;
      case "com/sun/jna/platform/win32/Crypt32Util": case "com/sun/jna/platform/win32/Crypt32": if (name.toLowerCase().includes("unprotect")) out.push("DPAPI"); out.push("NATIVE"); break;
      case "com/sun/jna/Native": if (any("load", "loadLibrary", "register")) out.push("NATIVE"); break;
      case "org/bukkit/Bukkit": case "org/bukkit/Server": case "net/md_5/bungee/api/plugin/PluginManager": case "com/velocitypowered/api/command/CommandManager":
        if (any("dispatchCommand", "executeAsync", "executeImmediatelyAsync")) out.push("BUKKIT_DISPATCH"); break;
      case "org/bukkit/event/player/AsyncPlayerChatEvent": case "org/bukkit/event/player/PlayerChatEvent": case "org/bukkit/event/player/PlayerCommandPreprocessEvent":
      case "io/papermc/paper/event/player/AsyncChatEvent": case "net/md_5/bungee/api/event/ChatEvent": case "com/velocitypowered/api/event/player/PlayerChatEvent":
        if (any("getMessage", "message", "signedMessage", "originalMessage")) out.push("BUKKIT_CHAT_EVENT"); break;
      case "net/milkbowl/vault/economy/Economy": if (any("depositPlayer", "withdrawPlayer", "bankDeposit")) out.push("BUKKIT_ECONOMY"); break;
      case "javax/sound/sampled/AudioSystem": if (any("getTargetDataLine")) out.push("MIC"); break;
      case "javax/sound/sampled/TargetDataLine": if (any("open", "start", "read")) out.push("MIC"); break;
      case "org/lwjgl/openal/ALC11": case "org/lwjgl/openal/ALC10": if (any("alcCaptureOpenDevice", "alcCaptureStart")) out.push("MIC"); break;
      case "javax/script/ScriptEngine": case "javax/script/Compilable": if (any("eval", "compile")) out.push("SCRIPT_EVAL"); break;
      case "groovy/lang/GroovyShell": if (any("evaluate", "parse", "run")) out.push("SCRIPT_EVAL"); break;
      case "org/mozilla/javascript/Context": if (any("evaluateString", "compileString", "evaluateReader")) out.push("SCRIPT_EVAL"); break;
      case "bsh/Interpreter": if (any("eval", "source")) out.push("SCRIPT_EVAL"); break;
      case "java/rmi/registry/LocateRegistry": if (N("createRegistry")) out.push("SERVER_SOCKET"); break;
      case "javax/management/remote/JMXConnectorServerFactory": if (N("newJMXConnectorServer")) out.push("SERVER_SOCKET"); break;
      case "org/apache/logging/log4j/core/Logger": case "org/apache/logging/log4j/core/config/LoggerConfig": case "org/apache/logging/log4j/core/Appender": if (N("addFilter")) out.push("LOG_FILTER"); break;
      case "java/util/logging/Logger": case "java/util/logging/Handler": if (N("setFilter")) out.push("LOG_FILTER"); break;
      case "org/bukkit/plugin/PluginManager": case "org/bukkit/plugin/PluginLoader": if (any("loadPlugin", "enablePlugin")) out.push("PLUGIN_LOAD"); break;
      case "com/sun/jna/platform/win32/Advapi32Util": if (name.startsWith("registrySet") || name.startsWith("registryCreate")) out.push("REG_WRITE"); out.push("NATIVE"); break;
    }
    if (owner === "java/awt/Robot" && any("mouseMove", "mousePress", "mouseRelease", "keyPress", "keyRelease", "mouseWheel")) out.push("ROBOT_INPUT");
    if (owner.startsWith("com/github/sarxos/webcam/") || /^org\/bytedeco\/javacv\/.*FrameGrabber$/.test(owner) || owner === "org/opencv/videoio/VideoCapture") out.push("WEBCAM");
    if (N("defineClass") && !owner.startsWith("java/lang/invoke")) out.push("DEFINE_CLASS");
    if (N("setOp") && (owner.startsWith("org/bukkit/") || owner.includes("bukkit"))) out.push("BUKKIT_OP");
    if (N("addAttachment") && owner.startsWith("org/bukkit/")) out.push("BUKKIT_PERM");
    if (any("chat", "performCommand") && owner.startsWith("org/bukkit/entity/")) out.push("MC_CHAT_SEND");
    if (owner.startsWith("com/github/kwhat/jnativehook") || owner.startsWith("org/jnativehook")) out.push("KEYHOOK");
    if (owner.startsWith("oshi/hardware") || owner === "oshi/SystemInfo") out.push("SYSINFO");
    if (owner.startsWith("net/minecraft/") || owner.startsWith("com/mojang/")) {
      const sessionOwner = owner.includes("class_320") || owner.endsWith("/Session") || owner === "net/minecraft/client/User" || owner.endsWith("/session/Session");
      if (sessionOwner) out.push("MC_SESSION");
      if (any("getAccessToken", "method_1674", "func_148254_d", "getSessionID", "func_111286_b", "method_1675", "func_148255_b", "getSessionId")) {
        if (sessionOwner || owner.startsWith("com/mojang/authlib")) out.push("MC_TOKEN");
      } else if (any("getSession", "method_1548", "func_110432_I", "getUser", "m_91094_")) {
        if (owner.includes("class_310") || owner.endsWith("MinecraftClient") || owner === "net/minecraft/client/Minecraft") out.push("MC_SESSION");
      } else if (any("sendChatCommand", "sendCommand", "sendChatMessage", "sendUnsignedCommand", "sendChat", "method_45730", "method_45731", "method_45729", "method_44096", "func_71165_d", "m_246175_", "m_246623_", "m_234156_", "chat", "commandUnsigned", "commandSigned")) {
        if (!N("chat") || owner.includes("Player")) out.push("MC_CHAT_SEND");
      }
    }
  }
  function fieldTags(owner, name, out) {
    if (owner.startsWith("net/minecraft/") && (owner.includes("class_320") || owner.endsWith("/Session") || owner === "net/minecraft/client/User")) {
      out.push("MC_SESSION");
      const n = name.toLowerCase();
      if (n.includes("token") || ["field_1985", "field_148258_c", "f_92536_"].includes(n) || n.includes("sessionid")) out.push("MC_TOKEN");
    }
  }
  function typeTags(type, out) {
    if (/(ChatCommandC2SPacket|ChatMessageC2SPacket|ServerboundChatCommandPacket|ServerboundChatPacket|CPacketChatMessage|C01PacketChatMessage|CommandExecutionC2SPacket|class_7472|class_7640|class_2797)$/.test(type)) out.push("MC_CHAT_SEND");
    if (type === "java/net/URLClassLoader") out.push("CLASSLOAD");
  }

  /* ---------------- string processing (port of Analyzer.processString) ---------------- */
  const PLAIN = new Set(["ldc", "source", "resource", "indy"]);
  const ORIGIN = { base64: "Base64-encoded", hex: "hex-encoded", reversed: "written backwards", bytearray: "built from a byte array", raw: "from a corrupted class", decrypted: "encrypted, decrypted by emulation" };
  function processString(ci, s, e, origin, depth) {
    if (!s) return;
    if (s.length > 8192) s = s.slice(0, 8192);
    const trimmed = s.trim(), low = trimmed.toLowerCase();
    const shown = ev(e.method, e.line, clip(PLAIN.has(origin) ? trimmed : "[" + origin + "] " + trimmed), e.needle == null ? null : clip(e.needle));
    for (const r of STR) {
      if (!r.rx.test(trimmed)) continue;
      if (origin === "reversed" && r.sev == null) continue;
      tag(ci, r.tag, shown);
      if (r.sev != null) {
        let sev = r.sev, title = r.title;
        if (!PLAIN.has(origin)) {
          title = title + " (hidden: " + (ORIGIN[origin] || origin) + ")";
          if (SEV.indexOf(sev) > 1 && origin !== "raw") sev = SEV[SEV.indexOf(sev) - 1];
        }
        add(ci, at(finding("STR_" + r.id + (title === r.title ? "" : "_" + origin.toUpperCase()), sev, r.cat, title, r.desc), ci.container, ci.name, shown, origin === "source" ? "decompiler" : "asm"));
      }
    }
    familyCheck(ci, low, shown, null);
    if (depth > 1) return;
    if (trimmed.length >= 12 && B64.test(trimmed) && !/^[a-z]+$/.test(trimmed) && !/^[A-Z_]+$/.test(trimmed)) {
      try {
        const d = b64decode(trimmed);
        if (d.length >= 4 && printableRatio(d) > 0.92) { tag(ci, "S_B64STR", shown); processString(ci, d, e, "base64", depth + 1); }
      } catch (x) {}
    }
    if (HEX.test(trimmed)) {
      const u = new Uint8Array(trimmed.length / 2);
      for (let i = 0; i < u.length; i++) u[i] = parseInt(trimmed.substr(i * 2, 2), 16);
      const d = td.decode(u);
      if (printableRatio(d) > 0.95) processString(ci, d, e, "hex", depth + 1);
    }
    if (depth === 0 && trimmed.length >= 10 && (trimmed.includes("/") || trimmed.includes("."))) processString(ci, [...trimmed].reverse().join(""), e, "reversed", 2);
  }
  function familyCheck(ci, low, shown, prefixLabel) {
    for (const fam of R.families) for (const ioc of fam.strings) {
      if (low.includes(ioc)) {
        tag(ci, "S_EXFIL", shown);
        add(ci, at(finding("FAMILY_" + fam.name.toUpperCase(), fam.sev, "Known malware", "Known malware: " + fam.name, fam.desc + " (indicator: " + ioc + ")"), ci.container, ci.name, prefixLabel ? ev(shown.method, shown.line, prefixLabel + ioc, null) : shown, "asm"));
      }
    }
  }
  const JOIN_TAGS = new Set(["S_EXFIL", "S_REMOTE", "S_IPGRAB", "S_STEAL", "S_MINER", "S_EVASION", "S_PERSIST", "S_SHELL"]);
  function joinWithPrevious(ci, prev, s, method, line) {
    if (prev.v == null || prev.v.length + s.length > 600) return;
    const joined = prev.v + s, jl = joined.toLowerCase(), pl = prev.v.toLowerCase(), sl = s.toLowerCase();
    const e = ev(method, line, joined, s);
    for (const fam of R.families) for (const ioc of fam.strings) {
      if (jl.includes(ioc) && !pl.includes(ioc) && !sl.includes(ioc)) {
        tag(ci, "S_EXFIL", e);
        add(ci, at(finding("FAMILY_" + fam.name.toUpperCase(), fam.sev, "Known malware", "Known malware: " + fam.name, fam.desc + " (indicator: " + ioc + ")"), ci.container, ci.name, ev(method, line, "[joined] " + clip(joined), clip(s)), "asm"));
      }
    }
    for (const r of STR) {
      if (r.sev == null || !JOIN_TAGS.has(r.tag)) continue;
      if (!r.rx.test(joined) || r.rx.test(prev.v) || r.rx.test(s)) continue;
      tag(ci, r.tag, e);
      add(ci, at(finding("STR_" + r.id + "_JOINED", r.sev, r.cat, r.title + " (hidden: split into pieces)", r.desc + " The string is assembled from several pieces at runtime so simple scanners miss it."), ci.container, ci.name, ev(method, line, "[joined] " + clip(joined), clip(s)), "asm"));
    }
  }
  function scanConcatenation(ci, all, method, line) {
    if (all.length < 8) return;
    familyCheck(ci, all.toLowerCase(), ev(method, line, "", null), "[decrypted] ");
    for (const r of STR) {
      if (r.sev == null || !JOIN_TAGS.has(r.tag) || ci.findings.has("STR_" + r.id + "_DECRYPTED") || ci.findings.has("STR_" + r.id + "_JOINED")) continue;
      const m = r.rx.exec(all);
      if (!m) continue;
      const hit = all.slice(Math.max(0, m.index - 20), Math.min(all.length, m.index + m[0].length + 40));
      tag(ci, r.tag, ev(method, line, hit, null));
      add(ci, at(finding("STR_" + r.id + "_JOINED", r.sev, r.cat, r.title + " (hidden: encrypted + split)", r.desc + " The string is encrypted and only assembled from pieces at runtime."), ci.container, ci.name, ev(method, line, "[decrypted] " + clip(hit), null), "asm"));
    }
  }

  /* ---------------- class file parsing ---------------- */
  const OPLEN = new Int8Array(256);
  [[0x10, 1], [0x11, 2], [0x12, 1], [0x13, 2], [0x14, 2], [0x15, 1], [0x16, 1], [0x17, 1], [0x18, 1], [0x19, 1], [0x36, 1], [0x37, 1], [0x38, 1], [0x39, 1], [0x3a, 1], [0x84, 2], [0xa9, 1],
   [0xb2, 2], [0xb3, 2], [0xb4, 2], [0xb5, 2], [0xb6, 2], [0xb7, 2], [0xb8, 2], [0xb9, 4], [0xba, 4], [0xbb, 2], [0xbc, 1], [0xbd, 2], [0xc0, 2], [0xc1, 2], [0xc5, 3], [0xc6, 2], [0xc7, 2], [0xc8, 4], [0xc9, 4]].forEach(([o, l]) => OPLEN[o] = l);
  for (let o = 0x99; o <= 0xa8; o++) OPLEN[o] = 2;
  const OPNAMES = ("nop aconst_null iconst_m1 iconst_0 iconst_1 iconst_2 iconst_3 iconst_4 iconst_5 lconst_0 lconst_1 fconst_0 fconst_1 fconst_2 dconst_0 dconst_1 bipush sipush ldc ldc_w ldc2_w iload lload fload dload aload iload_0 iload_1 iload_2 iload_3 lload_0 lload_1 lload_2 lload_3 fload_0 fload_1 fload_2 fload_3 dload_0 dload_1 dload_2 dload_3 aload_0 aload_1 aload_2 aload_3 iaload laload faload daload aaload baload caload saload istore lstore fstore dstore astore istore_0 istore_1 istore_2 istore_3 lstore_0 lstore_1 lstore_2 lstore_3 fstore_0 fstore_1 fstore_2 fstore_3 dstore_0 dstore_1 dstore_2 dstore_3 astore_0 astore_1 astore_2 astore_3 iastore lastore fastore dastore aastore bastore castore sastore pop pop2 dup dup_x1 dup_x2 dup2 dup2_x1 dup2_x2 swap iadd ladd fadd dadd isub lsub fsub dsub imul lmul fmul dmul idiv ldiv fdiv ddiv irem lrem frem drem ineg lneg fneg dneg ishl lshl ishr lshr iushr lushr iand land ior lor ixor lxor iinc i2l i2f i2d l2i l2f l2d f2i f2l f2d d2i d2l d2f i2b i2c i2s lcmp fcmpl fcmpg dcmpl dcmpg ifeq ifne iflt ifge ifgt ifle if_icmpeq if_icmpne if_icmplt if_icmpge if_icmpgt if_icmple if_acmpeq if_acmpne goto jsr ret tableswitch lookupswitch ireturn lreturn freturn dreturn areturn return getstatic putstatic getfield putfield invokevirtual invokespecial invokestatic invokeinterface invokedynamic new newarray anewarray arraylength athrow checkcast instanceof monitorenter monitorexit wide multianewarray ifnull ifnonnull goto_w jsr_w").split(" ");

  function parseClass(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (dv.getUint32(0) !== 0xCAFEBABE) throw new Error("bad magic");
    let p = 8;
    const n = dv.getUint16(p); p += 2;
    const cp = new Array(n);
    for (let i = 1; i < n; i++) {
      const t = b[p++];
      switch (t) {
        case 1: { const l = dv.getUint16(p); cp[i] = { t, v: mutf8(b, p + 2, l) }; p += 2 + l; break; }
        case 3: cp[i] = { t, v: dv.getInt32(p) }; p += 4; break;
        case 4: cp[i] = { t, v: dv.getFloat32(p) }; p += 4; break;
        case 5: cp[i] = { t, v: dv.getBigInt64(p) }; p += 8; i++; break;
        case 6: cp[i] = { t, v: dv.getFloat64(p) }; p += 8; i++; break;
        case 7: case 8: case 16: case 19: case 20: cp[i] = { t, a: dv.getUint16(p) }; p += 2; break;
        case 9: case 10: case 11: case 12: case 17: case 18: cp[i] = { t, a: dv.getUint16(p), b: dv.getUint16(p + 2) }; p += 4; break;
        case 15: cp[i] = { t, k: b[p], a: dv.getUint16(p + 1) }; p += 3; break;
        default: throw new Error("bad constant tag " + t);
      }
    }
    const utf = i => (cp[i] && cp[i].t === 1 ? cp[i].v : "");
    const cls = i => (cp[i] ? utf(cp[i].a) : "");
    const cpEnd = p;
    p += 2;
    const name = cls(dv.getUint16(p)); p += 2;
    const superName = cls(dv.getUint16(p)); p += 2;
    const ic = dv.getUint16(p); p += 2 + ic * 2;
    const attrs = () => { const c = dv.getUint16(p); p += 2; const out = []; for (let k = 0; k < c; k++) { const nm = utf(dv.getUint16(p)), len = dv.getUint32(p + 2); out.push({ nm, off: p + 6, len }); p += 6 + len; } return out; };
    const fields = [];
    const fc = dv.getUint16(p); p += 2;
    for (let k = 0; k < fc; k++) {
      const faccess = dv.getUint16(p), fname = utf(dv.getUint16(p + 2)), fdesc = utf(dv.getUint16(p + 4)); p += 6;
      const cv = attrs().find(a => a.nm === "ConstantValue");
      let value = null, cval;
      if (cv) { const c = cp[dv.getUint16(cv.off)]; if (c && c.t === 8) value = utf(c.a); else if (c) cval = c.v; }
      fields.push({ name: fname, value, desc: fdesc, access: faccess, cval });
    }
    const methods = [];
    const mc = dv.getUint16(p); p += 2;
    for (let k = 0; k < mc; k++) {
      const access = dv.getUint16(p), mname = utf(dv.getUint16(p + 2)), desc = utf(dv.getUint16(p + 4)); p += 6;
      const code = attrs().find(a => a.nm === "Code");
      let codeOff = 0, codeLen = 0, lines = null, maxLocals = 0;
      const handlers = [];
      if (code) {
        maxLocals = dv.getUint16(code.off + 2);
        codeLen = dv.getUint32(code.off + 4); codeOff = code.off + 8;
        let q = codeOff + codeLen;
        const exLen = dv.getUint16(q);
        for (let z = 0; z < exLen; z++) handlers.push({ start: dv.getUint16(q + 2 + z * 8), end: dv.getUint16(q + 4 + z * 8), handler: dv.getUint16(q + 6 + z * 8) });
        q += 2 + exLen * 8;
        const ac = dv.getUint16(q); q += 2;
        for (let z = 0; z < ac; z++) {
          const nm = utf(dv.getUint16(q)), len = dv.getUint32(q + 2);
          if (nm === "LineNumberTable") { lines = []; const c = dv.getUint16(q + 6); for (let y = 0; y < c; y++) lines.push([dv.getUint16(q + 8 + y * 4), dv.getUint16(q + 10 + y * 4)]); }
          q += 6 + len;
        }
      }
      methods.push({ access, name: mname, desc, codeOff, codeLen, lines, maxLocals, handlers });
    }
    const ca = attrs();
    const bsms = [];
    const bm = ca.find(a => a.nm === "BootstrapMethods");
    if (bm) {
      let q = bm.off; const c = dv.getUint16(q); q += 2;
      for (let k = 0; k < c; k++) {
        const ref = dv.getUint16(q), na = dv.getUint16(q + 2); q += 4;
        const args = [];
        for (let z = 0; z < na; z++) { const ai = dv.getUint16(q); q += 2; if (cp[ai] && cp[ai].t === 8) args.push(utf(cp[ai].a)); }
        let owner = "";
        const mh = cp[ref];
        if (mh && mh.t === 15) { const mr = cp[mh.a]; if (mr) owner = cls(mr.a); }
        bsms.push({ owner, args });
      }
    }
    const modAnnotation = cp.some(c => c && c.t === 1 && (c.v === "Lnet/minecraftforge/fml/common/Mod;" || c.v === "Lnet/neoforged/fml/common/Mod;"));
    return { name, superName, cp, utf, cls, fields, methods, bsms, dv, b, modAnnotation, cpEnd, cpCount: n };
  }
  function mutf8(b, off, len) {
    let s = "", i = off;
    const end = off + len;
    while (i < end) {
      const c = b[i++];
      if (c < 0x80) s += String.fromCharCode(c);
      else if ((c & 0xe0) === 0xc0) s += String.fromCharCode(((c & 0x1f) << 6) | (b[i++] & 0x3f));
      else { s += String.fromCharCode(((c & 0x0f) << 12) | ((b[i] & 0x3f) << 6) | (b[i + 1] & 0x3f)); i += 2; }
    }
    return s;
  }
  function decode(C, m) {
    const { b, dv } = C;
    const out = [];
    let i = 0;
    const lineAt = new Map();
    if (m.lines) for (const [pc, ln] of m.lines) lineAt.set(pc, ln);
    let line = 0;
    while (i < m.codeLen) {
      const pc = i, at0 = m.codeOff + i, op = b[at0];
      if (lineAt.has(pc)) line = lineAt.get(pc);
      const ins = { op, pc, line };
      if (op === 0xaa) { const q = (i + 4) & ~3; const lo = dv.getInt32(m.codeOff + q + 4), hi = dv.getInt32(m.codeOff + q + 8); i = q + 12 + (hi - lo + 1) * 4; out.push(ins); continue; }
      if (op === 0xab) { const q = (i + 4) & ~3; const np = dv.getInt32(m.codeOff + q + 4); i = q + 8 + np * 8; out.push(ins); continue; }
      if (op === 0xc4) { const w = b[at0 + 1]; ins.op = w; ins.v = dv.getUint16(at0 + 2); ins.wide = true; i += w === 0x84 ? 6 : 4; out.push(ins); continue; }
      const l = OPLEN[op];
      if (l === 1) ins.v = op === 0x10 ? dv.getInt8(at0 + 1) : b[at0 + 1];
      else if (l >= 2) ins.v = op === 0x11 ? dv.getInt16(at0 + 1) : dv.getUint16(at0 + 1);
      if (op === 0x84) { ins.v = b[at0 + 1]; ins.inc = dv.getInt8(at0 + 2); }
      if (op === 0x99 + 0 || (op >= 0x99 && op <= 0xa8) || op === 0xc6 || op === 0xc7) ins.v = dv.getInt16(at0 + 1);
      i += 1 + l;
      out.push(ins);
    }
    return out;
  }
  const memberRef = (C, idx) => { const r = C.cp[idx]; if (!r) return null; const nt = C.cp[r.b]; return { owner: C.cls(r.a), name: C.utf(nt.a), desc: C.utf(nt.b) }; };
  function constInt(C, ins) {
    const op = ins.op;
    if (op >= 0x02 && op <= 0x08) return op - 0x03;
    if (op === 0x10 || op === 0x11) return ins.v;
    if (op === 0x12 || op === 0x13) { const c = C.cp[ins.v]; if (c && c.t === 3) return c.v; }
    return undefined;
  }
  function ldcString(C, ins) {
    if (ins.op !== 0x12 && ins.op !== 0x13) return null;
    const c = C.cp[ins.v];
    return c && c.t === 8 ? C.utf(c.a) : null;
  }

  /* ---------------- string emulator (port of StringEmulator) ---------------- */
  const UNKNOWN = Symbol("u");
  function emulate(C, insns) {
    const out = [], stack = [], locals = new Map();
    let sb = "", line = 0;
    const pop = () => stack.length ? stack.pop() : UNKNOWN;
    const emit = (s, ln) => { if (s.length >= 2 && printableRatio(s) > 0.85) out.push({ value: s, line: ln }); };
    const flush = () => { if (sb.length >= 2) emit(sb, line); sb = ""; };
    const arrValue = a => a.chars ? String.fromCharCode(...a.data.map(x => x & 0xffff)) : td.decode(Uint8Array.from(a.data, x => x & 0xff));
    for (const ins of insns) {
      line = ins.line || line;
      const k = constInt(C, ins);
      if (k !== undefined) { stack.push(k); continue; }
      const op = ins.op;
      switch (op) {
        case 0x60: case 0x64: case 0x68: case 0x6c: case 0x70: case 0x78: case 0x7a: case 0x7c: case 0x7e: case 0x80: case 0x82: {
          const y = pop(), x = pop();
          if (typeof x === "number" && typeof y === "number") {
            let r;
            switch (op) {
              case 0x60: r = (x + y) | 0; break; case 0x64: r = (x - y) | 0; break; case 0x68: r = Math.imul(x, y); break;
              case 0x6c: r = y === 0 ? UNKNOWN : (x / y) | 0; break; case 0x70: r = y === 0 ? UNKNOWN : x % y; break;
              case 0x78: r = x << y; break; case 0x7a: r = x >> y; break; case 0x7c: r = (x >>> y) | 0; break;
              case 0x7e: r = x & y; break; case 0x80: r = x | y; break; case 0x82: r = x ^ y; break;
            }
            stack.push(r);
          } else stack.push(UNKNOWN);
          break;
        }
        case 0x74: { const x = pop(); stack.push(typeof x === "number" ? (-x) | 0 : UNKNOWN); break; }
        case 0x92: { const x = pop(); stack.push(typeof x === "number" ? x & 0xffff : UNKNOWN); break; }
        case 0x91: { const x = pop(); stack.push(typeof x === "number" ? (x << 24) >> 24 : UNKNOWN); break; }
        case 0x93: { const x = pop(); stack.push(typeof x === "number" ? (x << 16) >> 16 : UNKNOWN); break; }
        case 0xbc: { const s = pop(); stack.push(typeof s === "number" && s > 0 && s <= 8192 && (ins.v === 5 || ins.v === 8) ? { arr: true, chars: ins.v === 5, data: new Array(s).fill(0), stores: 0 } : UNKNOWN); break; }
        case 0x59: stack.push(stack.length ? stack[stack.length - 1] : UNKNOWN); break;
        case 0x55: case 0x54: { const v = pop(), ix = pop(), a = pop(); if (a && a.arr && typeof ix === "number" && typeof v === "number" && ix >= 0 && ix < a.data.length) { a.data[ix] = v; a.stores++; } break; }
        case 0x3a: case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x36: case 0x3b: case 0x3c: case 0x3d: case 0x3e: {
          const idx = op === 0x3a || op === 0x36 ? ins.v : op >= 0x4b ? op - 0x4b : op - 0x3b; locals.set(idx, pop()); break;
        }
        case 0x19: case 0x2a: case 0x2b: case 0x2c: case 0x2d: { const idx = op === 0x19 ? ins.v : op - 0x2a; const v = locals.get(idx); stack.push(v && v.arr ? v : UNKNOWN); break; }
        case 0x15: case 0x1a: case 0x1b: case 0x1c: case 0x1d: { const idx = op === 0x15 ? ins.v : op - 0x1a; const v = locals.get(idx); stack.push(typeof v === "number" ? v : UNKNOWN); break; }
        case 0x57: pop(); break;
        case 0xbb: { if (C.cls(ins.v) === "java/lang/StringBuilder") flush(); stack.push(UNKNOWN); break; }
        case 0xb6: case 0xb7: case 0xb8: {
          const r = memberRef(C, ins.v);
          if (r && r.owner === "java/lang/StringBuilder" && r.name === "append" && r.desc === "(C)Ljava/lang/StringBuilder;") {
            const v = pop(); pop();
            if (typeof v === "number") sb += String.fromCharCode(v & 0xffff); else flush();
            stack.push(UNKNOWN);
          } else if (r && r.owner === "java/lang/StringBuilder" && r.name === "toString") { flush(); stack.length = 0; stack.push(UNKNOWN); }
          else if (r && r.owner === "java/lang/String" && r.name === "<init>" && (r.desc.startsWith("([C") || r.desc.startsWith("([B"))) {
            const a = pop(); if (a && a.arr && a.stores >= a.data.length * 0.7) emit(arrValue(a), line); stack.length = 0;
          } else if (r && r.owner === "java/lang/String" && (r.name === "valueOf" || r.name === "copyValueOf") && r.desc.startsWith("([C")) {
            const a = pop(); if (a && a.arr && a.stores >= a.data.length * 0.7) emit(arrValue(a), line); stack.length = 0; stack.push(UNKNOWN);
          } else stack.length = 0;
          break;
        }
        default: stack.length = 0;
      }
      if (stack.length > 64) stack.length = 0;
      if (out.length > 4000) break;
    }
    flush();
    return out;
  }

  /* ---------------- class analysis (port of Analyzer.analyze) ---------------- */
  function spoofedPackage(name) {
    const slash = name.lastIndexOf("/");
    if (slash < 0) return null;
    const pkg = name.slice(0, slash + 1);
    if (pkg === "net/fabric/" || (pkg.startsWith("net/fabric/") && !pkg.startsWith("net/fabricmc/"))) return "Fabric (net.fabricmc)";
    if (pkg.startsWith("com/mojang/") && !/^com\/mojang\/(authlib|brigadier|datafixers|serialization|blaze3d|logging|math|realmsclient|text2speech|bridge|jtracy|jvm|util)\//.test(pkg)) return "Mojang (com.mojang)";
    if (pkg.startsWith("org/spongepowered/") && !pkg.startsWith("org/spongepowered/asm/") && !pkg.startsWith("org/spongepowered/tools/")) return "Mixin (org.spongepowered)";
    return null;
  }
  function topLevel(name, all) {
    let idx = name.indexOf("$");
    while (idx > 0) { const c = name.slice(0, idx); if (all.has(c)) return c; idx = name.indexOf("$", idx + 1); }
    return name;
  }
  function rawStrings(b) {
    const out = []; let s = "";
    for (let i = 0; i < b.length && out.length < 20000; i++) { const c = b[i]; if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c); else { if (s.length >= 6) out.push(s); s = ""; } }
    if (s.length >= 6) out.push(s);
    return out;
  }
  function analyzeClass(container, entryPath, bytes, hidden, names) {
    let C;
    try { C = parseClass(bytes); } catch (e) {
      const fb = entryPath.endsWith(".class") ? entryPath.slice(0, -6) : entryPath;
      const ci = newClass(container, fb, fb, isLibrary(fb), hidden, entryPath);
      ci.broken = true;
      add(ci, at(finding("BROKEN_CLASS", "LOW", "Obfuscation", "Tampered class file", "The class file could not be read (" + e.message + "). Obfuscators corrupt classes on purpose to break decompilers."), container, fb, ev(null, 0, entryPath, null), "asm"));
      for (const s of rawStrings(bytes)) processString(ci, s, ev(null, 0, s, s), "raw", 0);
      return { ci, C: null };
    }
    const name = C.name, top = topLevel(name, names);
    const ci = newClass(container, name, top, isLibrary(name), hidden, entryPath);
    ci.modAnnotation = C.modAnnotation;
    if (!hidden && entryPath.endsWith(".class") && !entryPath.includes("META-INF/versions/")) {
      const exp = entryPath.slice(0, -6);
      if (exp !== name) add(ci, at(finding("NAME_MISMATCH", "LOW", "Obfuscation", "File name does not match the class", "The file '" + entryPath + "' actually contains the class '" + name + "'."), container, name, ev(null, 0, entryPath, null), "asm"));
    }
    if (/^(java|jdk|sun)\//.test(name)) add(ci, at(finding("JDK_SHADOW", "HIGH", "Evasion", "Class inside a JDK package", "The JAR ships a class in the java/jdk/sun package – an attempt to disguise itself as a system class."), container, name, ev(null, 0, name, null), "asm"));
    const spoof = spoofedPackage(name);
    if (spoof) {
      tag(ci, "SPOOF_PKG", ev(null, 0, name, null));
      add(ci, at(finding("SPOOF_PACKAGE", "HIGH", "Evasion", "Fake package: imitates " + spoof, "The class lives in a package that looks like " + spoof + " but does not belong to it (e.g. net/fabric instead of net/fabricmc). Injected malware hides between real libraries this way."), container, name, ev(null, 0, name.replace(/\//g, "."), null), "asm"));
    }
    for (const fam of R.families) for (const pre of fam.classes)
      if (name.startsWith(pre)) add(ci, at(finding("FAMILY_" + fam.name.toUpperCase(), fam.sev, "Known malware", "Known malware: " + fam.name, fam.desc + " (class name matches the known family.)"), container, name, ev(null, 0, name, null), "asm"));
    for (const f of C.fields) if (f.value != null) processString(ci, f.value, ev("<field " + f.name + ">", 0, f.value, f.value), "ldc", 0);
    for (const m of C.methods) if (m.codeLen) analyzeMethod(ci, C, m);
    return { ci, C };
  }
  function analyzeMethod(ci, C, m) {
    const mname = m.name + m.desc;
    const insns = decode(C, m);
    let xors = 0, charOps = false;
    const prev = { v: null }, tags = [];
    for (let i = 0; i < insns.length; i++) {
      const ins = insns[i], op = ins.op, line = ins.line;
      tags.length = 0;
      if (op >= 0xb6 && op <= 0xb9) {
        const r = memberRef(C, ins.v);
        if (!r) continue;
        callTags(r.owner, r.name, tags);
        if (tags.length) {
          const simple = r.owner.slice(r.owner.lastIndexOf("/") + 1);
          const needle = r.name === "<init>" ? "new " + simple.slice(simple.lastIndexOf("$") + 1) : r.name + "(";
          const e = ev(mname, line, simple + "." + r.name, needle);
          for (const t of tags) tag(ci, t, e);
        }
        if (r.owner === "java/lang/String" && (r.name === "toCharArray" || r.name === "charAt")) charOps = true;
        if (r.owner === "java/lang/ClassLoader" && r.name === "loadClass") {
          for (let k = i - 1; k >= 0 && k > i - 4; k--) {
            const s = ldcString(C, insns[k]);
            if (s != null) {
              if (s === "Utility") add(ci, at(finding("FRACTUREISER_STAGE0", "CRITICAL", "Known malware", "fractureiser stage-0 loader", "Loads a class named 'Utility' through a ClassLoader – exactly the pattern of the fractureiser worm."), ci.container, ci.name, ev(mname, line, 'loadClass("Utility")', "Utility"), "asm"));
              break;
            }
          }
        }
      } else if (op >= 0xb2 && op <= 0xb5) {
        const r = memberRef(C, ins.v);
        if (!r) continue;
        fieldTags(r.owner, r.name, tags);
        for (const t of tags) tag(ci, t, ev(mname, line, r.owner.slice(r.owner.lastIndexOf("/") + 1) + "." + r.name, r.name));
      } else if (op === 0xbb) {
        const t0 = C.cls(ins.v);
        typeTags(t0, tags);
        for (const t of tags) tag(ci, t, ev(mname, line, "new " + t0, t0.slice(t0.lastIndexOf("/") + 1)));
      } else if (op === 0x12 || op === 0x13) {
        const s = ldcString(C, ins);
        if (s != null) { processString(ci, s, ev(mname, line, s, s), "ldc", 0); joinWithPrevious(ci, prev, s, mname, line); prev.v = s; }
      } else if (op === 0xba) {
        const ref = C.cp[ins.v];
        const bsm = ref ? C.bsms[ref.a] : null;
        if (bsm) {
          if (!R.bootstraps.includes(bsm.owner)) ci.customIndy++;
          for (const a of bsm.args) for (const part of a.split(/[\u0001\u0002]/)) {
            if (part.length >= 3) { processString(ci, part, ev(mname, line, part, part), "indy", 0); joinWithPrevious(ci, prev, part, mname, line); prev.v = part; }
          }
        }
      } else if (op === 0x82 || op === 0x83) xors++;
    }
    const decoded = emulate(C, insns);
    if (decoded.length) {
      const dprev = { v: null };
      let all = "", hidden = 0;
      const plain = new Set();
      for (const ins of insns) { const s = ldcString(C, ins); if (s != null) plain.add(s); }
      for (const d of decoded) {
        if (!plain.has(d.value)) hidden++;
        processString(ci, d.value, ev(mname, d.line, d.value, null), "decrypted", 0);
        joinWithPrevious(ci, dprev, d.value, mname, d.line);
        dprev.v = d.value;
        if (all.length < 20000) all += d.value;
      }
      if (hidden >= 3) { ci.encryptedStrings += hidden; tag(ci, "S_ENCSTR", ev(mname, decoded[0].line, decoded[0].value, null)); }
      scanConcatenation(ci, all, mname, decoded[0].line);
    }
    if ((m.access & 0x0008) && m.desc.startsWith("(Ljava/lang/String;") && m.desc.endsWith(")Ljava/lang/String;") && xors >= 1 && charOps) ci.decryptors++;
  }

  /* ---------------- disassembler for the code view ---------------- */
  function disassemble(bytes) {
    let C;
    try { C = parseClass(bytes); } catch (e) { return "// Could not read class: " + e.message; }
    const lines = ["// class " + C.name.replace(/\//g, ".") + (C.superName && C.superName !== "java/lang/Object" ? " extends " + C.superName.replace(/\//g, ".") : ""), ""];
    for (const f of C.fields) lines.push("  field " + f.name + (f.value != null ? " = " + JSON.stringify(f.value) : ""));
    if (C.fields.length) lines.push("");
    for (const m of C.methods) {
      lines.push("  " + m.name + m.desc + (m.codeLen ? "" : "  // no code"));
      if (!m.codeLen) { lines.push(""); continue; }
      const insns = decode(C, m);
      let lastLine = -1;
      for (const ins of insns) {
        if (ins.line && ins.line !== lastLine) { lines.push("    // line " + ins.line); lastLine = ins.line; }
        let arg = "";
        const op = ins.op;
        if (op === 0x12 || op === 0x13 || op === 0x14) { const c = C.cp[ins.v]; arg = c ? (c.t === 8 ? JSON.stringify(C.utf(c.a)) : c.t === 7 ? C.utf(c.a) : String(c.v ?? "")) : ""; }
        else if (op >= 0xb2 && op <= 0xb9) { const r = memberRef(C, ins.v); if (r) arg = r.owner + "." + r.name + (op >= 0xb6 ? " " + r.desc : " : " + r.desc); }
        else if (op === 0xba) { const ref = C.cp[ins.v]; if (ref) { const nt = C.cp[ref.b]; arg = C.utf(nt.a) + " " + C.utf(nt.b) + " [bsm " + (C.bsms[ref.a] ? C.bsms[ref.a].owner : "?") + "]"; } }
        else if (op === 0xbb || op === 0xbd || op === 0xc0 || op === 0xc1 || op === 0xc5) arg = C.cls(ins.v);
        else if (op === 0x84) arg = ins.v + " " + ins.inc;
        else if (op === 0x10 || op === 0x11 || op === 0xbc || (OPLEN[op] === 1 && op !== 0x12)) arg = String(ins.v);
        else if ((op >= 0x99 && op <= 0xa8) || op === 0xc6 || op === 0xc7) arg = "L" + (ins.pc + ins.v);
        lines.push("    " + String(ins.pc).padStart(4, " ") + ": " + (OPNAMES[op] || "op" + op).toUpperCase() + (arg ? " " + arg : ""));
      }
      lines.push("");
    }
    return lines.join("\n");
  }

  /* ---------------- zip ---------------- */
  async function inflate(data) {
    const ds = new DecompressionStream("deflate-raw");
    const stream = new Blob([data]).stream().pipeThrough(ds);
    const reader = stream.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > LIMITS.entry) { reader.cancel(); throw new Error("Entry too large (> 256 MB)"); }
      chunks.push(value);
    }
    const out = new Uint8Array(total); let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
  }
  function zipEntries(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    let eocd = -1;
    for (let i = u8.length - 22; i >= Math.max(0, u8.length - 70000); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("Not a valid JAR/ZIP file: zip END header not found");
    const n = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
    const out = [];
    let p = cdOff;
    for (let k = 0; k < n; k++) {
      if (p + 46 > u8.length || dv.getUint32(p, true) !== 0x02014b50) throw new Error("Not a valid JAR/ZIP file: broken central directory");
      const method = dv.getUint16(p + 10, true), cs = dv.getUint32(p + 20, true), us = dv.getUint32(p + 24, true);
      const fl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true), lo = dv.getUint32(p + 42, true);
      const nameBytes = u8.subarray(p + 46, p + 46 + fl);
      out.push({ name: td.decode(nameBytes), method, cs, us, lo });
      p += 46 + fl + el + cl;
    }
    return out;
  }
  async function readEntry(u8, e) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (dv.getUint32(e.lo, true) !== 0x04034b50) throw new Error("bad local header");
    const fl = dv.getUint16(e.lo + 26, true), el = dv.getUint16(e.lo + 28, true);
    const start = e.lo + 30 + fl + el;
    const data = u8.subarray(start, start + e.cs);
    if (e.method === 0) { if (data.length > LIMITS.entry) throw new Error("Entry too large (> 256 MB)"); return data.length > 16 << 20 ? data : data.slice(); }
    if (e.method === 8) return inflate(data);
    throw new Error("unsupported compression " + e.method);
  }

  /* ---------------- scanner (port of Scanner.java) ---------------- */
  async function scan(bytes, fileName, progress = () => {}, knownSha256 = null) {
    const S = { containers: [], classes: new Map(), resourceFindings: [], jarTags: new Set(), jarTagEvidence: new Map(), meta: {}, entrypoints: [], resources: [], totalBytes: 0, classBytes: 0, entryCount: 0, type: "Java archive", hidden: new Set(), binary: null, raw: new Map() };
    const t0 = Date.now();
    const tagJar = (t, e) => { if (!S.jarTags.has(t)) { S.jarTags.add(t); S.jarTagEvidence.set(t, e); } };
    const resFinding = (container, path, rule, sev, cat, title, desc) => S.resourceFindings.push({ rule, severity: sev, category: cat, title, description: desc, container, evidence: path, needle: path, source: "resource", occurrences: 1 });
    S.tagJar = tagJar; S.resFinding = resFinding;
    const hashes = { sha256: /^[0-9a-f]{64}$/.test(knownSha256 || "") ? knownSha256 : await digest("SHA-256", bytes), sha1: await digest("SHA-1", bytes) };
    progress("Unpacking", 3);
    const isZip = bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && (bytes[2] === 3 || bytes[2] === 5 || bytes[2] === 7);
    if (isZip) await loadContainer(S, "", bytes, 0);
    else { progress("Binary analysis", 5); S.binary = await scanBinary(S, bytes, fileName); }

    progress("ASM bytecode analysis", 10);
    const total = S.containers.reduce((a, c) => a + c.classes.size, 0);
    let done = 0;
    for (const c of S.containers) {
      const names = new Set(c.classes.keys());
      for (const [nm, b] of c.classes) {
        const { ci } = analyzeClass(c.path, nm + ".class", b, S.hidden.has(c.path + "!" + nm), names);
        S.classes.set(ci.container + "!" + ci.name, ci);
        if (++done % 100 === 0) { progress("ASM bytecode analysis", 10 + Math.round(75 * done / Math.max(1, total))); await new Promise(r => setTimeout(r, 0)); }
      }
    }
    markEntrypoints(S);
    progress("Obfuscation & resources", 88);
    obfuscationChecks(S, tagJar, resFinding);
    progress("Scoring", 95);
    S.preCombo = S.resourceFindings.length;
    evaluateCombos(S, resFinding, hashes.sha256);
    const report = buildReport(S, hashes, fileName, bytes.length, Date.now() - t0);
    progress("Done", 100);
    return { report, containers: S.containers, state: S, hashes, size: bytes.length, ms: Date.now() - t0 };
  }
  function softHash(alg, data) {
    const u = data instanceof Uint8Array ? data : new Uint8Array(data), n = u.length, sha1 = alg === "SHA-1";
    const words = ((n + 8) >> 6) + 1 << 4, W = new Uint32Array(words);
    for (let i = 0; i < n; i++) W[i >> 2] |= u[i] << (24 - (i & 3) * 8);
    W[n >> 2] |= 0x80 << (24 - (n & 3) * 8);
    W[words - 1] = (n * 8) >>> 0; W[words - 2] = Math.floor(n / 0x20000000);
    const rotl = (x, c) => (x << c) | (x >>> (32 - c)), rotr = (x, c) => (x >>> c) | (x << (32 - c)), w = new Uint32Array(sha1 ? 80 : 64);
    let H;
    if (sha1) {
      H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
      for (let o = 0; o < words; o += 16) {
        for (let t = 0; t < 80; t++) w[t] = t < 16 ? W[o + t] : rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
        let [a, b, c, d, e] = H;
        for (let t = 0; t < 80; t++) {
          const f = t < 20 ? (b & c) | (~b & d) : t < 40 ? b ^ c ^ d : t < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
          const k = t < 20 ? 0x5a827999 : t < 40 ? 0x6ed9eba1 : t < 60 ? 0x8f1bbcdc : 0xca62c1d6;
          const tmp = (rotl(a, 5) + f + e + k + w[t]) | 0; e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
        }
        H = [H[0] + a | 0, H[1] + b | 0, H[2] + c | 0, H[3] + d | 0, H[4] + e | 0];
      }
    } else {
      const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
      H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
      for (let o = 0; o < words; o += 16) {
        for (let t = 0; t < 64; t++) {
          if (t < 16) w[t] = W[o + t];
          else { const x = w[t - 15], y = w[t - 2]; w[t] = (w[t - 16] + (rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3)) + w[t - 7] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10))) | 0; }
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let t = 0; t < 64; t++) {
          const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) | 0;
          const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
          h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        H = H.map((v, i) => (v + [a, b, c, d, e, f, g, h][i]) | 0);
      }
    }
    return H.map(v => (v >>> 0).toString(16).padStart(8, "0")).join("");
  }
  async function digest(alg, bytes) {
    if (!(globalThis.crypto && globalThis.crypto.subtle)) return softHash(alg, bytes);
    const h = await crypto.subtle.digest(alg, bytes);
    return [...new Uint8Array(h)].map(x => x.toString(16).padStart(2, "0")).join("");
  }

  async function loadContainer(S, path, bytes, depth) {
    const c = { path, classes: new Map(), text: new Map(), depth };
    S.containers.push(c);
    let entries;
    try { entries = zipEntries(bytes); } catch (e) {
      if (depth === 0) throw e;
      S.resFinding(path, path, "BROKEN_NESTED", "LOW", "Obfuscation", "Broken nested archive", e.message);
      return;
    }
    for (const e of entries) {
      if (++S.entryCount > LIMITS.entries) { skip(S, "entries", "More than " + LIMITS.entries.toLocaleString("en-US") + " files in the archive – the rest was not unpacked (zip bomb?)."); break; }
      if (e.name.endsWith("/")) {
        if (e.name.endsWith(".class/")) S.resFinding(path, e.name, "CLASS_DIR_TRICK", "LOW", "Obfuscation", "Folder named like a .class file", "A folder is named like a class file – a known trick to confuse decompilers/unzippers.");
        continue;
      }
      if (e.us > LIMITS.entry) { bigEntry(S, path, e.name, e.us); continue; }
      let data;
      try { data = await readEntry(bytes, e); } catch (x) { if (/too large/i.test(x.message)) bigEntry(S, path, e.name, e.us); continue; }
      S.totalBytes += data.length;
      if (S.totalBytes > LIMITS.total) { skip(S, "total", "More than 6 GB unpacked – the rest of the archive was not unpacked (zip bomb?)."); break; }
      await handleEntry(S, c, e.name, data, depth);
    }
  }

  function skip(S, key, text) {
    S.skipped = S.skipped || {};
    if (S.skipped[key]) return;
    S.skipped[key] = true;
    S.resFinding("", text, "PARTIAL_" + key.toUpperCase(), "LOW", "Coverage", "Only part of the file was analysed", text);
  }
  function bigEntry(S, path, name, size) {
    S.resFinding(path, name, "HUGE_ENTRY", "LOW", "Coverage", "File too large to unpack", "'" + name + "' unpacks to " + Math.round(size / 1048576) + " MB (limit 256 MB) and was skipped. Large single files inside a mod are unusual – check what it is.");
  }
  const NATIVE_EXT = new Set(["dll", "so", "dylib", "jnilib", "node", "sys"]), EXE_EXT = new Set(["exe", "scr", "com", "bin", "msi"]);
  const TEXT_EXT = new Set(["json", "txt", "yml", "yaml", "properties", "cfg", "toml", "xml", "mf", "js", "lua", "conf", "ini", "json5", "info", "md", "html", "py", "kts", "gradle"]);
  const BLOB_SKIP = new Set("png jpg jpeg gif ogg mp3 wav gz nbt ttf otf woff woff2 webp zip jar xz bz2 zst lz4 fsh vsh glsl bdmodel bbmodel icns ico tga dds pack mcmeta schem schematic litematic mca dat bin ser res brotli br zlib lzma 7z rar jfr pdf svg pdn psd blob frag vert material qoi kotlin_module kotlin_builtins rsa dsa sf ec p7s sig asc".split(" "));
  async function handleEntry(S, c, name, data, depth) {
    const lowerName = name.toLowerCase();
    const classMagic = data.length > 10 && data[0] === 0xca && data[1] === 0xfe && data[2] === 0xba && data[3] === 0xbe;
    const major = data.length > 8 ? (data[6] << 8) | data[7] : 0;
    const isClass = classMagic && major >= 45 && major <= 90;
    if (lowerName.endsWith(".class")) {
      if (!classMagic) { S.resFinding(c.path, name, "FAKE_CLASS", "LOW", "Obfuscation", "Invalid .class file", "The file ends in .class but is not a Java class (encrypted or a decoy)."); S.tagJar("R_BLOB", { text: name }); return; }
      let cname = name.slice(0, -6);
      try { cname = parseClassName(data) || cname; } catch (e) {}
      if ((S.classBytes += data.length) > LIMITS.classBytes) { skip(S, "classes", "More than 512 MB of class files – the remaining classes were not analysed."); return; }
      if (!c.classes.has(cname)) c.classes.set(cname, data);
      return;
    }
    if (isClass) {
      let cname = name;
      try { cname = parseClassName(data) || name; } catch (e) {}
      if (!c.classes.has(cname)) c.classes.set(cname, data);
      S.hidden.add(c.path + "!" + cname);
      S.resFinding(c.path, name, "HIDDEN_CLASS", "HIGH", "Evasion", "Class disguised as a resource", "'" + name + "' is actually the Java class '" + cname + "'. Such classes are not loaded normally but by custom loader code.");
      S.tagJar("R_HIDDENCLASS", { text: name });
      return;
    }
    const zipMagic = data.length > 4 && data[0] === 0x50 && data[1] === 0x4b && data[2] === 3 && data[3] === 4;
    if (zipMagic && (/\.(jar|zip|litemod)$/.test(lowerName) || !/\.(png|jpg|ogg|nbt|mcpack|mcworld|xlsx|docx)$/.test(lowerName))) {
      if (depth + 1 > LIMITS.depth) { S.resFinding(c.path, name, "DEEP_NESTING", "LOW", "Obfuscation", "Very deeply nested archives", "Not unpacked further."); return; }
      if (!/\.(jar|zip|litemod)$/.test(lowerName)) S.resFinding(c.path, name, "DISGUISED_ARCHIVE", "MEDIUM", "Evasion", "Disguised archive", "'" + name + "' is a ZIP/JAR archive with a fake file extension.");
      S.resources.push({ container: c.path, path: name, size: data.length, kind: "nested-jar" });
      await loadContainer(S, c.path ? c.path + "!/" + name : name, data, depth + 1);
      return;
    }
    const kind = resourceKind(S, c, name, lowerName, data);
    if (S.resources.length < 5000) S.resources.push({ container: c.path, path: name, size: data.length, kind });
    const ext = lowerName.includes(".") ? lowerName.slice(lowerName.lastIndexOf(".") + 1) : "";
    if ((TEXT_EXT.has(ext) || lowerName.endsWith("manifest.mf")) && data.length <= 1048576 && (S.textBytes = (S.textBytes || 0) + data.length) <= 32 * 1048576) c.text.set(name, data);
    if (depth === 0) parseMeta(S, name, data);
  }
  function parseClassName(b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let p = 8; const n = dv.getUint16(p); p += 2;
    const cp = new Array(n);
    for (let i = 1; i < n; i++) {
      const t = b[p++];
      if (t === 1) { const l = dv.getUint16(p); cp[i] = { t, v: mutf8(b, p + 2, l) }; p += 2 + l; }
      else if (t === 3 || t === 4) p += 4;
      else if (t === 5 || t === 6) { p += 8; i++; }
      else if (t === 7) { cp[i] = { t, a: dv.getUint16(p) }; p += 2; }
      else if (t === 8 || t === 16 || t === 19 || t === 20) p += 2;
      else if (t >= 9 && t <= 12 || t === 17 || t === 18) p += 4;
      else if (t === 15) p += 3;
      else return null;
    }
    const tc = cp[dv.getUint16(p + 2)];
    return tc && cp[tc.a] ? cp[tc.a].v : null;
  }
  function resourceKind(S, c, name, lowerName, data) {
    const ext = lowerName.includes(".") ? lowerName.slice(lowerName.lastIndexOf(".") + 1) : "";
    const mz = data.length > 64 && data[0] === 0x4d && data[1] === 0x5a;
    const elf = data.length > 16 && data[0] === 0x7f && data[1] === 0x45 && data[2] === 0x4c && data[3] === 0x46;
    const m = data.length > 4 ? ((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]) >>> 0 : 0;
    const macho = [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE].includes(m);
    if (mz || elf || macho) {
      const knownLib = /(lwjgl|jna|sqlite|natives?|discord|jinput|openal|glfw|jemalloc|netty|zstd|lz4|snappy|brotli|conpty|pty4j|jnativehook|oshi|win32-x86|linux-x86|darwin|osx|macos|aarch64|amd64|x86_64|arm64)/.test(lowerName);
      if (!NATIVE_EXT.has(ext) && !EXE_EXT.has(ext)) S.resFinding(c.path, name, "DISGUISED_BINARY", "HIGH", "Evasion", "Disguised executable", "'" + name + "' is a native program (" + (mz ? "Windows PE" : elf ? "Linux ELF" : "macOS Mach-O") + ") with a harmless-looking extension.");
      else if (EXE_EXT.has(ext)) S.resFinding(c.path, name, "EMBEDDED_EXE", "HIGH", "Execution", "Embedded program (.exe)", "The JAR contains an executable program. Mods almost never need this – it is often started secretly.");
      else if (!knownLib) S.resFinding(c.path, name, "EMBEDDED_NATIVE", "MEDIUM", "Execution", "Unknown native library", "Native library that does not belong to a known library (LWJGL, JNA, SQLite …).");
      else S.resFinding(c.path, name, "EMBEDDED_NATIVE_KNOWN", "INFO", "Execution", "Native library (known)", "Native library of a known library.");
      return "binary";
    }
    if (["bat", "cmd", "ps1", "vbs", "vbe", "hta", "wsf", "jse", "lnk", "reg"].includes(ext)) {
      S.resFinding(c.path, name, "EMBEDDED_SCRIPT", "MEDIUM", "Execution", "Embedded Windows script", "Batch/PowerShell/VBS scripts in a mod are often used to run malicious code.");
      scanText(S, c, name, data.length > 2000000 ? data.subarray(0, 2000000) : data); return "script";
    }
    if (ext === "sh" || ext === "command") { S.resFinding(c.path, name, "EMBEDDED_SHELL", "LOW", "Execution", "Embedded shell script", "Shell script inside the JAR."); scanText(S, c, name, data.length > 2000000 ? data.subarray(0, 2000000) : data); return "script"; }
    if (TEXT_EXT.has(ext) || (ext === "" && data.length < 200000 && printableRatio(latin.decode(data.subarray(0, 4096))) > 0.95)) { if (data.length < 2000000) scanText(S, c, name, data); return "text"; }
    if (data.length > 2048 && !BLOB_SKIP.has(ext) && !lowerName.startsWith("meta-inf/")) {
      const e = entropy(data);
      if (e > 7.6) { S.resFinding(c.path, name, "ENCRYPTED_BLOB", "LOW", "Obfuscation", "Data that looks encrypted", "'" + name + "' has an entropy of " + e.toFixed(2) + " bits/byte – encrypted or packed."); S.tagJar("R_BLOB", { text: name }); return "blob"; }
    }
    return "file";
  }
  const QUOTED = /"((?:[^"\\]|\\.){3,2000})"/g;
  function quoted(s) { const out = []; for (const m of s.matchAll(QUOTED)) out.push(m[1].replace(/\\\\/g, "\\").replace(/\\\//g, "/")); return out; }
  function scanText(S, c, name, data) {
    const text = td.decode(data);
    const pseudo = "res:" + name;
    const holder = newClass(c.path, pseudo, pseudo, false, false, name);
    let n = 0;
    for (const line of text.split(/\r\n|\r|\n/)) {
      if (++n > 20000) break;
      const t = line.trim();
      if (!t) continue;
      processString(holder, t.length > 4000 ? t.slice(0, 4000) : t, ev(null, n, t, t), "resource", 1);
      for (const q of quoted(t)) if (q !== t) processString(holder, q, ev(null, n, q, q), "resource", 0);
    }
    for (const f of holder.findings.values()) { f.cls = null; f.method = null; f.title += " (in resource)"; f.source = "resource"; f.evidence = name + ":" + f.line + "  " + f.evidence; S.resourceFindings.push(f); }
    for (const [t, e] of holder.tags) S.tagJar(t, e);
  }
  function parseMeta(S, name, data) {
    if (data.length > 4 << 20 || name.includes("/") && !/^META-INF\/(MANIFEST\.MF|mods\.toml|neoforge\.mods\.toml)$/i.test(name)) return;
    const text = td.decode(data), M = S.meta;
    const put = (k, v) => { if (v != null && typeof v !== "object" && M[k] == null) M[k] = String(v); };
    const flat = v => Array.isArray(v) ? v.map(x => typeof x === "string" ? x : x && (x.name || x.config) || "").filter(Boolean).join(", ") : typeof v === "object" && v ? Object.keys(v).join(", ") : String(v);
    try {
      if (name === "fabric.mod.json" || name === "quilt.mod.json") {
        const o = JSON.parse(text), quilt = name.startsWith("quilt");
        S.type = quilt ? "Quilt mod" : "Fabric mod";
        const base = quilt && o.quilt_loader ? o.quilt_loader : o;
        put("id", base.id); put("version", base.version);
        const md = quilt && base.metadata ? base.metadata : o;
        put("name", md.name); put("description", md.description);
        if (md.authors) M.authors = flat(md.authors);
        if (base.entrypoints && typeof base.entrypoints === "object")
          for (const [k, v] of Object.entries(base.entrypoints)) for (const it of (Array.isArray(v) ? v : [v])) { const cls = typeof it === "string" ? it : it && it.value; if (cls) S.entrypoints.push(k + ": " + cls); }
        if (o.mixins) M.mixins = flat(o.mixins);
      } else if (name === "META-INF/mods.toml" || name === "META-INF/neoforge.mods.toml") {
        S.type = name.includes("neoforge") ? "NeoForge mod" : "Forge mod";
        for (const [k, t] of [["modId", "id"], ["displayName", "name"], ["version", "version"], ["authors", "authors"], ["description", "description"]]) {
          const mm = new RegExp("^\\s*" + k + "\\s*=\\s*(?:\"([^\"]*)\"|'''([\\s\\S]*?)'''|'([^']*)')", "m").exec(text);
          if (mm) put(t, (mm[1] ?? mm[2] ?? mm[3]).trim());
        }
      } else if (name === "mcmod.info") {
        if (S.type === "Java archive") S.type = "Forge mod (legacy)";
        const el = JSON.parse(text);
        const o = Array.isArray(el) ? el[0] : el && el.modList ? el.modList[0] : null;
        if (o) { put("id", o.modid); put("name", o.name); put("version", o.version); if (o.authorList) M.authors = flat(o.authorList); }
      } else if (["plugin.yml", "paper-plugin.yml", "bungee.yml"].includes(name)) {
        S.type = name === "bungee.yml" ? "BungeeCord plugin" : name.startsWith("paper") ? "Paper plugin" : "Bukkit/Spigot/Paper plugin";
        for (const [k, t] of [["name", "name"], ["version", "version"], ["main", "main"], ["author", "authors"], ["authors", "authors"], ["description", "description"]]) {
          const mm = new RegExp("^" + k + "\\s*:\\s*(.+)$", "m").exec(text);
          if (mm) put(t, mm[1].trim().replace(/^["']|["']$/g, ""));
        }
        if (M.main) S.entrypoints.push("main: " + M.main);
      } else if (name === "velocity-plugin.json") {
        S.type = "Velocity plugin";
        const o = JSON.parse(text); put("id", o.id); put("name", o.name); put("version", o.version); put("main", o.main);
        if (o.authors) M.authors = flat(o.authors);
        if (M.main) S.entrypoints.push("main: " + M.main);
      } else if (name === "META-INF/MANIFEST.MF") {
        const attrs = {};
        let last = null;
        for (const l of text.split(/\r?\n/)) {
          if (l.startsWith(" ") && last) { attrs[last] += l.slice(1); continue; }
          const i = l.indexOf(":"); if (i > 0) { last = l.slice(0, i).trim(); attrs[last] = l.slice(i + 1).trim(); }
        }
        for (const k of ["Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class", "Created-By", "Implementation-Title", "Implementation-Version", "Class-Path"]) if (attrs[k]) M["manifest." + k] = attrs[k];
        if (attrs["Main-Class"]) S.entrypoints.push("Main-Class: " + attrs["Main-Class"]);
        for (const k of ["Premain-Class", "Agent-Class", "Launcher-Agent-Class"]) if (attrs[k]) {
          S.entrypoints.push(k + ": " + attrs[k]);
          S.resFinding("", name, "JAVA_AGENT", "MEDIUM", "Code loading", "Java agent (" + k + ")", "The JAR can hook into the JVM as a Java agent and modify other classes while they load.");
        }
        if (attrs["Class-Path"] && /(https?|ftp):/i.test(attrs["Class-Path"])) S.resFinding("", name, "REMOTE_CLASSPATH", "HIGH", "Downloader", "Classpath points to the internet", "The manifest Class-Path contains a remote URL: " + attrs["Class-Path"]);
        if (attrs["Main-Class"] && S.type === "Java archive") S.type = "Java application";
      }
    } catch (e) { M["parseError." + name] = e.name; }
  }
  function markEntrypoints(S) {
    const eps = new Set();
    for (const e of S.entrypoints) { let cls = e.slice(e.indexOf(":") + 1).trim(); if (cls.includes("::")) cls = cls.slice(0, cls.indexOf("::")); eps.add(cls.replace(/\./g, "/")); }
    for (const ci of S.classes.values()) {
      if (ci.modAnnotation) { eps.add(ci.name); S.entrypoints.push("@Mod: " + ci.name.replace(/\//g, ".")); }
      if (eps.has(ci.name) || eps.has(ci.top)) { ci.entrypoint = true; for (const f of ci.findings.values()) f.entrypoint = true; }
    }
    if (S.entrypoints.some(s => s.startsWith("preLaunch"))) S.resFinding("", "fabric.mod.json", "PRELAUNCH", "INFO", "Start", "Runs before the game starts (preLaunch)", "The mod uses the preLaunch entrypoint and runs before Minecraft itself is loaded.");
  }
  function obfuscationChecks(S, tagJar, resFinding) {
    let own = 0, weird = 0, indy = 0, decryptors = 0, enc = 0;
    for (const ci of S.classes.values()) {
      if (ci.library) continue;
      own++;
      const simple = ci.name.slice(ci.name.lastIndexOf("/") + 1);
      if (/^[Il1|_]{4,}$/.test(simple) || !/^[\x20-\x7e]+$/.test(simple) || /^[a-z]{1,2}$/.test(simple) || /\s/.test(simple) || ["if", "do", "for", "int", "new", "con", "nul", "aux", "prn", "com1", "lpt1"].includes(simple.toLowerCase())) weird++;
      indy += ci.customIndy; decryptors += ci.decryptors; enc += ci.encryptedStrings;
    }
    if (own >= 5 && weird > own * 0.3) { resFinding("", weird + " of " + own + " classes", "OBF_NAMES", "LOW", "Obfuscation", "Class names are obfuscated", "Many classes have meaningless names (IlIl, Unicode, a/b/c, reserved Windows names). Obfuscation is not automatically malware, but it hides what the code does."); tagJar("OBFUSCATED", null); }
    if (indy > 0) { resFinding("", indy + " calls", "OBF_INDY", indy > 20 ? "MEDIUM" : "LOW", "Obfuscation", "InvokeDynamic obfuscation", "Method calls go through custom bootstrap methods, so decompilers cannot show which method is really called – popular with obfuscators and malware."); tagJar("OBFUSCATED", null); }
    if (enc >= 20) { resFinding("", enc + " strings", "OBF_CHARSTRINGS", "MEDIUM", "Obfuscation", "Character-by-character encrypted strings", "Strings are built character by character from arithmetic (e.g. (char)(47932 - 47815)). RatScanner decrypted and checked them via emulation – but the technique itself is mostly used by malware to hide URLs and commands."); tagJar("OBFUSCATED", null); }
    if (decryptors > 0) { resFinding("", decryptors + " methods", "OBF_STRINGS", "LOW", "Obfuscation", "String encryption", "Methods that decrypt strings with XOR – URLs/commands are not visible in plain text, so this scan may be incomplete."); tagJar("OBFUSCATED", null); }
    if (S.type.includes("mod")) for (const ci of S.classes.values()) if (ci.name.startsWith("net/minecraft/") && !ci.library) {
      resFinding(ci.container, ci.name, "MC_SHADOW", "MEDIUM", "Evasion", "Mod ships Minecraft classes", "Classes in net/minecraft belong to the game. A mod that ships its own can override game classes."); break;
    }
  }
  const tagLabel = t => (R.caps[t] && R.caps[t].label) || ({ S_EXFIL: "Webhook/exfil address", S_REMOTE: "Suspicious download address", S_IPGRAB: "IP lookup", S_STEAL: "Credential paths", S_BROWSER: "Browser profiles", S_CRYPTOADDR: "Crypto addresses", S_PERSIST: "Autostart", S_EVASION: "Anti-analysis", S_SHELL: "Shell commands", S_EXECEXT: ".exe/.bat file names", S_MINER: "Mining", S_SYSINFO: "System info", S_MODSDIR: "mods/plugins folder", S_JAREXT: ".jar files", S_UUID: "Hard-coded UUID", S_TOKENWORD: "Token keywords", S_PAY: "/pay command", S_OPCMD: "OP/permission command", R_BLOB: "Encrypted resource", R_HIDDENCLASS: "Disguised class", S_B64STR: "Base64 strings",
    S_INJECTDC: "Discord client files", S_LAUNCHER: "Other launchers", S_UAC: "UAC bypass", S_ELEVATE: "Admin rights", S_SYSMOD: "System settings", S_HIDE: "Hiding/self-delete",
    S_KILL: "Kills processes", S_TUNNEL: "Tunnel / Tor", S_C2CMD: "Bot command channel", S_RATWORD: "RAT wording", S_CMDSHELL: "cmd / sh shell", S_RAWHTTP: "Hand-made HTTP", S_C2: "Blockchain C2" }[t] || t);
  const evMap = (t, cls, e) => { const m = { tag: t, label: tagLabel(t) }; if (cls) m.cls = cls; if (e) { if (e.method) m.method = e.method; m.evidence = e.text; if (e.needle) m.needle = e.needle; } return m; };
  const matches = (co, tags) => co.all.every(t => tags.has(t)) && (!co.any.length || co.any.some(t => tags.has(t)));
  function applyCombos(ci) {
    for (const co of R.combos) {
      if (co.id.endsWith("_B") && ci.findings.has("COMBO_" + co.id.slice(0, -2))) continue;
      if (ci.findings.has("COMBO_" + co.id)) continue;
      if (!matches(co, ci.tags)) continue;
      const f = finding("COMBO_" + co.id, co.sev, co.cat, co.title, co.desc);
      const used = [...co.all, ...co.any.filter(t => ci.tags.has(t))];
      at(f, ci.container, ci.name, ci.tags.get(used[0]), "asm");
      f.related = used.filter(t => ci.tags.get(t)).map(t => evMap(t, ci.name, ci.tags.get(t)));
      add(ci, f);
    }
  }
  function evaluateCombos(S, resFinding, sha256) {
    const union = new Map();
    for (const ci of S.classes.values()) {
      applyCombos(ci);
      if (!ci.library || ci.findings.size) for (const [t, e] of ci.tags) {
        if (!union.has(t)) union.set(t, new Set());
        union.get(t).add(ci.name);
        if (!S.jarTagEvidence.has(t)) S.jarTagEvidence.set(t, e);
      }
    }
    if (S.binaryHolder) { applyCombos(S.binaryHolder); for (const f of S.binaryHolder.findings.values()) { f.cls = null; f.source = "binary"; S.resourceFindings.push(f); } }
    const all = new Set([...union.keys(), ...S.jarTags]);
    const fired = new Set();
    for (const ci of S.classes.values()) for (const r of ci.findings.keys()) fired.add(r);
    if (S.binaryHolder) for (const r of S.binaryHolder.findings.keys()) fired.add(r);
    for (const co of R.combos) {
      if (!co.jar || !matches(co, all)) continue;
      const base = co.id.replace(/_B$/, "");
      if (fired.has("COMBO_" + co.id) || fired.has("COMBO_" + base)) continue;
      const onlyRes = co.all.every(t => t.startsWith("R_"));
      const sev = ["FORCE_OP", "BLOB_LOADER", "HIDDEN_CLASS_LOADER"].includes(co.id) || onlyRes ? co.sev : lower(co.sev);
      const f = { rule: "JAR_" + co.id, severity: sev, category: co.cat, title: co.title + " (across classes)", description: co.desc + " The pieces are spread over several classes – a common trick to dodge scanners.", source: "asm", occurrences: 1 };
      const used = [...co.all, ...co.any.filter(t => all.has(t))];
      f.related = used.map(t => { const w = union.get(t); return evMap(t, w && w.size ? [...w][0] : null, S.jarTagEvidence.get(t)); });
      if (f.related.length) { const r0 = f.related[0]; f.cls = r0.cls; f.evidence = r0.evidence; f.needle = r0.needle; f.method = r0.method; }
      S.resourceFindings.push(f);
      fired.add("JAR_" + co.id);
    }
    injectedEntrypoints(S, resFinding);
    if (R.badHashes.includes(sha256)) resFinding("", sha256, "KNOWN_BAD_HASH", "CRITICAL", "Known malware", "File is known malware", "The SHA-256 hash is on the list of known malware.");
  }
  function injectedEntrypoints(S) {
    const root = n => { const p = n.split("/"); return p.length >= 3 ? p[0] + "/" + p[1] : p.length === 2 ? p[0] : ""; };
    const roots = new Map(); let own = 0;
    for (const ci of S.classes.values()) { if (ci.container !== "" || ci.library) continue; own++; roots.set(root(ci.name), (roots.get(root(ci.name)) || 0) + 1); }
    if (own < 20) return;
    for (const e of S.entrypoints) {
      let cls = e.slice(e.indexOf(":") + 1).trim(); if (cls.includes("::")) cls = cls.slice(0, cls.indexOf("::"));
      const internal = cls.replace(/\./g, "/"), share = roots.get(root(internal)) || 0;
      if (share * 20 >= own) continue;
      const ci = S.classes.get("!" + internal);
      const max = ci ? maxSeverity(ci) : null;
      const bad = (max && atLeast(max, "HIGH")) || (ci && ci.tags.has("SPOOF_PKG"));
      S.resourceFindings.push({ rule: "INJECTED_ENTRYPOINT", severity: bad ? "CRITICAL" : "MEDIUM", category: "Infection", title: bad ? "Injected entrypoint" : "Foreign entrypoint",
        description: "The entrypoint '" + e + "' points to a package that has almost nothing to do with the rest of the mod (" + share + " of " + own + " classes). " + (bad ? "The code there is suspicious itself – typical for a mod that was infected afterwards (e.g. the SilentNet injector): the real mod keeps working but also starts malware." : "Can be harmless (compatibility module), but it is also the pattern of injected mods."),
        container: "", cls: internal, evidence: e, needle: internal.slice(internal.lastIndexOf("/") + 1), source: "resource", entrypoint: true, occurrences: 1 });
    }
  }
  function maxSeverity(ci) { let m = null; for (const f of ci.findings.values()) if (m == null || SEV.indexOf(f.severity) < SEV.indexOf(m)) m = f.severity; return m; }

  function buildReport(S, hashes, fileName, size, ms) {
    const findings = [...S.resourceFindings];
    for (const ci of S.classes.values()) {
      for (const f of ci.findings.values()) findings.push(f);
      for (const [t, e] of ci.tags) {
        const cap = R.caps[t];
        if (!cap || !cap.alone || ci.library) continue;
        const f = at(finding("CAP_" + t, cap.alone, cap.cat, cap.title, cap.desc), ci.container, ci.name, e, "asm");
        f.entrypoint = ci.entrypoint;
        findings.push(f);
      }
    }
    findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || (a.library ? 1 : 0) - (b.library ? 1 : 0) || a.title.localeCompare(b.title));
    const count = new Map(), first = new Map();
    for (const f of findings) { const base = f.rule.replace(/^JAR_/, "COMBO_"); count.set(base, (count.get(base) || 0) + (f.occurrences || 1)); if (!first.has(base)) first.set(base, f); }
    let score = 0, crit = 0, high = 0;
    const highTitles = new Set();
    for (const [base, f] of first) {
      let w = WEIGHT[f.severity] * (1 + Math.min(count.get(base) - 1, 4) * 0.08);
      if (f.library) w *= 0.5;
      score += w;
      if (f.severity === "CRITICAL" && !f.library) crit++;
      if (f.severity === "HIGH") highTitles.add(f.category + f.title);
      if (f.library && f.severity === "CRITICAL") high++;
    }
    high += highTitles.size;
    const obfuscated = S.jarTags.has("OBFUSCATED");
    if (obfuscated && (crit > 0 || high > 0)) score *= 1.15;
    const verdict = crit > 0 || high >= 3 || score >= 70 ? "MALICIOUS" : high > 0 || score >= 22 ? "SUSPICIOUS" : score >= 6 ? "CAUTION" : "CLEAN";
    const severityCounts = Object.fromEntries(SEV.map(s => [s, 0]));
    for (const f of findings) severityCounts[f.severity]++;
    const capCounts = new Map();
    for (const ci of S.classes.values()) if (!ci.library) for (const t of ci.tags.keys()) if (R.caps[t]) capCounts.set(t, (capCounts.get(t) || 0) + 1);
    const capabilities = [...capCounts].map(([t, n]) => ({ tag: t, label: R.caps[t].label, category: R.caps[t].cat, classes: n }));
    const topSev = new Map();
    for (const ci of S.classes.values()) {
      let s = maxSeverity(ci);
      for (const t of ci.tags.keys()) { const cap = R.caps[t]; if (cap && cap.alone && !ci.library && (s == null || SEV.indexOf(cap.alone) < SEV.indexOf(s))) s = cap.alone; }
      if (s) { const k = ci.container + "!" + ci.top; const p = topSev.get(k); if (!p || SEV.indexOf(s) < SEV.indexOf(p)) topSev.set(k, s); }
    }
    const classes = [];
    for (const ci of S.classes.values()) {
      if (ci.name !== ci.top) continue;
      const m = { c: ci.container, n: ci.name };
      const s = topSev.get(ci.container + "!" + ci.name);
      if (s) m.s = s;
      if (ci.library) m.lib = true;
      if (ci.hidden) m.hidden = true;
      if (ci.entrypoint) m.entry = true;
      classes.push(m);
    }
    const behavior = behaviorOf(S, findings);
    return {
      fileName, size, hashes, scannedAt: new Date().toISOString(), durationMs: ms, type: S.type, meta: S.meta, entrypoints: S.entrypoints,
      verdict, score: Math.min(100, Math.round(score)), obfuscated, severityCounts, capabilities, behavior, findings, classes, classCount: S.classes.size,
      containers: S.containers.map(c => ({ path: c.path || "(main JAR)", raw: c.path, classes: c.classes.size, depth: c.depth })),
      resourceCount: S.resources.length, binary: S.binary || undefined, engines: { asm: { status: "ok", classes: S.classes.size } }
    };
  }

  /* What the file would do on your PC once it runs, derived from tags and findings. */
  const BEHAVIOR = [
    { id: "persist", label: "Starts again after a reboot (autostart, service, Java agent)", none: "No autostart or service found", bad: true,
      tags: ["S_PERSIST"], rules: ["PERSIST_EXEC", "REG_PERSIST", "PERSIST_SERVICE"] },
    { id: "install", label: "Downloads and installs other files or programs", none: "Does not download and install anything", bad: true,
      rules: ["DROPPER", "DOWNLOAD_EXE", "MOD_INSTALLER", "PAYLOAD_EXTRACT_EXEC", "WIN_URLDOWNLOAD", "REMOTE_LOADER", "URL_LOADER", "PLUGIN_REMOTE"] },
    { id: "infect", label: "Changes other mods, launchers or Discord", none: "Leaves other mods, launchers and Discord alone", bad: true,
      tags: ["S_INJECTDC", "S_LAUNCHER"], rules: ["JAR_INFECTOR", "JAR_INFECTOR_MODS", "DISCORD_INJECT", "LAUNCHER_INJECT"] },
    { id: "remote", label: "Can be remote-controlled (backdoor, bot, tunnel, Tor, open port)", none: "No backdoor or remote control found", bad: true,
      tags: ["S_C2CMD", "S_TUNNEL", "SERVER_SOCKET", "S_RATWORD"], rules: ["REVERSE_SHELL", "REMOTE_DESKTOP", "BOT_RAT", "TUNNEL_BACKDOOR", "CMD_SOCKET_SHELL", "FORCE_OP", "CHAT_CONSOLE", "HARDCODED_OP", "BLOCKCHAIN_C2"] },
    { id: "system", label: "Changes Windows settings (firewall, proxy, certificates, hosts, backups)", none: "Does not touch system settings", bad: true, tags: ["S_SYSMOD"], rules: ["EVASION_AV", "SYSMOD_EXEC"] },
    { id: "admin", label: "Tries to get administrator rights", none: "Does not ask for admin rights", bad: true, tags: ["S_UAC", "S_ELEVATE"] },
    { id: "steal", label: "Reads passwords, tokens, cookies or wallets", none: "No access to passwords or tokens found", bad: true,
      tags: ["S_STEAL", "S_BROWSER", "DPAPI", "MC_TOKEN", "S_CRYPTOADDR"] },
    { id: "spy", label: "Records screen, keys, microphone or webcam", none: "No screen, key, mic or webcam recording", bad: true,
      tags: ["SCREEN", "KEYHOOK", "WEBCAM", "W_WEBCAM"], rules: ["MIC_SPY", "CLIPPER"] },
    { id: "hide", label: "Hides itself or disables antivirus", none: "Does not try to hide", bad: true,
      tags: ["S_HIDE", "S_KILL"], rules: ["HIDDEN_PROCESS", "SELF_RELAUNCH", "LOG_HIDE_OP", "LOG_HIDE_EXEC", "EVASION_AV", "KILL_AV"] },
    { id: "exec", label: "Starts other programs", none: "Does not start other programs", tags: ["EXEC", "S_SHELL", "W_WINEXEC"] },
    { id: "code", label: "Loads extra code at runtime", none: "Does not load extra code", tags: ["CLASSLOAD", "DEFINE_CLASS", "SCRIPT_EVAL", "PLUGIN_LOAD", "ATTACH", "INSTRUMENT"] },
    { id: "net", label: "Connects to the internet", none: "No internet access", tags: ["NET", "SOCKET", "S_EXFIL", "S_C2", "W_URLDOWNLOAD"] }
  ];
  function behaviorOf(S, findings) {
    const where = new Map();
    for (const ci of S.classes.values()) if (!ci.library) for (const [t, e] of ci.tags) if (!where.has(t)) where.set(t, { cls: ci.name, e });
    for (const t of S.jarTags) if (!where.has(t)) where.set(t, { cls: null, e: S.jarTagEvidence.get(t) });
    const byRule = new Map();
    for (const f of findings) if (!f.library) { const base = f.rule.replace(/^(JAR|COMBO|STR|CAP)_/, "").replace(/_(DECRYPTED|JOINED|BASE64|HEX|REVERSED|BYTEARRAY|RAW|SOURCE|LDC|INDY|B)$/, ""); if (!byRule.has(base)) byRule.set(base, f); }
    return BEHAVIOR.map(b => {
      const f = (b.rules || []).map(r => byRule.get(r)).find(Boolean);
      const t = (b.tags || []).find(x => where.has(x));
      const out = { id: b.id, hit: !!(f || t), bad: !!b.bad, label: b.label, none: b.none };
      if (f) { out.why = f.title; if (f.cls) out.cls = f.cls; if (f.evidence) out.evidence = String(f.evidence).slice(0, 160); out.severity = f.severity; }
      else if (t) { const w = where.get(t); out.why = tagLabel(t); if (w.cls) out.cls = w.cls; if (w.e && w.e.text) out.evidence = String(w.e.text).slice(0, 160); }
      return out;
    });
  }

  /* ---------------- binary files (port of BinaryScanner) ---------------- */
  const IMPORT_TAGS = {};
  const it = (tagName, ...fns) => fns.forEach(f => IMPORT_TAGS[f] = tagName);
  it("DPAPI", "CryptUnprotectData", "BCryptDecrypt", "NCryptUnprotectSecret"); it("W_HOOK", "SetWindowsHookExA", "SetWindowsHookExW");
  it("W_KEYS", "GetAsyncKeyState", "GetKeyboardState", "GetKeyState", "MapVirtualKeyA", "MapVirtualKeyW"); it("CLIPBOARD_WRITE", "SetClipboardData"); it("CLIPBOARD_READ", "GetClipboardData");
  it("W_ALLOCEX", "VirtualAllocEx", "VirtualAlloc2"); it("W_WRITEMEM", "WriteProcessMemory", "NtWriteVirtualMemory");
  it("W_REMOTETHREAD", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread");
  it("W_UNMAP", "NtUnmapViewOfSection", "ZwUnmapViewOfSection"); it("W_SETCTX", "SetThreadContext", "Wow64SetThreadContext");
  it("W_ANTIDEBUG", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread");
  it("W_URLDOWNLOAD", "URLDownloadToFileA", "URLDownloadToFileW", "URLDownloadToCacheFileA", "URLDownloadToCacheFileW"); it("W_WINEXEC", "WinExec");
  it("W_REGWRITE", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"); it("W_WEBCAM", "capCreateCaptureWindowA", "capCreateCaptureWindowW");
  const IMPORT_CAPS = [
    ["InternetOpenA|InternetOpenW|InternetOpenUrlA|InternetOpenUrlW|HttpSendRequestA|HttpSendRequestW|WinHttpOpen|WinHttpSendRequest|URLDownloadToFileA|URLDownloadToFileW|connect|WSAConnect|send|recv", "Network access"],
    ["CreateProcessA|CreateProcessW|ShellExecuteA|ShellExecuteW|ShellExecuteExA|ShellExecuteExW|WinExec|CreateProcessAsUserW", "Starts processes"],
    ["CryptUnprotectData|BCryptDecrypt", "Decrypts protected data (DPAPI)"], ["SetWindowsHookExA|SetWindowsHookExW|GetAsyncKeyState|GetKeyboardState", "Keyboard input / hooks"],
    ["GetClipboardData|SetClipboardData", "Clipboard"], ["VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetThreadContext", "Writes into other processes"],
    ["RegSetValueExA|RegSetValueExW|RegCreateKeyExA|RegCreateKeyExW", "Writes the registry"], ["IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess", "Debugger detection"],
    ["BitBlt|GetDIBits", "Screen capture (GDI)"], ["LoadLibraryA|LoadLibraryW|LoadLibraryExA|LoadLibraryExW|GetProcAddress", "Dynamic API loading"]];
  function indexOf(u8, pat, from) {
    outer: for (let i = Math.max(0, from); i <= u8.length - pat.length; i++) { for (let k = 0; k < pat.length; k++) if (u8[i + k] !== pat[k]) continue outer; return i; }
    return -1;
  }
  function extractStrings(u8) {
    const seen = new Set(), max = LIMITS.deepStrings;
    const push = s => { if (s.length >= 6 && seen.size < max) seen.add(s.length > 4000 ? s.slice(0, 4000) : s); };
    let s = "";
    for (let i = 0; i < u8.length && seen.size < max; i++) { const c = u8[i]; if (c >= 0x20 && c < 0x7f) { if (s.length < 4096) s += String.fromCharCode(c); } else { push(s); s = ""; } }
    push(s); s = "";
    for (let i = 0; i + 1 < u8.length && seen.size < max; i += 2) { const c = u8[i] | (u8[i + 1] << 8); if (c >= 0x20 && c < 0x7f) { if (s.length < 4096) s += String.fromCharCode(c); } else { push(s); s = ""; } }
    push(s);
    return [...seen];
  }
  async function scanBinary(S, u8, fileName) {
    const info = { notes: [] };
    const lowerName = (fileName || "").toLowerCase();
    const holder = newClass("", "file:" + fileName, "file:" + fileName, false, false, fileName);
    S.binaryHolder = holder;
    const addF = (rule, sev, cat, title, desc, evd) => S.resourceFindings.push({ rule, severity: sev, category: cat, title, description: desc, container: "", evidence: evd || null, source: "binary", occurrences: 1 });
    const mz = u8.length > 0x40 && u8[0] === 0x4d && u8[1] === 0x5a;
    const elf = u8.length > 16 && u8[0] === 0x7f && u8[1] === 0x45 && u8[2] === 0x4c && u8[3] === 0x46;
    const m = u8.length > 4 ? ((u8[0] << 24) | (u8[1] << 16) | (u8[2] << 8) | u8[3]) >>> 0 : 0;
    const macho = [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE].includes(m);
    const text = printableRatio(latin.decode(u8.subarray(0, 8192))) > 0.92;
    if (mz) { S.type = "Windows program (PE)"; parsePe(S, u8, info, holder, addF); }
    else if (elf) { S.type = "Linux program (ELF)"; info.format = "ELF"; }
    else if (macho) { S.type = "macOS program (Mach-O)"; info.format = "Mach-O"; }
    else if (text) { S.type = scriptType(lowerName); info.format = "Text / script"; }
    else { S.type = "Unknown binary file"; info.format = "Unknown"; }
    if (text) {
      if (u8.length > 64 << 20) skip(S, "text", "Only the first 64 MB of this text file were read.");
      const t = td.decode(u8.length > 64 << 20 ? u8.subarray(0, 64 << 20) : u8);
      let n = 0;
      for (const line of t.split(/\r\n|\r|\n/)) {
        if (++n > 400000) break;
        const s = line.trim(); if (!s) continue;
        processString(holder, s.length > 4000 ? s.slice(0, 4000) : s, ev(null, n, s, s), "resource", 1);
        for (const q of quoted(s)) if (q !== s) processString(holder, q, ev(null, n, q, q), "resource", 0);
      }
      const l = t.toLowerCase();
      if ((l.includes("frombase64string") || l.includes("-encodedcommand") || l.includes("[convert]::")) && (l.includes("iex") || l.includes("invoke-expression"))) addF("SCRIPT_ENCODED_EXEC", "HIGH", "Execution", "Decodes and runs hidden code", "The script decodes Base64 data and runs it with Invoke-Expression – the classic way to hide a malicious payload.");
      if (lowerName.endsWith(".py") && (l.includes("exec(") || l.includes("eval(")) && /base64|zlib|marshal/.test(l)) addF("PY_OBFUSCATED_EXEC", "HIGH", "Execution", "Python runs decoded/compressed code", "exec/eval on base64/zlib/marshal data – typical for obfuscated Python stealers.");
      if (lowerName.endsWith(".js") && l.includes("child_process") && (l.includes("http") || l.includes("fetch("))) addF("JS_DOWNLOAD_EXEC", "MEDIUM", "Execution", "JavaScript with network access and process execution", "The script can download data and start programs.");
    } else {
      let count = 0;
      const strs = extractStrings(u8);
      if (strs.length >= LIMITS.deepStrings) skip(S, "strings", "The file has more than " + LIMITS.deepStrings.toLocaleString("en-US") + " different text strings – only those were checked.");
      for (const s of strs) { count++; processString(holder, s, ev(null, 0, s, s), "resource", 2); }
      info.strings = count;
      const all = latin.decode(u8.length > 64 << 20 ? u8.subarray(0, 64 << 20) : u8);
      if (all.includes("MEI\f\x0b\n\x0b\x0e") || all.includes("pyi-runtime-tmpdir") || all.includes("_MEIPASS")) { info.notes.push("PyInstaller"); addF("PYINSTALLER", "MEDIUM", "Packing", "Python program packed with PyInstaller", "The file is a Python script bundled into an .exe. Most Discord/browser stealers on the market are built exactly like this. Not malicious by itself, but a strong reason to be careful.", fileName); }
      if (all.includes("Nuitka") || all.includes("__nuitka")) info.notes.push("Nuitka (Python)");
      if (all.includes("Go build ID:") || all.includes("runtime.gopanic")) info.notes.push("Go");
      if (all.includes("Nullsoft") || all.includes("NSIS Error")) info.notes.push("NSIS installer");
      if (all.includes("Inno Setup")) info.notes.push("Inno Setup installer");
      if (all.includes("electron.asar") || all.includes("app.asar")) info.notes.push("Electron");
      if (/launch4j/i.test(all)) info.notes.push("Launch4j (Java wrapper)");
      const pk = indexOf(u8, [0x50, 0x4b, 3, 4], mz ? 0x200 : 0);
      if (pk >= 0 && indexOf(u8, [...new TextEncoder().encode("META-INF/")], pk) > 0) {
        try {
          await loadContainer(S, "[embedded-jar@" + pk + "]", u8.subarray(pk), 1);
          info.notes.push("Contains a Java archive");
          addF("EMBEDDED_JAR", "LOW", "Packing", "Program contains a Java archive", "A JAR was found inside the program (offset " + pk + "). It was unpacked and scanned with the Java engine – see the classes below.", fileName);
        } catch (e) {}
      }
    }
    const T = holder.tags;
    if (T.has("W_ALLOCEX") && T.has("W_WRITEMEM") && T.has("W_REMOTETHREAD")) addF("WIN_INJECTION", "HIGH", "Injection", "Process injection", "Imports VirtualAllocEx + WriteProcessMemory + CreateRemoteThread – the textbook way to inject code into another running program (e.g. a browser to steal cookies).", fileName);
    if (T.has("W_UNMAP") && T.has("W_SETCTX")) addF("WIN_HOLLOWING", "HIGH", "Injection", "Process hollowing", "NtUnmapViewOfSection + SetThreadContext: replaces the code of a legit process with its own – used to hide malware inside trusted programs.", fileName);
    if (T.has("W_HOOK") && T.has("W_KEYS")) { tag(holder, "KEYHOOK", T.get("W_HOOK")); addF("WIN_KEYHOOK", "MEDIUM", "Spying", "Keyboard hooks", "SetWindowsHookEx together with key-state functions – can record keystrokes system-wide.", fileName); }
    if (T.has("W_URLDOWNLOAD")) addF("WIN_URLDOWNLOAD", "MEDIUM", "Download", "Downloads files directly to disk", "URLDownloadToFile saves a file from the internet in one call – popular with droppers.", fileName);
    if (T.has("W_WINEXEC")) addF("WIN_WINEXEC", "LOW", "Execution", "Uses WinExec", "Legacy API to run commands, rarely used by modern legit software but common in droppers.", fileName);
    if (T.has("W_ANTIDEBUG")) addF("WIN_ANTIDEBUG", "LOW", "Evasion", "Debugger detection", "Checks whether it is being debugged – often used to hide behaviour from analysts.", fileName);
    if (T.has("W_WEBCAM")) addF("WIN_WEBCAM", "HIGH", "Spying", "Webcam capture", "Imports the Video-for-Windows capture API – can take webcam pictures.", fileName);
    if (T.has("W_REGWRITE") && T.has("S_PERSIST")) tag(holder, "EXEC", T.get("W_REGWRITE"));
    for (const [t, e] of holder.tags) S.tagJar(t, e);
    return info;
  }
  function scriptType(n) {
    if (/\.(bat|cmd)$/.test(n)) return "Batch script"; if (/\.psm?1$/.test(n)) return "PowerShell script"; if (/\.vb[se]$/.test(n)) return "VBScript";
    if (/\.[mc]?js$/.test(n)) return "JavaScript"; if (/\.pyw?$/.test(n)) return "Python script"; if (/\.(sh|command)$/.test(n)) return "Shell script";
    if (n.endsWith(".hta")) return "HTML application (HTA)"; return "Text file";
  }
  function parsePe(S, d, info, holder, addF) {
    const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
    try {
      const pe = dv.getUint32(0x3c, true);
      if (pe <= 0 || pe + 24 > d.length || dv.getUint32(pe, true) !== 0x4550) { info.format = "MZ (no valid PE header)"; return; }
      const machine = dv.getUint16(pe + 4, true), nSec = dv.getUint16(pe + 6, true), ts = dv.getUint32(pe + 8, true), optSize = dv.getUint16(pe + 20, true), chars = dv.getUint16(pe + 22, true);
      const opt = pe + 24, pe64 = dv.getUint16(opt, true) === 0x20b, subsystem = dv.getUint16(opt + 68, true), ddBase = opt + (pe64 ? 112 : 96);
      info.format = chars & 0x2000 ? "PE DLL" : "PE executable";
      info.arch = machine === 0x14c ? "x86 (32-bit)" : machine === 0x8664 ? "x64" : machine === 0xaa64 ? "ARM64" : "0x" + machine.toString(16);
      info.subsystem = subsystem === 2 ? "GUI" : subsystem === 3 ? "Console" : String(subsystem);
      info.compiled = ts ? new Date(ts * 1000).toISOString() : "unknown";
      if (ts * 1000 > Date.now() + 86400000) info.notes.push("Timestamp in the future (faked)");
      const secs = [], secList = [];
      let sh = opt + optSize, lastRaw = 0;
      for (let i = 0; i < nSec && i < 96; i++) {
        const o = sh + i * 40; if (o + 40 > d.length) break;
        const name = latin.decode(d.subarray(o, o + 8)).replace(/\0/g, "");
        const vsize = dv.getUint32(o + 8, true), va = dv.getUint32(o + 12, true), rsize = dv.getUint32(o + 16, true), rptr = dv.getUint32(o + 20, true);
        secs.push([va, Math.max(vsize, rsize), rptr]); lastRaw = Math.max(lastRaw, rptr + rsize);
        const ent = rsize > 0 && rptr + rsize <= d.length ? entropy(d.subarray(rptr, rptr + rsize)) : 0;
        secList.push({ name, size: rsize, entropy: Math.round(ent * 100) / 100 });
        const n = name.toLowerCase();
        const note = s => { if (!info.notes.includes(s)) info.notes.push(s); };
        if (n.startsWith("upx")) note("UPX packed"); if (n.includes("themida") || n.includes("winlice")) note("Themida/WinLicense"); if (n.startsWith(".vmp")) note("VMProtect");
        if (n.includes("enigma")) note("Enigma Protector"); if (n.includes("aspack") || n.includes("adata")) note("ASPack"); if (n.includes("mpress")) note("MPRESS");
        if (ent > 7.4 && rsize > 4096 && n !== ".rsrc") note("High-entropy section (packed/encrypted code)");
      }
      info.sections = secList;
      if (lastRaw > 0 && lastRaw < d.length) info.overlay = d.length - lastRaw;
      const rva = r => { if (r <= 0) return -1; for (const [va, sz, raw] of secs) if (r >= va && r < va + sz) return raw + (r - va); return -1; };
      const cstr = off => { if (off < 0 || off >= d.length) return null; let e = off; while (e < d.length && d[e] !== 0 && e - off < 256) e++; const s = latin.decode(d.subarray(off, e)); return s && /^[\x20-\x7e]+$/.test(s) ? s : null; };
      const imports = {}; let total = 0;
      const impOff = rva(dv.getUint32(ddBase + 8, true));
      if (impOff > 0) for (let i = 0; i < 512; i++) {
        const o = impOff + i * 20; if (o + 20 > d.length) break;
        const oft = dv.getUint32(o, true), nameRva = dv.getUint32(o + 12, true), ft = dv.getUint32(o + 16, true);
        if (!oft && !nameRva && !ft) break;
        const dll = cstr(rva(nameRva)); if (!dll) break;
        const fns = [];
        let th = rva(oft || ft);
        for (let k = 0; th > 0 && k < 4000; k++) {
          const to = th + k * (pe64 ? 8 : 4); if (to + 8 > d.length) break;
          const lo = dv.getUint32(to, true), hi = pe64 ? dv.getUint32(to + 4, true) : 0;
          if (!lo && !hi) break;
          if ((pe64 && (hi & 0x80000000)) || (!pe64 && (lo & 0x80000000))) { fns.push("#" + (lo & 0xffff)); continue; }
          const fn = cstr(rva(lo) + 2); if (!fn) break;
          fns.push(fn); total++;
          if (IMPORT_TAGS[fn]) tag(holder, IMPORT_TAGS[fn], ev(null, 0, dll + "!" + fn, fn));
        }
        imports[dll] = fns.slice(0, 60);
      }
      info.importCount = total; info.imports = imports;
      const allFns = new Set(Object.values(imports).flat());
      info.capabilities = IMPORT_CAPS.filter(([k]) => k.split("|").some(f => allFns.has(f))).map(([, v]) => v);
      if (total < 8 && Object.keys(imports).length) info.notes.push("Very few imports (APIs are resolved at runtime – packer/loader)");
      if (dv.getUint32(ddBase + 14 * 8, true)) { info.notes.push(".NET assembly"); S.type = "Windows .NET program"; }
      if (info.notes.some(n => /^(UPX|Themida|VMProtect|Enigma|MPRESS|ASPack)/.test(n))) addF("PACKED_BINARY", "MEDIUM", "Packing", "Packed / protected program", "The program is compressed or protected with " + info.notes.join(", ") + ". The real code is only unpacked at runtime, so static scans see very little. Very common for malware.");
    } catch (e) { info.notes.push("Malformed PE header"); }
  }

  /* ---------------- deobfuscation: sandboxed bytecode emulator ----------------
     Re-computes string decryption routines of obfuscators. It only knows pure
     arithmetic, arrays and a whitelist of side-effect-free String/StringBuilder/
     Base64/Integer functions. Anything else (files, network, reflection, threads,
     class loading, unknown objects) aborts the emulation. Nothing of the file is
     ever run by the JVM or the browser. */
  class Abort extends Error {}
  const abort = why => { throw new Abort(why || "unsupported"); };
  const DEOBF = { steps: 2000000, depth: 14, arr: 1 << 20 };

  function parseDesc(desc) {
    const args = []; let i = 1;
    while (desc[i] !== ")") {
      const st = i;
      while (desc[i] === "[") i++;
      if (desc[i] === "L") i = desc.indexOf(";", i);
      i++;
      args.push(desc.slice(st, i));
    }
    return { args, ret: desc.slice(i + 1) };
  }
  function decodeFull(C, m) {
    const { b, dv } = C, base = m.codeOff, end = m.codeLen, out = [], byPc = new Map();
    const lineAt = new Map(); if (m.lines) for (const [pc, ln] of m.lines) lineAt.set(pc, ln);
    let i = 0, line = 0;
    while (i < end) {
      const pc = i, op = b[base + i];
      if (lineAt.has(pc)) line = lineAt.get(pc);
      const ins = { op, pc, line, len: 1 };
      if (op === 0xaa) {
        const q = (i + 4) & ~3, def = dv.getInt32(base + q), lo = dv.getInt32(base + q + 4), hi = dv.getInt32(base + q + 8);
        if (hi - lo > 65535 || hi < lo) abort("bad switch");
        ins.def = pc + def; ins.lo = lo; ins.tab = [];
        for (let k = 0; k <= hi - lo; k++) ins.tab.push(pc + dv.getInt32(base + q + 12 + k * 4));
        ins.len = q + 12 + (hi - lo + 1) * 4 - i;
      } else if (op === 0xab) {
        const q = (i + 4) & ~3, def = dv.getInt32(base + q), np = dv.getInt32(base + q + 4);
        if (np < 0 || np > 65535) abort("bad switch");
        ins.def = pc + def; ins.map = new Map();
        for (let k = 0; k < np; k++) ins.map.set(dv.getInt32(base + q + 8 + k * 8), pc + dv.getInt32(base + q + 12 + k * 8));
        ins.len = q + 8 + np * 8 - i;
      } else if (op === 0xc4) {
        const w = b[base + i + 1]; ins.op = w; ins.v = dv.getUint16(base + i + 2);
        if (w === 0x84) { ins.inc = dv.getInt16(base + i + 4); ins.len = 6; } else ins.len = 4;
      } else {
        const l = OPLEN[op];
        ins.len = 1 + l;
        if (op === 0x10) ins.v = dv.getInt8(base + i + 1);
        else if (op === 0x11) ins.v = dv.getInt16(base + i + 1);
        else if (op === 0x84) { ins.v = b[base + i + 1]; ins.inc = dv.getInt8(base + i + 2); }
        else if ((op >= 0x99 && op <= 0xa8) || op === 0xc6 || op === 0xc7) ins.v = pc + dv.getInt16(base + i + 1);
        else if (op === 0xc8 || op === 0xc9) ins.v = pc + dv.getInt32(base + i + 1);
        else if (op === 0xc5) { ins.v = dv.getUint16(base + i + 1); ins.dims = b[base + i + 3]; }
        else if (l === 1) ins.v = b[base + i + 1];
        else if (l >= 2) ins.v = dv.getUint16(base + i + 1);
      }
      byPc.set(pc, out.length);
      out.push(ins);
      i += ins.len;
    }
    return { insns: out, byPc };
  }

  const isWide = v => typeof v === "bigint" || (v !== null && typeof v === "object" && v.D !== undefined);
  const jstr = (v, t) => {
    if (typeof v === "string") return v;
    if (v === null) return "null";
    if (t === "C") return String.fromCharCode(v & 0xffff);
    if (t === "Z") return v ? "true" : "false";
    if (typeof v === "number") return String(v | 0);
    if (typeof v === "bigint") return v.toString();
    if (v.D !== undefined || v.F !== undefined) { const x = v.D !== undefined ? v.D : v.F; return Number.isFinite(x) && Number.isInteger(x) ? x.toFixed(1) : String(x); }
    if (v.SB) return v.s;
    if (v.BOX) return jstr(v.v, v.BOX);
    if (v.CLASS) return "class " + v.CLASS.replace(/\//g, ".");
    abort("toString of object");
  };
  const javaHash = s => { let h = 0; for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0; return h; };
  const charsetOf = v => {
    const n = (typeof v === "string" ? v : v && v.CS ? v.CS : "").toLowerCase().replace(/_/g, "-");
    if (n === "utf-8" || n === "utf8") return "utf-8";
    if (n === "iso-8859-1" || n === "latin1" || n === "us-ascii" || n === "ascii") return "latin1";
    if (n === "utf-16le" || n === "utf-16be" || n === "utf-16") return n;
    abort("charset " + n);
  };
  const enc8 = new TextEncoder();
  function bytesToStr(arr, off, len, cs) {
    const u = new Uint8Array(arr.data.buffer, arr.data.byteOffset + off, len);
    if (cs === "latin1") { let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return s; }
    if (cs === "utf-16be") { let s = ""; for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode((u[i] << 8) | u[i + 1]); return s; }
    if (cs === "utf-16le") { let s = ""; for (let i = 0; i + 1 < u.length; i += 2) s += String.fromCharCode(u[i] | (u[i + 1] << 8)); return s; }
    return td.decode(u);
  }
  function strToBytes(s, cs) {
    let u;
    if (cs === "latin1") { u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) < 256 ? s.charCodeAt(i) : 63; }
    else if (cs === "utf-16be" || cs === "utf-16le") { u = new Uint8Array(s.length * 2); for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); u[i * 2] = cs === "utf-16be" ? c >> 8 : c & 255; u[i * 2 + 1] = cs === "utf-16be" ? c & 255 : c >> 8; } }
    else u = enc8.encode(s);
    return { A: "B", data: new Int8Array(u.buffer, u.byteOffset, u.length) };
  }
  const newArr = (t, n) => {
    if (typeof n !== "number" || n < 0 || n > DEOBF.arr) abort("array size");
    const data = t === "C" ? new Uint16Array(n) : t === "B" || t === "Z" ? new Int8Array(n) : t === "S" ? new Int16Array(n) : t === "I" ? new Int32Array(n) : t === "J" ? new BigInt64Array(n) : t === "F" || t === "D" ? new Float64Array(n) : new Array(n).fill(null);
    return { A: t, data };
  };
  const ATYPE = { 4: "Z", 5: "C", 6: "F", 7: "D", 8: "B", 9: "S", 10: "I", 11: "J" };
  const b64std = s => {
    const clean = s.replace(/[\s]/g, "").replace(/-/g, "+").replace(/_/g, "/");
    let bin; try { bin = atob(clean + "===".slice((clean.length + 3) % 4)); } catch (e) { abort("bad base64"); }
    const u = new Int8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return { A: "B", data: u };
  };
  const int = v => { if (typeof v !== "number") abort("int expected"); return v | 0; };
  const str = v => { if (typeof v !== "string") abort(v === null ? "null string" : "string expected"); return v; };
  const arrOf = (v, t) => { if (!v || !v.A || (t && v.A !== t)) abort("array expected"); return v; };
  const charsOf = (a, off, len) => { let s = ""; const d = a.data; for (let i = off; i < off + len; i++) s += String.fromCharCode(d[i] & 0xffff); return s; };
  const toCharArr = s => { const a = newArr("C", s.length); for (let i = 0; i < s.length; i++) a.data[i] = s.charCodeAt(i); return a; };

  function stringMethod(s, name, desc, a) {
    switch (name) {
      case "length": return s.length;
      case "charAt": { const i = int(a[0]); if (i < 0 || i >= s.length) abort("index"); return s.charCodeAt(i); }
      case "codePointAt": { const i = int(a[0]); if (i < 0 || i >= s.length) abort("index"); return s.codePointAt(i); }
      case "toCharArray": return toCharArr(s);
      case "getBytes": return strToBytes(s, a.length ? charsetOf(a[0]) : "utf-8");
      case "substring": { const st = int(a[0]), en = a.length > 1 ? int(a[1]) : s.length; if (st < 0 || en > s.length || st > en) abort("index"); return s.substring(st, en); }
      case "subSequence": { const st = int(a[0]), en = int(a[1]); if (st < 0 || en > s.length || st > en) abort("index"); return s.substring(st, en); }
      case "indexOf": return desc.startsWith("(I") ? s.indexOf(String.fromCharCode(int(a[0])), a.length > 1 ? int(a[1]) : 0) : s.indexOf(str(a[0]), a.length > 1 ? int(a[1]) : 0);
      case "lastIndexOf": return desc.startsWith("(I") ? s.lastIndexOf(String.fromCharCode(int(a[0]))) : s.lastIndexOf(str(a[0]));
      case "equals": return typeof a[0] === "string" && a[0] === s ? 1 : 0;
      case "equalsIgnoreCase": return typeof a[0] === "string" && a[0].toLowerCase() === s.toLowerCase() ? 1 : 0;
      case "hashCode": return javaHash(s);
      case "intern": case "toString": case "strip": return name === "strip" ? s.trim() : s;
      case "trim": return s.replace(/^[\u0000- ]+|[\u0000- ]+$/g, "");
      case "isEmpty": return s.length === 0 ? 1 : 0;
      case "concat": return s + str(a[0]);
      case "contains": return s.includes(jstr(a[0])) ? 1 : 0;
      case "startsWith": return s.startsWith(str(a[0]), a.length > 1 ? int(a[1]) : 0) ? 1 : 0;
      case "endsWith": return s.endsWith(str(a[0])) ? 1 : 0;
      case "toUpperCase": return s.toUpperCase();
      case "toLowerCase": return s.toLowerCase();
      case "compareTo": { const o = str(a[0]); const n = Math.min(s.length, o.length); for (let i = 0; i < n; i++) if (s.charCodeAt(i) !== o.charCodeAt(i)) return s.charCodeAt(i) - o.charCodeAt(i); return s.length - o.length; }
      case "replace": return desc.startsWith("(CC") ? s.split(String.fromCharCode(int(a[0]))).join(String.fromCharCode(int(a[1]))) : s.split(jstr(a[0])).join(jstr(a[1]));
      case "repeat": { const n = int(a[0]); if (n < 0 || n * s.length > DEOBF.arr) abort("repeat"); return s.repeat(n); }
      case "chars": abort("streams");
    }
    abort("String." + name);
  }
  function sbMethod(o, name, desc, a) {
    switch (name) {
      case "append": {
        const t = parseDesc(desc).args[0];
        if (t === "[C") { const ar = arrOf(a[0], "C"); o.s += a.length > 1 ? charsOf(ar, int(a[1]), int(a[2])) : charsOf(ar, 0, ar.data.length); }
        else if (t === "Ljava/lang/CharSequence;" && a.length === 3) o.s += jstr(a[0]).substring(int(a[1]), int(a[2]));
        else o.s += jstr(a[0], t);
        if (o.s.length > DEOBF.arr) abort("too long");
        return o;
      }
      case "toString": return o.s;
      case "length": return o.s.length;
      case "charAt": { const i = int(a[0]); if (i < 0 || i >= o.s.length) abort("index"); return o.s.charCodeAt(i); }
      case "reverse": o.s = [...o.s].reverse().join(""); return o;
      case "setCharAt": { const i = int(a[0]); if (i < 0 || i >= o.s.length) abort("index"); o.s = o.s.slice(0, i) + String.fromCharCode(int(a[1]) & 0xffff) + o.s.slice(i + 1); return undefined; }
      case "deleteCharAt": { const i = int(a[0]); if (i < 0 || i >= o.s.length) abort("index"); o.s = o.s.slice(0, i) + o.s.slice(i + 1); return o; }
      case "insert": { const i = int(a[0]); const t = parseDesc(desc).args[1]; if (i < 0 || i > o.s.length) abort("index"); o.s = o.s.slice(0, i) + jstr(a[1], t) + o.s.slice(i); return o; }
      case "setLength": { const n = int(a[0]); o.s = n <= o.s.length ? o.s.slice(0, n) : o.s + "\0".repeat(n - o.s.length); return undefined; }
      case "indexOf": return o.s.indexOf(str(a[0]));
      case "substring": return o.s.substring(int(a[0]), a.length > 1 ? int(a[1]) : o.s.length);
      case "hashCode": abort("identity hash");
    }
    abort("StringBuilder." + name);
  }

  function makeEmulator(index, S) {
    const statics = new Map(), clinit = new Map();
    let steps = 0, tainted = false, inClinit = 0;
    const findMethod = (owner, name, desc) => {
      let o = owner;
      for (let k = 0; k < 12 && o; k++) {
        const c = index.classes.get(o);
        if (!c) return null;
        const m = c.byKey.get(name + desc);
        if (m) return { c, m };
        o = c.C.superName;
      }
      return null;
    };
    const fieldDefault = d => d === "J" ? 0n : d === "D" ? { D: 0 } : d === "F" ? { F: 0 } : "ZBCSI".includes(d) ? 0 : null;
    function ensureClinit(owner, depth, chain) {
      const st = clinit.get(owner);
      if (st) return;
      const c = index.classes.get(owner);
      if (!c) abort("class " + owner);
      const map = new Map();
      for (const f of c.C.fields) if (f.access & 0x0008) map.set(f.name, f.value != null ? f.value : f.cval !== undefined ? (f.desc === "D" ? { D: f.cval } : f.desc === "F" ? { F: f.cval } : f.cval) : fieldDefault(f.desc));
      statics.set(owner, map);
      clinit.set(owner, "running");
      const m = c.byKey.get("<clinit>()V");
      if (m) { inClinit++; try { run(c, m, [], depth + 1, chain); clinit.set(owner, "done"); } catch (e) { if (!(e instanceof Abort)) throw e; clinit.set(owner, "partial"); } finally { inClinit--; } }
      else clinit.set(owner, "done");
    }
    function getStatic(owner, name, desc, depth, chain) {
      if (owner === "java/nio/charset/StandardCharsets") return { CS: name.replace(/_/g, "-") };
      if (!index.classes.has(owner)) abort("static " + owner + "." + name);
      ensureClinit(owner, depth, chain);
      if (!inClinit) { const fd = index.classes.get(owner).C.fields.find(f => f.name === name); if (fd && !(fd.access & 0x0010) && !fd.desc.startsWith("[")) tainted = true; }
      const map = statics.get(owner);
      if (!map.has(name)) { const c = index.classes.get(owner); const sup = c && c.C.superName; if (sup && index.classes.has(sup)) return getStatic(sup, name, desc, depth, chain); abort("field " + name); }
      return map.get(name);
    }
    function native(owner, name, desc, args, recv, isStatic, frame) {
      if (!isStatic && recv === null) abort("null receiver");
      if (!isStatic && typeof recv === "string") return stringMethod(recv, name, desc, args);
      if (!isStatic && recv && recv.SB) return sbMethod(recv, name, desc, args);
      if (!isStatic && recv && recv.A) { if (name === "clone") { const a = newArr(recv.A, recv.data.length); a.data.set ? a.data.set(recv.data) : recv.data.forEach((x, i) => a.data[i] = x); return a; } if (name === "getClass") return { CLASS: "[" + recv.A }; abort("array." + name); }
      if (!isStatic && recv && recv.BOX) {
        if (/^(int|char|byte|short|long|boolean)Value$/.test(name)) { const v = recv.v; return name === "longValue" ? BigInt(v) : name === "byteValue" ? (v << 24) >> 24 : name === "shortValue" ? (v << 16) >> 16 : name === "charValue" ? v & 0xffff : v; }
        if (name === "toString") return jstr(recv.v, recv.BOX);
        if (name === "hashCode") return typeof recv.v === "number" ? recv.v : abort("hash");
        if (name === "equals") return args[0] && args[0].BOX === recv.BOX && args[0].v === recv.v ? 1 : 0;
        abort("box." + name);
      }
      if (!isStatic && recv && recv.B64) { if (name === "decode") return b64std(typeof args[0] === "string" ? args[0] : bytesToStr(arrOf(args[0], "B"), 0, args[0].data.length, "latin1")); abort("b64." + name); }
      if (!isStatic && recv && recv.B64E) { if (name === "encodeToString") { const a = arrOf(args[0], "B"); let bin = ""; for (const x of a.data) bin += String.fromCharCode(x & 255); return btoa(bin); } abort("b64e." + name); }
      if (!isStatic && recv && recv.CLASS) { if (name === "getName" || name === "getTypeName") return recv.CLASS.replace(/\//g, "."); if (name === "getSimpleName") return recv.CLASS.slice(recv.CLASS.lastIndexOf("/") + 1).replace(/^.*\$/, ""); abort("Class." + name); }
      if (!isStatic && recv && recv.CS) { if (name === "name" || name === "toString" || name === "displayName") return recv.CS.toUpperCase(); abort("charset." + name); }
      if (!isStatic && recv && (recv.THR || recv.THREAD)) {
        if (name === "getStackTrace") {
          const tr = recv.THREAD ? [{ cls: "java.lang.Thread", method: "getStackTrace" }, ...trace(frame)] : recv.trace;
          const a = newArr("L", tr.length); tr.forEach((t, i) => a.data[i] = { STE: t }); return a;
        }
        abort("thread." + name);
      }
      if (!isStatic && recv && recv.STE) { if (name === "getClassName") return recv.STE.cls; if (name === "getMethodName") return recv.STE.method; abort("ste." + name); }
      if (!isStatic && recv && recv.OBJ && name === "getClass") return { CLASS: recv.OBJ };
      switch (owner) {
        case "java/lang/String":
          if (name === "valueOf" || name === "copyValueOf") { const t = parseDesc(desc).args[0]; if (t === "[C") { const ar = arrOf(args[0], "C"); return args.length > 1 ? charsOf(ar, int(args[1]), int(args[2])) : charsOf(ar, 0, ar.data.length); } return jstr(args[0], t); }
          if (name === "join" || name === "format") abort("String." + name);
          break;
        case "java/lang/Integer": case "java/lang/Short": case "java/lang/Byte":
          if (name === "parseInt" || name === "valueOf" && desc.startsWith("(Ljava/lang/String;")) { const r = args.length > 1 ? int(args[1]) : 10; const v = parseInt(str(args[0]), r); if (Number.isNaN(v)) abort("nfe"); return name === "valueOf" ? { BOX: "I", v: v | 0 } : v | 0; }
          if (name === "valueOf") return { BOX: owner === "java/lang/Integer" ? "I" : owner === "java/lang/Short" ? "S" : "B", v: int(args[0]) };
          if (name === "toString") return args.length > 1 ? (int(args[0])).toString(int(args[1])) : String(int(args[0]));
          if (name === "toHexString") return (int(args[0]) >>> 0).toString(16);
          if (name === "toBinaryString") return (int(args[0]) >>> 0).toString(2);
          if (name === "rotateLeft") { const x = int(args[0]), d = int(args[1]) & 31; return (x << d) | (x >>> (32 - d)); }
          if (name === "rotateRight") { const x = int(args[0]), d = int(args[1]) & 31; return (x >>> d) | (x << (32 - d)); }
          if (name === "bitCount") { let x = int(args[0]) >>> 0, c = 0; while (x) { c += x & 1; x >>>= 1; } return c; }
          if (name === "reverse") { let x = int(args[0]) >>> 0, r = 0; for (let i = 0; i < 32; i++) { r = (r << 1) | (x & 1); x >>>= 1; } return r | 0; }
          if (name === "hashCode") return int(args[0]);
          break;
        case "java/lang/Long":
          if (name === "parseLong") { try { return BigInt.asIntN(64, BigInt(str(args[0]))); } catch (e) { abort("nfe"); } }
          if (name === "valueOf" && desc === "(J)Ljava/lang/Long;") return { BOX: "J", v: args[0] };
          if (name === "toString" && desc === "(J)Ljava/lang/String;") return args[0].toString();
          break;
        case "java/lang/Character":
          if (name === "valueOf") return { BOX: "C", v: int(args[0]) & 0xffff };
          if (name === "toUpperCase") return String.fromCharCode(int(args[0])).toUpperCase().charCodeAt(0);
          if (name === "toLowerCase") return String.fromCharCode(int(args[0])).toLowerCase().charCodeAt(0);
          if (name === "isDigit") return /\d/.test(String.fromCharCode(int(args[0]))) ? 1 : 0;
          if (name === "isLetter") return /\p{L}/u.test(String.fromCharCode(int(args[0]))) ? 1 : 0;
          if (name === "toString") return String.fromCharCode(int(args[0]));
          break;
        case "java/lang/Boolean":
          if (name === "valueOf" && desc === "(Z)Ljava/lang/Boolean;") return { BOX: "Z", v: int(args[0]) };
          break;
        case "java/lang/Math": case "java/lang/StrictMath":
          if (name === "abs") return desc === "(J)J" ? (args[0] < 0n ? BigInt.asIntN(64, -args[0]) : args[0]) : desc === "(I)I" ? Math.abs(int(args[0])) | 0 : abort("abs");
          if (name === "max" && desc === "(II)I") return Math.max(int(args[0]), int(args[1]));
          if (name === "min" && desc === "(II)I") return Math.min(int(args[0]), int(args[1]));
          if (name === "floorMod" && desc === "(II)I") { const y = int(args[1]); if (!y) abort("div0"); return ((int(args[0]) % y) + y) % y; }
          break;
        case "java/lang/System":
          if (name === "arraycopy") {
            const src = arrOf(args[0]), sp = int(args[1]), dst = arrOf(args[2]), dp = int(args[3]), n = int(args[4]);
            if (sp < 0 || dp < 0 || n < 0 || sp + n > src.data.length || dp + n > dst.data.length) abort("index");
            if (src.data.copyWithin && src === dst) dst.data.copyWithin(dp, sp, sp + n);
            else { const tmp = Array.from(src.data.slice(sp, sp + n)); for (let i = 0; i < n; i++) dst.data[dp + i] = tmp[i]; }
            return undefined;
          }
          break;
        case "java/util/Arrays":
          if (name === "copyOf" || name === "copyOfRange") {
            const a = arrOf(args[0]), from = name === "copyOf" ? 0 : int(args[1]), to = name === "copyOf" ? int(args[1]) : int(args[2]);
            if (from < 0 || to < from || from > a.data.length) abort("index");
            const r = newArr(a.A, to - from); for (let i = from; i < Math.min(to, a.data.length); i++) r.data[i - from] = a.data[i]; return r;
          }
          if (name === "fill" && args.length === 2) { arrOf(args[0]).data.fill(args[1]); return undefined; }
          break;
        case "java/util/Base64":
          if (name === "getDecoder" || name === "getMimeDecoder" || name === "getUrlDecoder") return { B64: name };
          if (name === "getEncoder") return { B64E: true };
          break;
        case "java/nio/charset/Charset":
          if (name === "forName") return { CS: charsetOf(str(args[0])) };
          if (name === "defaultCharset") return { CS: "utf-8" };
          break;
        case "java/lang/Thread":
          if (name === "currentThread") return { THREAD: true };
          break;
        case "java/lang/Object":
          if (name === "<init>") return undefined;
          break;
      }
      abort(owner + "." + name);
    }
    function trace(frame) {
      const out = [];
      for (let f = frame; f; f = f.parent) out.push({ cls: f.cls.replace(/\//g, "."), method: f.method });
      return out;
    }
    function construct(owner, desc, obj, args, frame) {
      const t = parseDesc(desc).args;
      switch (owner) {
        case "java/lang/String": {
          if (!t.length) return "";
          if (t[0] === "Ljava/lang/String;") return str(args[0]);
          if (t[0] === "[C") { const a = arrOf(args[0], "C"); return t.length >= 3 ? charsOf(a, int(args[1]), int(args[2])) : charsOf(a, 0, a.data.length); }
          if (t[0] === "[B") { const a = arrOf(args[0], "B"); const csArg = t.length === 2 ? args[1] : t.length === 4 ? args[3] : null; const off = t.length >= 3 ? int(args[1]) : 0, len = t.length >= 3 ? int(args[2]) : a.data.length; if (off < 0 || len < 0 || off + len > a.data.length) abort("index"); return bytesToStr(a, off, len, csArg ? charsetOf(csArg) : "utf-8"); }
          if (t[0] === "Ljava/lang/StringBuilder;" || t[0] === "Ljava/lang/StringBuffer;") return args[0].s;
          abort("String<init>");
        }
        case "java/lang/StringBuilder": case "java/lang/StringBuffer":
          obj.SB = true; obj.s = t.length && t[0] !== "I" ? jstr(args[0]) : ""; return obj;
        case "java/lang/Object": obj.OBJ = "java/lang/Object"; return obj;
        case "java/lang/Throwable": case "java/lang/Exception": case "java/lang/RuntimeException": case "java/lang/Error":
          if (t.length) abort("throwable args");
          obj.THR = true; obj.trace = trace(frame); return obj;
        case "java/lang/Integer": obj.BOX = "I"; obj.v = int(args[0]); return obj;
      }
      abort("new " + owner);
    }

    function run(c, m, args, depth, parent) {
      if (depth > DEOBF.depth) abort("depth");
      if (!m.codeLen) abort("no code");
      if (m.access & 0x0100) abort("native");
      const C = c.C;
      if (!m.dec) m.dec = decodeFull(C, m);
      const { insns, byPc } = m.dec;
      const frame = { cls: C.name, method: m.name, parent };
      const locals = new Array(Math.max(m.maxLocals, 1)).fill(undefined);
      { let k = 0; const types = parseDesc(m.desc).args; if (!(m.access & 0x0008) && m.name !== "<clinit>") abort("instance method"); types.forEach((t, i) => { locals[k] = args[i]; k += t === "J" || t === "D" ? 2 : 1; }); }
      const st = [];
      const pop = () => { if (!st.length) abort("stack underflow"); return st.pop(); };
      const jump = target => { const j = byPc.get(target); if (j === undefined) abort("bad jump"); return j; };
      let i = 0;
      for (;;) {
        if (++steps > DEOBF.steps) abort("step limit");
        const ins = insns[i];
        if (!ins) abort("fell off");
        const op = ins.op;
        let next = i + 1;
        switch (true) {
          case op === 0x00: break;
          case op === 0x01: st.push(null); break;
          case op >= 0x02 && op <= 0x08: st.push(op - 3); break;
          case op === 0x09 || op === 0x0a: st.push(BigInt(op - 9)); break;
          case op >= 0x0b && op <= 0x0d: st.push({ F: op - 0x0b }); break;
          case op === 0x0e || op === 0x0f: st.push({ D: op - 0x0e }); break;
          case op === 0x10 || op === 0x11: st.push(ins.v); break;
          case op >= 0x12 && op <= 0x14: {
            const k = C.cp[ins.v]; if (!k) abort("cp");
            if (k.t === 3) st.push(k.v); else if (k.t === 4) st.push({ F: k.v }); else if (k.t === 5) st.push(k.v); else if (k.t === 6) st.push({ D: k.v });
            else if (k.t === 8) st.push(C.utf(k.a)); else if (k.t === 7) st.push({ CLASS: C.utf(k.a) }); else abort("ldc");
            break;
          }
          case op >= 0x15 && op <= 0x19: st.push(locals[ins.v]); break;
          case op >= 0x1a && op <= 0x2d: st.push(locals[(op - 0x1a) & 3]); break;
          case op >= 0x2e && op <= 0x35: {
            const ix = int(pop()), a = arrOf(pop());
            if (ix < 0 || ix >= a.data.length) abort("index");
            const v = a.data[ix];
            st.push(op === 0x30 ? { F: v } : op === 0x31 ? { D: v } : v);
            break;
          }
          case op >= 0x36 && op <= 0x3a: locals[ins.v] = pop(); break;
          case op >= 0x3b && op <= 0x4e: locals[(op - 0x3b) & 3] = pop(); break;
          case op >= 0x4f && op <= 0x56: {
            let v = pop(); const ix = int(pop()), a = arrOf(pop());
            if (ix < 0 || ix >= a.data.length) abort("index");
            if (op === 0x51 || op === 0x52) v = v.F !== undefined ? v.F : v.D;
            if (op === 0x50 && typeof v !== "bigint") abort("long");
            a.data[ix] = v;
            break;
          }
          case op === 0x57: pop(); break;
          case op === 0x58: { const v = pop(); if (!isWide(v)) pop(); break; }
          case op === 0x59: { const v = pop(); st.push(v, v); break; }
          case op === 0x5a: { const a = pop(), b = pop(); st.push(a, b, a); break; }
          case op === 0x5b: { const a = pop(), b = pop(); if (isWide(b)) st.push(a, b, a); else { const c3 = pop(); st.push(a, c3, b, a); } break; }
          case op === 0x5c: { const a = pop(); if (isWide(a)) st.push(a, a); else { const b = pop(); st.push(b, a, b, a); } break; }
          case op === 0x5d: { const a = pop(); if (isWide(a)) { const b = pop(); st.push(a, b, a); } else { const b = pop(), c3 = pop(); st.push(b, a, c3, b, a); } break; }
          case op === 0x5e: abort("dup2_x2");
          case op === 0x5f: { const a = pop(), b = pop(); st.push(a, b); break; }
          case op >= 0x60 && op <= 0x83: {
            const kind = op >= 0x78 ? (op - 0x78) & 1 : (op - 0x60) & 3, grp = op >= 0x78 ? 6 + ((op - 0x78) >> 1) : (op - 0x60) >> 2;
            if (grp === 5) {
              const x = pop();
              st.push(kind === 0 ? (-int(x)) | 0 : kind === 1 ? BigInt.asIntN(64, -x) : kind === 2 ? { F: -x.F } : { D: -x.D });
              break;
            }
            const y = pop(), x = pop();
            if (kind === 0) {
              const a = int(x), b = int(y); let r;
              switch (grp) {
                case 0: r = (a + b) | 0; break; case 1: r = (a - b) | 0; break; case 2: r = Math.imul(a, b); break;
                case 3: if (!b) abort("div0"); r = (a / b) | 0; break; case 4: if (!b) abort("div0"); r = (a % b) | 0; break;
                case 6: r = a << (b & 31); break; case 7: r = a >> (b & 31); break; case 8: r = (a >>> (b & 31)) | 0; break;
                case 9: r = a & b; break; case 10: r = a | b; break; case 11: r = a ^ b; break;
              }
              st.push(r);
            } else if (kind === 1) {
              let r;
              if (grp >= 6 && grp <= 8) { const sh = BigInt(int(y) & 63); r = grp === 6 ? x << sh : grp === 7 ? x >> sh : BigInt.asUintN(64, x) >> sh; }
              else { if (typeof x !== "bigint" || typeof y !== "bigint") abort("long");
                switch (grp) { case 0: r = x + y; break; case 1: r = x - y; break; case 2: r = x * y; break; case 3: if (!y) abort("div0"); r = x / y; break; case 4: if (!y) abort("div0"); r = x % y; break; case 9: r = x & y; break; case 10: r = x | y; break; case 11: r = x ^ y; break; } }
              st.push(BigInt.asIntN(64, r));
            } else {
              const a = kind === 2 ? x.F : x.D, b = kind === 2 ? y.F : y.D; if (a === undefined || b === undefined) abort("fp");
              let r; switch (grp) { case 0: r = a + b; break; case 1: r = a - b; break; case 2: r = a * b; break; case 3: r = a / b; break; case 4: r = a % b; break; default: abort("fp op"); }
              st.push(kind === 2 ? { F: Math.fround(r) } : { D: r });
            }
            break;
          }
          case op === 0x84: locals[ins.v] = (int(locals[ins.v]) + ins.inc) | 0; break;
          case op >= 0x85 && op <= 0x93: {
            const x = pop(); let r;
            const fv = v => v.F !== undefined ? v.F : v.D;
            const toInt = f => Number.isNaN(f) ? 0 : f >= 2147483647 ? 2147483647 : f <= -2147483648 ? -2147483648 : Math.trunc(f);
            const toLong = f => Number.isNaN(f) ? 0n : f >= 9.223372036854776e18 ? 9223372036854775807n : f <= -9.223372036854776e18 ? -9223372036854775808n : BigInt(Math.trunc(f));
            switch (op) {
              case 0x85: r = BigInt(int(x)); break; case 0x86: r = { F: Math.fround(int(x)) }; break; case 0x87: r = { D: int(x) }; break;
              case 0x88: r = Number(BigInt.asIntN(32, x)); break; case 0x89: r = { F: Math.fround(Number(x)) }; break; case 0x8a: r = { D: Number(x) }; break;
              case 0x8b: case 0x8e: r = toInt(fv(x)); break; case 0x8c: case 0x8f: r = toLong(fv(x)); break;
              case 0x8d: r = { D: x.F }; break; case 0x90: r = { F: Math.fround(x.D) }; break;
              case 0x91: r = (int(x) << 24) >> 24; break; case 0x92: r = int(x) & 0xffff; break; case 0x93: r = (int(x) << 16) >> 16; break;
            }
            st.push(r);
            break;
          }
          case op === 0x94: { const y = pop(), x = pop(); st.push(x > y ? 1 : x < y ? -1 : 0); break; }
          case op >= 0x95 && op <= 0x98: { const y = pop(), x = pop(); const a = x.F !== undefined ? x.F : x.D, b = y.F !== undefined ? y.F : y.D; st.push(Number.isNaN(a) || Number.isNaN(b) ? (op === 0x95 || op === 0x97 ? -1 : 1) : a > b ? 1 : a < b ? -1 : 0); break; }
          case op >= 0x99 && op <= 0x9e: {
            const v = int(pop());
            const t = [v === 0, v !== 0, v < 0, v >= 0, v > 0, v <= 0][op - 0x99];
            if (t) next = jump(ins.v);
            break;
          }
          case op >= 0x9f && op <= 0xa4: {
            const b = int(pop()), a = int(pop());
            const t = [a === b, a !== b, a < b, a >= b, a > b, a <= b][op - 0x9f];
            if (t) next = jump(ins.v);
            break;
          }
          case op === 0xa5 || op === 0xa6: {
            const b = pop(), a = pop();
            const same = a === b && !(typeof a === "string" && typeof b === "string" && false);
            if ((op === 0xa5) === same) next = jump(ins.v);
            break;
          }
          case op === 0xa7 || op === 0xc8: next = jump(ins.v); break;
          case op === 0xaa: { const v = int(pop()); const k = v - ins.lo; next = jump(k >= 0 && k < ins.tab.length ? ins.tab[k] : ins.def); break; }
          case op === 0xab: { const v = int(pop()); next = jump(ins.map.has(v) ? ins.map.get(v) : ins.def); break; }
          case op >= 0xac && op <= 0xb0: return pop();
          case op === 0xb1: return undefined;
          case op === 0xb2: { const r = memberRef(C, ins.v); st.push(getStatic(r.owner, r.name, r.desc, depth, frame)); break; }
          case op === 0xb3: {
            const r = memberRef(C, ins.v), v = pop();
            if (!index.classes.has(r.owner)) abort("putstatic " + r.owner);
            if (r.owner !== C.name) ensureClinit(r.owner, depth, frame);
            if (!statics.has(r.owner)) statics.set(r.owner, new Map());
            statics.get(r.owner).set(r.name, v);
            break;
          }
          case op === 0xb4 || op === 0xb5: abort("instance field");
          case op >= 0xb6 && op <= 0xb9: {
            const r = memberRef(C, ins.v);
            const pd = parseDesc(r.desc);
            const args2 = new Array(pd.args.length);
            for (let k = pd.args.length - 1; k >= 0; k--) args2[k] = pop();
            const isStatic = op === 0xb8;
            const recv = isStatic ? undefined : pop();
            let res;
            if (op === 0xb7 && r.name === "<init>") {
              if (!recv || typeof recv !== "object" || !recv.NEW) abort("init target");
              const owner = recv.NEW;
              if (index.classes.has(owner)) abort("new own class");
              const made = construct(owner, r.desc, recv, args2, frame);
              delete recv.NEW;
              if (made !== recv) {
                for (let k = 0; k < st.length; k++) if (st[k] === recv) st[k] = made;
                for (let k = 0; k < locals.length; k++) if (locals[k] === recv) locals[k] = made;
              }
              break;
            }
            if (isStatic && index.classes.has(r.owner)) {
              const tgt = findMethod(r.owner, r.name, r.desc);
              if (!tgt) abort("missing " + r.owner + "." + r.name);
              ensureClinit(tgt.c.C.name, depth, frame);
              res = run(tgt.c, tgt.m, args2, depth + 1, frame);
            } else res = native(r.owner, r.name, r.desc, args2, recv, isStatic, frame);
            if (pd.ret !== "V") {
              if (res === undefined) abort("void result");
              st.push(pd.ret === "Z" && typeof res === "boolean" ? (res ? 1 : 0) : res);
            }
            break;
          }
          case op === 0xba: {
            const ref = C.cp[ins.v]; const nt = ref && C.cp[ref.b];
            const bsm = ref ? C.bsms[ref.a] : null;
            if (!bsm || !nt || bsm.owner !== "java/lang/invoke/StringConcatFactory") abort("indy");
            const name = C.utf(nt.a), desc = C.utf(nt.b), pd = parseDesc(desc);
            const a = new Array(pd.args.length); for (let k = pd.args.length - 1; k >= 0; k--) a[k] = pop();
            if (name === "makeConcatWithConstants") {
              const recipe = bsm.args[0] || ""; let out = "", ai = 0, ci = 1;
              for (const ch of recipe) { if (ch === "\u0001") { out += jstr(a[ai], pd.args[ai]); ai++; } else if (ch === "\u0002") out += bsm.args[ci++] ?? abort("indy const"); else out += ch; }
              st.push(out);
            } else if (name === "makeConcat") st.push(a.map((v, k) => jstr(v, pd.args[k])).join(""));
            else abort("indy " + name);
            break;
          }
          case op === 0xbb: { const cn = C.cls(ins.v); st.push({ NEW: cn }); break; }
          case op === 0xbc: st.push(newArr(ATYPE[ins.v], int(pop()))); break;
          case op === 0xbd: st.push(newArr("L", int(pop()))); break;
          case op === 0xbe: st.push(arrOf(pop()).data.length); break;
          case op === 0xbf: abort("throw");
          case op === 0xc0: break;
          case op === 0xc1: {
            const v = pop(), t = C.cls(ins.v);
            if (v === null) st.push(0);
            else if (typeof v === "string") st.push(t === "java/lang/String" || t === "java/lang/CharSequence" || t === "java/lang/Object" ? 1 : 0);
            else abort("instanceof");
            break;
          }
          case op === 0xc2 || op === 0xc3: pop(); break;
          case op === 0xc6: if (pop() === null) next = jump(ins.v); break;
          case op === 0xc7: if (pop() !== null) next = jump(ins.v); break;
          default: abort("op " + op);
        }
        if (st.length > 512) abort("stack");
        i = next;
      }
    }
    return {
      call(target, args, caller) { steps = 0; tainted = false; const v = run(target.c, target.m, args, 0, caller); return tainted ? null : v; },
      field(owner, name, caller) { steps = 0; tainted = false; const v = getStatic(owner, name, "", 0, caller); return tainted ? null : v; },
      findMethod, ensureClinit: o => { steps = 0; ensureClinit(o, 0, null); }, state: o => clinit.get(o)
    };
  }

  function constValue(C, ins) {
    const op = ins.op;
    if (op === 0x01) return { v: null };
    if (op >= 0x02 && op <= 0x08) return { v: op - 3 };
    if (op === 0x09 || op === 0x0a) return { v: BigInt(op - 9) };
    if (op === 0x10 || op === 0x11) return { v: ins.v };
    if (op >= 0x12 && op <= 0x14) {
      const k = C.cp[ins.v]; if (!k) return null;
      if (k.t === 3 || k.t === 5) return { v: k.v };
      if (k.t === 4) return { v: { F: k.v } };
      if (k.t === 6) return { v: { D: k.v } };
      if (k.t === 8) return { v: C.utf(k.a) };
      if (k.t === 7) return { v: { CLASS: C.utf(k.a) } };
    }
    return null;
  }
  const goodText = s => typeof s === "string" && s.length > 0 && s.length <= 65535 && printableRatio(s) >= 0.75;

  /* Finds every call site / static read that produces a constant string and
     computes it with the emulator. Returns the decrypted strings and patch
     lists (byte ranges to replace with "ldc <string>") per class. */
  async function deobfuscate(S, progress = () => {}) {
    const index = { classes: new Map() };
    for (const c of S.containers) for (const [n, b] of c.classes) {
      if (index.classes.has(n)) continue;
      let C; try { C = parseClass(b); } catch (e) { continue; }
      const byKey = new Map(); for (const m of C.methods) byKey.set(m.name + m.desc, m);
      index.classes.set(n, { C, byKey, container: c.path });
    }
    const emu = makeEmulator(index, S);
    const plain = new Set();
    for (const c of index.classes.values()) for (const k of c.C.cp) if (k && k.t === 8) plain.add(c.C.utf(k.a));
    const cache = new Map(), results = [], patches = new Map(), decryptors = new Map();
    let sites = 0, solved = 0, done = 0;
    const total = index.classes.size;
    for (const [cn, c] of index.classes) {
      const C = c.C, edits = [];
      for (const m of C.methods) {
        if (!m.codeLen) continue;
        let dec;
        try { dec = decodeFull(C, m); } catch (e) { continue; }
        m.dec = dec;
        const { insns } = dec;
        const targets = new Set();
        for (const ins of insns) {
          if ((ins.op >= 0x99 && ins.op <= 0xa8) || ins.op === 0xc6 || ins.op === 0xc7 || ins.op === 0xc8) targets.add(ins.v);
          if (ins.def !== undefined) { targets.add(ins.def); (ins.tab || [...ins.map.values()]).forEach(t => targets.add(t)); }
        }
        for (const h of m.handlers) targets.add(h.handler);
        const caller = { cls: C.name, method: m.name, parent: null };
        const record = (k, startIdx, value, via, line) => {
          if (!goodText(value) || plain.has(value)) return;
          const first = insns[startIdx], last = insns[k];
          let ok = true;
          for (let q = startIdx + 1; q <= k; q++) if (targets.has(insns[q].pc)) { ok = false; break; }
          if (ok && last.pc + last.len - first.pc >= 3) edits.push({ start: m.codeOff + first.pc, end: m.codeOff + last.pc + last.len, value });
          results.push({ container: c.container, cls: cn, method: m.name + m.desc, line, value, via });
          solved++;
        };
        for (let k = 0; k < insns.length; k++) {
          const ins = insns[k];
          if (ins.op === 0xb8) {
            const r = memberRef(C, ins.v);
            if (!r || !r.desc.endsWith(")Ljava/lang/String;") || !index.classes.has(r.owner)) continue;
            const pd = parseDesc(r.desc);
            if (!pd.args.length) continue;
            if (pd.args.some(t => !/^(?:[ZBCSIJFD]|Ljava\/lang\/String;|Ljava\/lang\/Object;|\[[BC])$/.test(t))) continue;
            const n = pd.args.length;
            if (k < n) continue;
            const vals = []; let okc = true;
            for (let q = k - n; q < k; q++) { const cv = constValue(C, insns[q]); if (!cv) { okc = false; break; } vals.push(cv.v); }
            if (!okc) continue;
            const tgt = emu.findMethod(r.owner, r.name, r.desc);
            if (!tgt || (tgt.m.access & 0x0100)) continue;
            sites++;
            const key = r.owner + "." + r.name + r.desc + "|" + C.name + "." + m.name + "|" + vals.map(v => typeof v === "bigint" ? v + "n" : JSON.stringify(v)).join(",");
            let out = cache.get(key);
            if (out === undefined) {
              try { emu.ensureClinit(tgt.c.C.name); out = emu.call(tgt, vals, caller); } catch (e) { if (!(e instanceof Abort)) throw e; out = null; }
              cache.set(key, out);
            }
            if (typeof out === "string" && !plain.has(out)) {
              const dk = r.owner + "." + r.name + r.desc;
              decryptors.set(dk, (decryptors.get(dk) || 0) + 1);
              record(k, k - n, out, "call " + r.owner.replace(/\//g, ".") + "." + r.name, ins.line);
            }
          } else if (ins.op === 0xb2) {
            const r = memberRef(C, ins.v);
            if (!r || !index.classes.has(r.owner) || (r.desc !== "Ljava/lang/String;" && r.desc !== "[Ljava/lang/String;")) continue;
            const fld = index.classes.get(r.owner).C.fields.find(f => f.name === r.name);
            if (!fld || !(fld.access & 0x0010) || !(fld.access & 0x0008)) continue;
            if (m.name === "<clinit>" && r.owner === C.name) continue;
            let v;
            try { emu.ensureClinit(r.owner); v = emu.state(r.owner) ? emu.field(r.owner, r.name, caller) : undefined; } catch (e) { if (!(e instanceof Abort)) throw e; continue; }
            if (r.desc === "Ljava/lang/String;") {
              if (typeof v !== "string" || (fld.value != null && fld.value === v)) continue;
              sites++;
              record(k, k, v, "static " + r.owner.replace(/\//g, ".") + "." + r.name, ins.line);
            } else if (v && v.A === "L" && k + 2 < insns.length && insns[k + 2].op === 0x32) {
              const ix = constValue(C, insns[k + 1]);
              if (!ix || typeof ix.v !== "number" || ix.v < 0 || ix.v >= v.data.length) continue;
              const s2 = v.data[ix.v];
              if (typeof s2 !== "string") continue;
              sites++;
              record(k + 2, k, s2, "table " + r.owner.replace(/\//g, ".") + "." + r.name + "[" + ix.v + "]", ins.line);
            }
          }
        }
        m.dec = null;
      }
      if (edits.length) patches.set(cn, edits);
      if (++done % 50 === 0) { progress(done, total); await new Promise(r => setTimeout(r, 0)); }
    }
    for (const c of index.classes.values()) for (const m of c.C.methods) m.dec = null;
    progress(total, total);
    return { results, patches, sites, solved, decryptors: [...decryptors].map(([k, n]) => ({ method: k.replace(/\//g, "."), calls: n })) };
  }

  function mutf8Encode(s) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 1 && c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return out;
  }
  /* Rewrites a class so each decrypted call site becomes a plain "ldc" of the
     clear-text string (rest filled with NOP). Only used to feed the decompiler. */
  function patchClass(bytes, edits) {
    if (!edits || !edits.length) return bytes;
    let C; try { C = parseClass(bytes); } catch (e) { return bytes; }
    const add = [], idxOf = new Map();
    let next = C.cpCount;
    for (const e of edits) {
      if (idxOf.has(e.value)) continue;
      const u = mutf8Encode(e.value);
      if (u.length > 65535 || next + 2 > 65535) continue;
      add.push(1, u.length >> 8, u.length & 255, ...u, 8, next >> 8, next & 255);
      idxOf.set(e.value, next + 1);
      next += 2;
    }
    if (!add.length) return bytes;
    const out = new Uint8Array(bytes.length + add.length);
    out.set(bytes.subarray(0, C.cpEnd), 0);
    out.set(add, C.cpEnd);
    out.set(bytes.subarray(C.cpEnd), C.cpEnd + add.length);
    out[8] = next >> 8; out[9] = next & 255;
    const shift = add.length;
    const sorted = [...edits].sort((a, b) => a.start - b.start);
    let lastEnd = -1;
    for (const e of sorted) {
      const idx = idxOf.get(e.value);
      if (!idx || e.start < lastEnd) continue;
      const s0 = e.start + shift, e0 = e.end + shift;
      out[s0] = 0x13; out[s0 + 1] = idx >> 8; out[s0 + 2] = idx & 255;
      for (let q = s0 + 3; q < e0; q++) out[q] = 0x00;
      lastEnd = e.end;
    }
    return out;
  }

  /* Reads every line of decompiled source (port of SourceScanner). */
  const SRC_LITERAL = /"((?:[^"\\\n]|\\.)*)"/g, SRC_CONCAT = /"\s*\+\s*"/g, SRC_CODES = /new (?:byte|char)\[\]\s*\{([\d\s,\-()a-z']+)}/g;
  function srcUnescape(s) {
    if (!s.includes("\\")) return s;
    return s.replace(/\\(u[0-9a-fA-F]{4}|[0-7]{1,3}|.)/g, (m, x) => x[0] === "u" ? String.fromCharCode(parseInt(x.slice(1), 16)) : /^[0-7]/.test(x) ? String.fromCharCode(parseInt(x, 8)) : ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f" }[x] ?? x));
  }
  function scanSource(S, container, cls, source) {
    const ci = S.classes.get(container + "!" + cls);
    if (!ci) return 0;
    const tmp = newClass(ci.container, ci.name, ci.top, ci.library, ci.hidden, ci.entryPath);
    const lines = source.split("\n"), seen = new Set();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.includes('"') && !line.includes("new byte[]") && !line.includes("new char[]")) continue;
      const folded = line.replace(SRC_CONCAT, "");
      for (const m of folded.matchAll(SRC_LITERAL)) {
        const s = srcUnescape(m[1]);
        if (s.length < 3 || seen.has(s)) continue;
        seen.add(s);
        const probe = s.length > 24 ? s.slice(0, 24) : s;
        processString(tmp, s, ev(null, i + 1, s, line.includes(probe) ? probe : s.slice(0, 12)), "source", 0);
      }
      for (const m of line.matchAll(SRC_CODES)) {
        let r = "";
        for (const part of m[1].split(",")) {
          const p = part.trim().replace(/^\((byte|char)\)\s*/, "");
          if (!p) continue;
          const v = /^'.'$/.test(p) ? p.charCodeAt(1) : /^-?\d+$/.test(p) ? parseInt(p, 10) : NaN;
          if (Number.isNaN(v)) { r = null; break; }
          r += String.fromCharCode(v & 0xff);
        }
        if (r && r.length >= 4 && printableRatio(r) > 0.9 && !seen.has(r)) { seen.add(r); processString(tmp, r, ev(null, i + 1, r, "new "), "bytearray", 0); }
      }
    }
    for (const [t, e] of tmp.tags) tag(ci, t, e);
    const bases = new Set([...ci.findings.keys()].map(k => k.replace(/_(DECRYPTED|JOINED|BASE64|HEX|REVERSED|BYTEARRAY|RAW|SOURCE|LDC|INDY)$/, "")));
    for (const f of tmp.findings.values()) {
      if (ci.findings.has(f.rule) || bases.has(f.rule.replace(/_(DECRYPTED|JOINED|BASE64|HEX|REVERSED|BYTEARRAY|RAW|SOURCE|LDC|INDY)$/, ""))) continue;
      f.source = "decompiler"; f.title = f.title + " (Vineflower)"; f.library = ci.library; f.entrypoint = ci.entrypoint;
      f.java = true;
      ci.findings.set(f.rule, f);
    }
    return lines.length;
  }

  /* Adds what the deep scan found to the quick scan and re-scores. */
  function deepen(S, deob, stats, hashes, fileName, size, ms) {
    addDecrypted(S, deob);
    S.resourceFindings.length = S.preCombo;
    evaluateCombos(S, S.resFinding, hashes.sha256);
    const report = buildReport(S, hashes, fileName, size, ms);
    report.deep = stats;
    return report;
  }
  function addDecrypted(S, deob) {
    if (deob.applied) return;
    deob.applied = true;
    const byMethod = new Map();
    for (const d of deob.results) {
      const ci = S.classes.get(d.container + "!" + d.cls);
      if (!ci) continue;
      processString(ci, d.value, ev(d.method, d.line, d.value, null), "decrypted", 0);
      const k = d.container + "!" + d.cls + "#" + d.method;
      if (!byMethod.has(k)) byMethod.set(k, { ci, method: d.method, line: d.line, all: "" });
      const bm = byMethod.get(k); if (bm.all.length < 20000) bm.all += d.value;
    }
    for (const bm of byMethod.values()) scanConcatenation(bm.ci, bm.all, bm.method, bm.line);
    if (deob.solved >= 3) {
      const first = deob.results[0];
      const ci = first && S.classes.get(first.container + "!" + first.cls);
      if (ci) tag(ci, "S_ENCSTR", ev(first.method, first.line, first.value, null));
    }
  }

  /* ---------------- web pages (URL scanner) ---------------- */
  const SL2 = new Set("co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz com.br com.tr co.jp co.kr com.cn com.mx co.in co.za com.ar com.pl com.ru com.ua co.il com.sg com.hk com.tw".split(" "));
  const isIp = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":");
  function regDomain(host) {
    if (!host || isIp(host)) return host || "";
    const p = host.split(".");
    if (p.length <= 2) return host;
    const two = p.slice(-2).join(".");
    return SL2.has(two) ? p.slice(-3).join(".") : two;
  }
  const hostOf = u => { try { return new URL(u).hostname.toLowerCase().replace(/^\[|\]$/g, ""); } catch (e) { return ""; } };
  const absUrl = (u, base) => { try { return new URL(u.trim().replace(/&amp;/g, "&"), base).href; } catch (e) { return null; } };
  const BRANDS = {
    discord: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.gift", "discord.new", "discord.media", "discordstatus.com"],
    steamcommunity: ["steamcommunity.com"], steampowered: ["steampowered.com", "steamstatic.com"],
    minecraft: ["minecraft.net", "mojang.com", "minecraftservices.com"], microsoft: ["microsoft.com", "live.com", "microsoftonline.com", "xbox.com", "office.com", "msauth.net", "msftauth.net"],
    modrinth: ["modrinth.com"], curseforge: ["curseforge.com", "overwolf.com", "forgecdn.net"], github: ["github.com", "github.io", "githubusercontent.com", "githubassets.com"],
    paypal: ["paypal.com", "paypal.me", "paypalobjects.com"], epicgames: ["epicgames.com", "unrealengine.com"], roblox: ["roblox.com", "rbxcdn.com"],
    google: ["google.com", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com"], instagram: ["instagram.com", "cdninstagram.com"], binance: ["binance.com"],
    coinbase: ["coinbase.com"], metamask: ["metamask.io"], lunarclient: ["lunarclient.com"], feathermc: ["feathermc.com"], badlion: ["badlion.net"],
    optifine: ["optifine.net"], fabricmc: ["fabricmc.net"], minecraftforge: ["minecraftforge.net"], neoforged: ["neoforged.net"], hypixel: ["hypixel.net"],
    spigotmc: ["spigotmc.org"], papermc: ["papermc.io"], twitch: ["twitch.tv"], tiktok: ["tiktok.com"], telegram: ["telegram.org", "t.me"],
    whatsapp: ["whatsapp.com"], facebook: ["facebook.com", "fbcdn.net"], amazon: ["amazon.com", "amazon.de"], netflix: ["netflix.com"], apple: ["apple.com", "icloud.com"]
  };
  const BRAND_NAMES = { discord: "Discord", steamcommunity: "Steam", steampowered: "Steam", minecraft: "Minecraft", microsoft: "Microsoft", modrinth: "Modrinth", curseforge: "CurseForge", github: "GitHub", paypal: "PayPal", epicgames: "Epic Games", roblox: "Roblox", google: "Google", instagram: "Instagram", binance: "Binance", coinbase: "Coinbase", metamask: "MetaMask", lunarclient: "Lunar Client", feathermc: "Feather", badlion: "Badlion", optifine: "OptiFine", fabricmc: "Fabric", minecraftforge: "Forge", neoforged: "NeoForge", hypixel: "Hypixel", spigotmc: "SpigotMC", papermc: "PaperMC", twitch: "Twitch", tiktok: "TikTok", telegram: "Telegram", whatsapp: "WhatsApp", facebook: "Facebook", amazon: "Amazon", netflix: "Netflix", apple: "Apple" };
  const ownsBrand = (host, b) => BRANDS[b].some(d => host === d || host.endsWith("." + d));
  const unglyph = s => s.replace(/rn/g, "m").replace(/cl(?=[^aeiouy]|$)/g, "d").replace(/vv/g, "w").replace(/0/g, "o").replace(/[1|]/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/8/g, "b").replace(/-/g, "");
  function lev(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 9;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length];
  }
  const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|shorturl\.at|rb\.gy|t\.ly|ow\.ly|buff\.ly|goo\.su|s\.id|v\.gd|tiny\.cc|shorturl\.gg|linktr\.ee|lnk\.bio|adf\.ly|linkvertise\.com|link-to\.net|direct-link\.net|up-to-down\.net)$/;
  const FILEHOSTS = /(^|\.)(mediafire\.com|mega\.nz|mega\.io|gofile\.io|anonfiles\.com|pixeldrain\.com|catbox\.moe|transfer\.sh|file\.io|dropbox\.com|dropboxusercontent\.com|drive\.google\.com|drive\.usercontent\.google\.com|sendspace\.com|uploadhaven\.com|krakenfiles\.com|qiwi\.gg|workupload\.com|bayfiles\.com|filebin\.net|cdn\.discordapp\.com|media\.discordapp\.net|1drv\.ms|onedrive\.live\.com|ufile\.io|send\.cm|buzzheavier\.com)$/;
  const BAD_TLD = /\.(zip|mov|top|xyz|tk|ml|ga|cf|gq|icu|cyou|rest|click|sbs|lol|bond|cfd|monster|quest|buzz|beauty|hair|skin|makeup|boats|mom|autos|support|ru\.com|su)$/;
  const EXEC_LINK = /\.(exe|msi|scr|bat|cmd|ps1|vbs|vbe|js|jse|hta|lnk|jar|apk|dmg|pkg|iso|img|zip|rar|7z|appx|msix)(\?|#|$)/i;
  const RUN_LINK = /\.(exe|msi|scr|bat|cmd|ps1|vbs|vbe|jse|hta|lnk|appx|msix)(\?|#|$)/i;
  const daysSince = d => { const t = Date.parse(d || ""); return Number.isFinite(t) ? (Date.now() - t) / 86400000 : null; };
  const attr = (tag, name) => { const m = tag.match(new RegExp("\\b" + name + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", "i")); return m ? (m[1] ?? m[2] ?? m[3] ?? "") : null; };
  const htmlText = h => h.replace(/<script\b[\s\S]*?<\/script>/gi, " ").replace(/<style\b[\s\S]*?<\/style>/gi, " ").replace(/<!--[\s\S]*?-->/g, " ").replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();
  const JS_STR = /(["'`])((?:\\.|(?!\1)[^\\\n]){4,2000})\1/g;

  function scanSite(d) {
    const t0 = Date.now();
    const findings = [];
    const add = (rule, sev, cat, title, desc, evidence, where) => {
      if (findings.some(f => f.rule === rule)) { findings.find(f => f.rule === rule).occurrences++; return; }
      findings.push({ rule, severity: sev, category: cat, title, description: desc, evidence: evidence == null ? null : clip(String(evidence)), container: where || "", source: "site", occurrences: 1 });
    };
    const start = d.url || d.final, final = d.final || d.url;
    const host = hostOf(final), reg = regDomain(host), startHost = hostOf(start), startReg = regDomain(startHost);
    const label = (reg.split(".")[0] || "").toLowerCase();
    const html = String(d.html || "");
    const text = htmlText(html), low = text.toLowerCase();
    const title = htmlText((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "").slice(0, 200);
    const scripts = (d.scripts || []).filter(s => typeof s.body === "string");
    const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].filter(m => !/\bsrc\s*=/i.test(m[1]) && !/type\s*=\s*["']?(application\/(ld\+)?json|text\/template|importmap)/i.test(m[1])).map(m => m[2]).filter(t => t.trim());
    const handlers = [...html.matchAll(/\bon[a-z]{3,20}\s*=\s*("([^"]{8,4000})"|'([^']{8,4000})')/gi)].map(m => m[2] || m[3]).join("\n");
    const code = [...inline.map((t, i) => ({ where: "inline script " + (i + 1), text: t })), ...(handlers ? [{ where: "HTML event handlers", text: handlers }] : []), ...scripts.map(s => ({ where: s.url, text: s.body }))];
    const allCode = code.map(c => c.text).join("\n;\n");
    const whereOf = rx => { const c = code.find(x => rx.test(x.text)); return c ? c.where : ""; };
    const snippet = (rx, src) => { const s = src || allCode; const m = s.match(rx); if (!m) return null; const i = Math.max(0, m.index - 40); return s.slice(i, m.index + m[0].length + 60).replace(/\s+/g, " "); };
    const tags = new Set();

    /* domain and identity */
    if (isIp(host)) add("SITE_IP_HOST", "MEDIUM", "Domain", "Site is only an IP address", "Real projects use a domain name. Bare IP addresses are typical for short-lived malware download servers.", host);
    if (host.includes("xn--")) add("SITE_PUNYCODE", "MEDIUM", "Domain", "Internationalised (punycode) domain", "The domain uses special characters (" + host + ") – often used to imitate a known name with lookalike letters.", host);
    if (BAD_TLD.test(host)) add("SITE_CHEAP_TLD", "LOW", "Domain", "Domain ending often used for abuse", "Endings like ." + host.split(".").pop() + " are cheap and very common for phishing and malware sites. Many legit sites use them too.", host);
    const ownBrand = Object.keys(BRANDS).find(b => ownsBrand(host, b));
    let posing = null;
    if (!ownBrand && label) {
      const ul = unglyph(label);
      const parts = label.split("-").filter(x => x.length >= 5);
      outer: for (const b of Object.keys(BRANDS)) {
        if (b.length < 6 || !parts.length || parts.length === 1 && parts[0] === label) continue;
        for (const part of parts) {
          const up = unglyph(part), dist = lev(up, b);
          if (part !== b && (up === b || dist > 0 && ((b.length >= 7 && dist === 1) || (b.length >= 10 && dist === 2)))) { posing = BRAND_NAMES[b]; add("SITE_TYPOSQUAT", "HIGH", "Phishing", "Look-alike of " + BRAND_NAMES[b] + " (typosquatting)", "'" + reg + "' contains '" + part + "', a misspelled " + BRANDS[b][0] + " – a classic phishing trick.", reg); break outer; }
        }
      }
      if (!posing) for (const b of Object.keys(BRANDS)) {
        const name = BRAND_NAMES[b];
        if (ul === b && label !== b) { posing = name; add("SITE_HOMOGLYPH", "CRITICAL", "Phishing", "Fake domain imitating " + name, "'" + reg + "' uses swapped look-alike characters to read like " + BRANDS[b][0] + ". This is never the real site.", reg); break; }
        const dist = lev(ul, b);
        if (dist > 0 && ((b.length >= 7 && dist === 1) || (b.length >= 10 && dist === 2))) { posing = name; add("SITE_TYPOSQUAT", "HIGH", "Phishing", "Look-alike of " + name + " (typosquatting)", "'" + reg + "' differs from " + BRANDS[b][0] + " by only " + dist + " letter" + (dist > 1 ? "s" : "") + " – a classic phishing trick.", reg); break; }
        if (b.length >= 6 && label.includes(b) && label !== b) { posing = name; add("SITE_BRAND_IN_DOMAIN", "LOW", "Phishing", "Uses the name " + name + " but is not " + name, "'" + reg + "' contains '" + b + "' but does not belong to " + name + " (" + BRANDS[b][0] + "). Fan sites do this too – scams very often.", reg); break; }
      }
      for (const b of Object.keys(BRANDS)) for (const dom of BRANDS[b]) {
        if (host.startsWith(dom + ".") || host.includes("." + dom + ".") || host.includes(dom.replace(".", "-") + ".")) { posing = posing || BRAND_NAMES[b]; add("SITE_BRAND_SUBDOMAIN", "HIGH", "Phishing", "Hides " + dom + " inside a foreign address", "The address starts with '" + dom + "' but the real domain is " + reg + ". People read the beginning of the link and trust it.", host); }
      }
    }
    const created = d.domain && d.domain.created, age = daysSince(created);
    if (age != null) {
      if (age < 14) add("SITE_NEW_DOMAIN", "HIGH", "Domain", "Domain registered " + Math.max(0, Math.round(age)) + " days ago", "Brand-new domains are the most reliable sign of phishing and scam sites – they are thrown away after a few days.", created);
      else if (age < 60) add("SITE_YOUNG_DOMAIN", "MEDIUM", "Domain", "Domain is only " + Math.round(age) + " days old", "Young domains are much more often used for scams. Be careful if it asks for logins or offers downloads.", created);
      else if (age < 180) add("SITE_RECENT_DOMAIN", "LOW", "Domain", "Domain is less than half a year old", "Registered " + Math.round(age) + " days ago.", created);
    }
    if (!/^https:/i.test(final)) add("SITE_NO_HTTPS", "MEDIUM", "Connection", "No HTTPS", "The page is not encrypted. Anything you type can be read or changed on the way.", final);
    if (d.cert && d.cert.from) { const ca = daysSince(d.cert.from); if (ca != null && ca < 3 && (age == null || age < 60)) add("SITE_FRESH_CERT", "LOW", "Connection", "Certificate issued in the last days", "The HTTPS certificate is " + Math.max(0, Math.round(ca * 24)) + " hours old – together with a young domain a sign of a freshly set up site.", d.cert.issuer + " · " + d.cert.from); }

    /* redirects */
    const chain = d.chain || [];
    if (startReg && reg && startReg !== reg) add("SITE_REDIRECT_OTHER", SHORTENERS.test(startHost) ? "LOW" : "MEDIUM", "Redirects", SHORTENERS.test(startHost) ? "Short link hides the real destination" : "Sends you to a different site", "You opened " + startHost + " but end up on " + host + ". Check that this is really where you wanted to go.", chain.map(c => c.url).join("  →  "));
    if (chain.length > 4) add("SITE_REDIRECT_CHAIN", "LOW", "Redirects", "Long redirect chain (" + (chain.length - 1) + " hops)", "Malicious ads and traffic sellers bounce visitors through many addresses so scanners lose track.", chain.map(c => c.url).join("  →  "));
    const metaRefresh = html.match(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*>/i);
    if (metaRefresh) {
      const target = ((attr(metaRefresh[0], "content") || "").match(/url\s*=\s*['"]?([^'";]+)/i) || [])[1];
      const abs = target && absUrl(target, final);
      if (abs && RUN_LINK.test(abs)) add("SITE_AUTO_DOWNLOAD", "HIGH", "Downloads", "Starts a program download by itself", "The page automatically downloads " + abs.split(/[?#]/)[0].split("/").pop() + " without you clicking anything.", abs);
      else if (abs && regDomain(hostOf(abs)) !== reg) add("SITE_META_REDIRECT", "LOW", "Redirects", "Forwards you to another site", "A meta refresh sends visitors on to " + hostOf(abs) + ".", abs);
    }

    /* links and downloads */
    const links = [];
    for (const m of html.matchAll(/<a\b[^>]*>/gi)) { const h = attr(m[0], "href"); if (!h || /^(#|javascript:|mailto:|tel:)/i.test(h)) continue; const a = absUrl(h, final); if (a) links.push({ url: a, tag: m[0] }); }
    const downloads = [];
    for (const l of links) if (EXEC_LINK.test(l.url) || FILEHOSTS.test(hostOf(l.url)) || /\bdownload\b/i.test(l.tag)) if (!downloads.some(x => x.url === l.url)) downloads.push({ url: l.url, host: hostOf(l.url), name: decodeURIComponent(l.url.split(/[?#]/)[0].split("/").pop() || "").slice(0, 120), filehost: FILEHOSTS.test(hostOf(l.url)), runnable: RUN_LINK.test(l.url) });
    for (const m of allCode.matchAll(/["'](https?:\/\/[^"'\s]{6,300}\.(exe|msi|scr|bat|ps1|vbs|hta|lnk|jar|zip|rar|7z)(\?[^"'\s]*)?)["']/gi)) if (!downloads.some(x => x.url === m[1])) downloads.push({ url: m[1], host: hostOf(m[1]), name: m[1].split(/[?#]/)[0].split("/").pop().slice(0, 120), filehost: FILEHOSTS.test(hostOf(m[1])), runnable: RUN_LINK.test(m[1]), fromScript: true });
    if (downloads.some(x => x.filehost)) add("SITE_FILEHOST_DOWNLOAD", "MEDIUM", "Downloads", "Downloads come from an anonymous file host", "Files are offered from " + [...new Set(downloads.filter(x => x.filehost).map(x => x.host))].join(", ") + ". Anyone can upload there and swap the file – real projects host their own downloads or use Modrinth/CurseForge/GitHub.", downloads.find(x => x.filehost).url);
    if (downloads.some(x => x.runnable)) add("SITE_EXE_DOWNLOAD", "LOW", "Downloads", "Offers Windows programs or scripts", "The page links to " + downloads.filter(x => x.runnable).slice(0, 4).map(x => x.name).join(", ") + ". Scan every file before you run it.", downloads.find(x => x.runnable).url);
    const pw = low.match(/(archive|zip|rar|file|download)?\s*(password|passwort|pass|pw)\s*[:=]\s*["']?[a-z0-9!@#$%_.-]{2,16}/i);
    if (pw && (downloads.length || /\.(zip|rar|7z)\b/.test(low))) add("SITE_PASSWORD_ARCHIVE", "HIGH", "Downloads", "Password-protected download", "The page tells you the password for an archive. Malware is packed into encrypted archives so antivirus and scanners cannot look inside.", snippet(/(password|passwort|pass|pw)\s*[:=]/i, text));
    if (/(update|upgrade) (your )?(chrome|browser|edge|firefox|flash player)|browser is out of date|your browser (version )?is (outdated|not supported)|critical (security )?update (required|available)/i.test(text) && (downloads.length || /\.(zip|exe|js|msi)\b/i.test(allCode)))
      add("SITE_FAKE_UPDATE", "HIGH", "Fake download", "Fake browser update", "Real browsers update themselves and never ask a website to install an update. Fake update pages (SocGholish/FakeUpdates) are injected into hacked sites to spread malware.", snippet(/(update|upgrade) (your )?(chrome|browser|edge|firefox)|browser is out of date/i, text));

    /* logins, phishing kits */
    const pwInputs = (html.match(/<input\b[^>]*type\s*=\s*["']?password/gi) || []).length;
    const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)];
    if (pwInputs) tags.add("ASKS_LOGIN");
    for (const f of forms) {
      if (!/type\s*=\s*["']?password/i.test(f[2])) continue;
      const act = attr(f[1], "action"), abs = act ? absUrl(act, final) : final;
      if (abs && /^http:/i.test(abs)) add("SITE_PASSWORD_HTTP", "HIGH", "Phishing", "Password is sent without encryption", "The login form sends your password over plain HTTP to " + hostOf(abs) + ".", abs);
      else if (abs && hostOf(abs) && regDomain(hostOf(abs)) !== reg) { tags.add("SENDS_AWAY"); add("SITE_PASSWORD_ELSEWHERE", "HIGH", "Phishing", "Login form sends your password to another site", "The password field posts to " + hostOf(abs) + " instead of " + reg + ". Phishing kits collect logins this way.", abs); }
    }
    const claimRx = /\b(discord|steam|microsoft|minecraft|xbox|paypal|epic games|roblox|google|apple id|instagram|metamask|binance|coinbase|hypixel|lunar client|telegram|whatsapp|facebook|netflix|amazon)\b/i;
    const claim = (title.match(claimRx) || text.slice(0, 3000).match(/\b(sign in|log ?in|anmelden) (to|with|bei|mit) (discord|steam|microsoft|minecraft|xbox|paypal|epic games|roblox|google|apple|instagram|metamask|binance|coinbase|telegram|facebook|netflix|amazon)\b/i) || [])[0];
    if (pwInputs && claim && !ownBrand) add("SITE_FAKE_LOGIN", "CRITICAL", "Phishing", "Login page pretending to be " + claim.replace(/^(sign in|log ?in|anmelden) (to|with|bei|mit) /i, ""), "The page asks for a password and presents itself as " + claim + ", but the domain is " + reg + ". Never enter your login here.", title || claim);
    else if (pwInputs && posing) add("SITE_FAKE_LOGIN", "CRITICAL", "Phishing", "Login on a site imitating " + posing, "A look-alike domain that also asks for a password – a phishing page.", reg);
    if (/steamcommunity\.com\/openid|sign in through steam/i.test(html) && /(position\s*:\s*(fixed|absolute)[^}]{0,200}(titlebar|window|popup))|class\s*=\s*["'][^"']*(fake-?window|browser-?window|window-?bar|title-?bar|popup-?window)/i.test(html) && !ownsBrand(host, "steamcommunity"))
      add("SITE_BITB", "CRITICAL", "Phishing", "Fake pop-up login window (browser-in-the-browser)", "The page draws a fake browser window with a Steam/Discord login inside it. The address bar in it is just a picture – the login goes to the attacker.", snippet(/steamcommunity\.com\/openid|sign in through steam/i, html));
    if (/(secret|recovery|seed|mnemonic|wallet) (recovery )?(phrase|words)|12[- ]word|24[- ]word|private key/i.test(text) && /<(input|textarea)\b/i.test(html) && !ownBrand)
      add("SITE_SEED_PHISH", "CRITICAL", "Phishing", "Asks for your wallet recovery phrase", "No real service ever asks for your seed phrase or private key. Whoever has it owns your wallet.", snippet(/(secret|recovery|seed|mnemonic) (recovery )?(phrase|words)|private key/i, text));
    if (/remote-auth-gateway\.discord\.gg/i.test(allCode) && !ownsBrand(host, "discord")) add("SITE_DISCORD_QR", "CRITICAL", "Account theft", "Fake Discord QR-code login", "The page opens Discord's QR login itself. Scanning the code with your phone logs the attacker into your account (QR token grabbing).", "remote-auth-gateway.discord.gg");
    if (/webpackChunkdiscord_app|localStorage\.getItem\(\s*["']token["']\)|\.getToken\(\)\s*\)/i.test(allCode) && !ownsBrand(host, "discord")) add("SITE_DISCORD_TOKEN", "HIGH", "Account theft", "Code for reading Discord tokens", "Contains snippets that read the Discord login token. Scam pages tell you to paste this into the Discord console ('self-XSS').", snippet(/webpackChunkdiscord_app|getItem\(\s*["']token/i));
    if (/(press|drücke|hold).{0,30}(windows|win)\s*(key|taste)?\s*\+\s*r|win\s*\+\s*r\b|windows \+ r|ctrl\s*\+\s*v.{0,60}(enter|run|ausführen)|paste.{0,40}(run dialog|terminal|powershell)/i.test(text)) tags.add("CF_TEXT");
    const clipWrite = /clipboard\.writeText|execCommand\(\s*["']copy["']\)|clipboardData\.setData/i.test(allCode);
    const shellCmd = /powershell|pwsh|mshta|cmd(\.exe)?\s*\/[ck]|\biwr\b|\birm\b|Invoke-(WebRequest|RestMethod|Expression)|\biex\b|bitsadmin|certutil\s+-urlcache|rundll32|regsvr32|curl\s+[^|]{4,200}\|\s*(ba)?sh|conhost/i;
    const clipNearShell = code.some(c => { for (const m of c.text.matchAll(/clipboard\.writeText|execCommand\(\s*["']copy["']\)|clipboardData\.setData/gi)) if (shellCmd.test(c.text.slice(Math.max(0, m.index - 600), m.index + 600))) return true; return false; });
    const verifyText = /(verify|verification|human|robot|captcha|cloudflare|ray id|bestätig|überprüf)/i.test(title + " " + text.slice(0, 8000));
    if (clipWrite && (tags.has("CF_TEXT") || clipNearShell && verifyText)) { tags.add("CLIPBOARD_CMD"); add("SITE_CLICKFIX", "CRITICAL", "Fake captcha", "Fake 'verify you are human' – copies a command for you to run", "The page puts a command into your clipboard and tells you to paste it into Win+R / a terminal (ClickFix scam). Running it installs malware – no real captcha ever asks this.", snippet(shellCmd) || snippet(/clipboard\.writeText|execCommand\(\s*["']copy/i)); }
    else if (tags.has("CF_TEXT") && verifyText) add("SITE_CLICKFIX_TEXT", "HIGH", "Fake captcha", "Asks you to press Win+R and paste something", "Captcha pages never ask you to open the Run dialog or a terminal. This is the ClickFix scam.", snippet(/win(dows)?\s*(key|taste)?\s*\+\s*r|ctrl\s*\+\s*v/i, text));

    /* crypto */
    const wallet = /ethereum\.request|eth_requestAccounts|window\.ethereum|walletconnect|web3modal|solana\.connect|phantom\.solana|tronWeb/i.test(allCode);
    if (wallet) tags.add("WALLET");
    if (wallet && /setApprovalForAll|increaseAllowance|eth_signTypedData(_v4)?[\s\S]{0,400}(Permit|Seaport)|seaport|permit2|signAllTransactions|drainer|inferno|angel ?drainer|pink ?drainer/i.test(allCode)) add("SITE_DRAINER", "CRITICAL", "Crypto", "Crypto wallet drainer", "The page connects to your wallet and asks for blanket approvals/permit signatures. One click and everything in the wallet can be moved out.", snippet(/setApprovalForAll|increaseAllowance|seaport|permit2|signAllTransactions|drainer/i));
    if (/coinhive|coin-hive|coinimp|webminepool|cryptoloot|crypto-loot|jsecoin|minero\.cc|webmine\.cz|cryptonight\.wasm|CoinHive\.Anonymous|miner\.start\(/i.test(allCode + html)) add("SITE_MINER", "HIGH", "Crypto", "Mines cryptocurrency in your browser", "A mining script uses your CPU while the page is open.", snippet(/coinhive|coinimp|webminepool|cryptoloot|jsecoin|minero|miner\.start/i, allCode + html));

    /* injected / obfuscated code */
    const evalHidden = /eval\s*\(\s*(atob|unescape|decodeURIComponent|String\.fromCharCode|function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e)|new\s+Function\s*\(\s*(atob|unescape|decodeURIComponent)|document\.write\s*\(\s*(unescape|atob|decodeURIComponent)\s*\(/i;
    if (evalHidden.test(allCode)) { tags.add("HIDDEN_CODE"); add("SITE_EVAL_HIDDEN", "HIGH", "Hidden code", "Decodes and runs hidden code", "Script text is decoded at runtime and passed to eval/document.write – the real code is hidden from you and from scanners. Injected malware on hacked sites looks like this.", snippet(evalHidden), whereOf(evalHidden)); }
    for (const c of code) {
      const n = (c.text.match(/_0x[0-9a-f]{4,6}/g) || []).length;
      if (n > 80 && c.text.length < 400000) { tags.add("HIDDEN_CODE"); add("SITE_OBFUSCATED_JS", "MEDIUM", "Hidden code", "Heavily obfuscated JavaScript", "A script was run through an obfuscator (" + n + " scrambled names). Legit sites rarely hide their code like this.", c.text.slice(0, 160), c.where); }
    }
    if (/createElement\(\s*["']script["']\s*\)[\s\S]{0,300}(atob|fromCharCode|\\x[0-9a-f]{2}\\x)/i.test(allCode)) { tags.add("HIDDEN_CODE"); add("SITE_DYNAMIC_LOADER", "MEDIUM", "Hidden code", "Loads a script from a hidden address", "A script tag is created whose address is encoded – a common way injected code pulls in the next stage.", snippet(/createElement\(\s*["']script["']\s*\)/i)); }
    const after = html.slice(html.search(/<\/html>/i) + 7);
    if (/<\/html>/i.test(html) && /<script|<iframe/i.test(after)) add("SITE_AFTER_HTML", "MEDIUM", "Hidden code", "Code added after the end of the page", "A script/iframe sits behind </html>. Hacked sites often get code appended there.", after.trim().slice(0, 200));
    const before = html.slice(0, Math.max(0, html.search(/<!doctype|<html/i)));
    if (/<script|<iframe/i.test(before)) add("SITE_BEFORE_HTML", "MEDIUM", "Hidden code", "Code inserted before the page starts", "A script/iframe sits before <html> – a typical spot for injected code.", before.trim().slice(0, 200));
    for (const m of html.matchAll(/<iframe\b[^>]*>/gi)) {
      const t = m[0], src = attr(t, "src"), abs = src && absUrl(src, final);
      if (!abs) continue;
      if (/(width|height)\s*=\s*["']?[01]["'\s>]|display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0[;"']/i.test(t) && regDomain(hostOf(abs)) !== reg && !/(googletagmanager|doubleclick|google\.com\/recaptcha|challenges\.cloudflare\.com|facebook\.com\/tr|youtube)/i.test(abs)) { tags.add("HIDDEN_CODE"); add("SITE_HIDDEN_IFRAME", "MEDIUM", "Hidden code", "Invisible frame loads another site", "An iframe with size 0/hidden loads " + hostOf(abs) + ". Classic for drive-by downloads and click fraud.", abs); }
    }
    const POLY = /(^|\.)(polyfill\.io|polyfill\.com|polyfillcache\.com|bootcss\.com|bootcdn\.net|staticfile\.org|staticfile\.net|unionadjs\.com|xhsbpza\.com|union\.macoms\.la|newcrbpc\.com)$/;
    for (const s of d.scripts || []) {
      const sh = hostOf(s.url);
      if (POLY.test(sh)) add("SITE_POLYFILL", /polyfill/.test(sh) ? "CRITICAL" : "HIGH", "Hidden code", "Loads a script from a hijacked CDN (" + sh + ")", "This CDN was taken over in the 2024 polyfill.io supply-chain attack and served malicious redirects to visitors.", s.url, s.url);
      if (isIp(sh)) add("SITE_SCRIPT_IP", "MEDIUM", "Hidden code", "Script loaded from a bare IP address", "Scripts from an IP address instead of a domain are unusual and typical for injected code.", s.url, s.url);
    }
    if (/hacked by|defaced by|h4ck3d|0wn3d by|owned by .{0,20}(team|crew|cyber|army)|greetz to/i.test(title + " " + text.slice(0, 5000))) add("SITE_DEFACED", "HIGH", "Hacked site", "Site looks defaced", "The page contains typical defacement wording ('hacked by …'). Treat everything on it as untrusted.", snippet(/hacked by|defaced by|h4ck3d|0wn3d|owned by/i, title + " " + text));
    let spam = 0;
    for (const m of html.matchAll(/<(div|span|p|section)\b[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px|font-size\s*:\s*0)[^"']*["'][^>]*>([\s\S]{0,6000}?)<\/\1>/gi))
      if (/<a\b/i.test(m[3]) && /(casino|slot gacor|slot online|judi|togel|viagra|cialis|replica|payday loan|essay writing|porn|xxx|escort|bet88|sbobet|bandar)/i.test(m[3])) spam++;
    if (spam) add("SITE_SEO_SPAM", "HIGH", "Hacked site", "Hidden spam links injected", "Invisible blocks with casino/pharma/porn links were found (" + spam + "×). Spammers inject these into hacked websites – the site itself is compromised.", null);
    if (/addEventListener\(\s*["']contextmenu["'][\s\S]{0,120}preventDefault|oncontextmenu\s*=\s*["']?return false/i.test(allCode + html) && /(keyCode|which)\s*===?\s*123|["']F12["']|setInterval\([^)]{0,80}debugger|devtools-?detect/i.test(allCode)) add("SITE_ANTI_INSPECT", "LOW", "Hidden code", "Blocks inspecting the page", "Right-click and the developer tools (F12) are blocked so visitors cannot look at the code.", snippet(/contextmenu|F12|debugger/i));
    if (/Notification\.requestPermission|pushManager\.subscribe/i.test(allCode) && /(click|press|tap|klick).{0,20}(allow|erlauben|zulassen).{0,60}(robot|human|continue|video|download|weiter|verify)/i.test(text)) add("SITE_PUSH_SPAM", "MEDIUM", "Scam", "Tricks you into allowing notifications", "'Click Allow to continue' – after that the site can send scam/virus-alert pop-ups to your desktop any time.", snippet(/(click|press|tap|klick).{0,20}(allow|erlauben|zulassen)/i, text));
    if (/(your (pc|computer|device) is infected|virus(es)? (detected|found)|call (microsoft|apple) support|windows defender alert|trojan (spyware )?alert)/i.test(text)) add("SITE_TECH_SCAM", "HIGH", "Scam", "Fake virus warning", "The page claims your computer is infected. Websites cannot scan your PC – this is a tech-support or fake-antivirus scam.", snippet(/your (pc|computer|device) is infected|virus(es)? (detected|found)|call (microsoft|apple) support|defender alert|trojan/i, text));
    if (/(free|gratis|kostenlos) (discord )?nitro|nitro (gift|giveaway|for free)|claim (your )?(free )?nitro|steam gift.{0,20}(free|\$50)|free (robux|v-?bucks|minecoins|skins)/i.test(title + " " + text.slice(0, 6000)) && !ownBrand) add("SITE_FREEBIE_SCAM", "HIGH", "Scam", "Free Nitro/Robux/skins bait", "Promises free Nitro, Robux, V-Bucks or gift cards – the bait used by almost every account-stealing scam.", snippet(/(free|gratis|kostenlos) (discord )?nitro|nitro (gift|giveaway)|free (robux|v-?bucks|minecoins|skins)|steam gift/i, title + " " + text));

    /* the known string rules (webhooks, Telegram bots, IP grabbers, tunnels, paste sites, stealer paths …) on every string in the code */
    const holder = newClass("", "site:" + host, "site:" + host, false, false, final);
    const seen = new Set();
    let strings = 0;
    for (const c of code) {
      for (const m of c.text.matchAll(JS_STR)) {
        const s = m[2];
        if (seen.has(s) || ++strings > 120000) continue;
        seen.add(s);
        processString(holder, s.replace(/\\\//g, "/"), ev(null, null, s, s), "resource", 1);
        if (holder.findings.size) for (const f of holder.findings.values()) if (!f.site) { f.site = true; f.container = c.where; }
      }
    }
    for (const s of d.scripts || []) processString(holder, s.url, ev(null, null, s.url, s.url), "resource", 1);
    for (const f of holder.findings.values()) {
      if (!/^STR_(EXFIL_|REMOTE_(TUNNEL|PASTE|FILEHOST|DISCORD_CDN|RAW_IP)|IP_GRABBER|MINER|C2_BLOCKCHAIN|C2_TELEGRAM_CMD|TOR_BRIDGE|MC_TOKEN_JSON)/.test(f.rule)) continue;
      const sev = /^STR_IP_GRABBER/.test(f.rule) ? "LOW" : f.severity === "CRITICAL" ? "HIGH" : f.severity;
      findings.push({ rule: "SITE_" + f.rule, severity: sev, category: f.category, title: f.title.replace(/ \(hidden: .*\)$/, ""), description: f.description + " (found in the page's JavaScript)", evidence: f.evidence, container: f.container || "", source: "site", occurrences: f.occurrences || 1 });
    }
    if (holder.tags.has("S_EXFIL") && pwInputs) add("SITE_PHISH_EXFIL", "CRITICAL", "Phishing", "Logins are sent to a webhook/bot", "The page has a password field and its code contains a Discord webhook / Telegram bot / request catcher – a phishing kit that forwards whatever you type.", (holder.tags.get("S_EXFIL") || {}).text);
    if (holder.tags.has("S_EXFIL")) tags.add("SENDS_AWAY");

    if (/^(just a moment|attention required|one more step|ddos-guard|checking your browser)/i.test(title) || /cf-challenge|challenge-platform|cf_chl_opt/i.test(html.slice(0, 20000))) add("SITE_BOT_WALL", "INFO", "Coverage", "Site shows a bot check to scanners", "The site answered with a Cloudflare/DDoS-protection check page, so its real content could not be read. The domain checks above still apply.", title);
    /* headers */
    const H = d.headers || {};
    const missing = [["content-security-policy", "CSP"], ["strict-transport-security", "HSTS"], ["x-frame-options", "X-Frame-Options"]].filter(([k]) => !H[k] && !(k === "x-frame-options" && /frame-ancestors/i.test(H["content-security-policy"] || ""))).map(x => x[1]);
    if (missing.length === 3) add("SITE_NO_HEADERS", "INFO", "Connection", "No security headers", "The server sends no " + missing.join(", ") + ". Not dangerous by itself, but well-run sites set them.", null);
    if (d.truncated) add("SITE_TRUNCATED", "INFO", "Coverage", "Page is larger than 3 MB", "Only the first 3 MB of the HTML were checked.", null);
    const skipped = (d.scripts || []).filter(s => !s.body).length;
    if (skipped) add("SITE_SCRIPTS_SKIPPED", "INFO", "Coverage", skipped + " scripts were not checked", "They could not be loaded or the limit of 15 external scripts was reached.", (d.scripts || []).filter(s => !s.body).slice(0, 3).map(s => s.url).join("  "));

    const brandF = findings.find(f => f.rule === "SITE_BRAND_IN_DOMAIN");
    if (brandF && (pwInputs || downloads.some(x => x.runnable || x.filehost))) { brandF.severity = "MEDIUM"; brandF.description += " This one also asks for a login or offers downloads."; }
    /* verdict */
    findings.sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.title.localeCompare(b.title));
    let score = 0, crit = 0;
    const highs = new Set();
    for (const f of findings) { score += WEIGHT[f.severity] * (1 + Math.min((f.occurrences || 1) - 1, 4) * 0.08); if (f.severity === "CRITICAL") crit++; if (f.severity === "HIGH") highs.add(f.title); }
    const verdict = crit > 0 || highs.size >= 3 || score >= 70 ? "MALICIOUS" : highs.size > 0 || score >= 22 ? "SUSPICIOUS" : score >= 6 ? "CAUTION" : "CLEAN";
    const severityCounts = Object.fromEntries(SEV.map(s => [s, 0]));
    for (const f of findings) severityCounts[f.severity]++;
    const has = (...rules) => findings.find(f => rules.includes(f.rule));
    const B = (id, hit, bad, label, none, f) => ({ id, hit: !!hit, bad, label, none, why: f ? f.title : hit && typeof hit === "string" ? hit : undefined });
    const fakeF = has("SITE_HOMOGLYPH", "SITE_TYPOSQUAT", "SITE_BRAND_SUBDOMAIN", "SITE_FAKE_LOGIN", "SITE_BITB", "SITE_DISCORD_QR");
    const sendF = has("SITE_PASSWORD_ELSEWHERE", "SITE_PHISH_EXFIL", "SITE_PASSWORD_HTTP") || findings.find(f => /^SITE_STR_(EXFIL|IP_GRABBER|STEAL)/.test(f.rule));
    const dlF = has("SITE_AUTO_DOWNLOAD", "SITE_FAKE_UPDATE", "SITE_PASSWORD_ARCHIVE", "SITE_FILEHOST_DOWNLOAD", "SITE_EXE_DOWNLOAD");
    const hackF = has("SITE_POLYFILL", "SITE_SEO_SPAM", "SITE_DEFACED", "SITE_AFTER_HTML", "SITE_BEFORE_HTML", "SITE_HIDDEN_IFRAME", "SITE_EVAL_HIDDEN", "SITE_DYNAMIC_LOADER", "SITE_OBFUSCATED_JS", "SITE_SCRIPT_IP");
    const scamF = has("SITE_CLICKFIX", "SITE_CLICKFIX_TEXT", "SITE_TECH_SCAM", "SITE_FREEBIE_SCAM", "SITE_PUSH_SPAM", "SITE_SEED_PHISH");
    const behavior = [
      B("fake", fakeF, true, "Pretends to be another site or service", "Does not pretend to be a known brand", fakeF),
      B("login", pwInputs ? "Has " + pwInputs + " password field" + (pwInputs > 1 ? "s" : "") : null, !!(fakeF || sendF), "Asks for a password or login", "Does not ask for a password", has("SITE_FAKE_LOGIN", "SITE_PASSWORD_ELSEWHERE", "SITE_PASSWORD_HTTP")),
      B("send", sendF, true, "Sends what you type or your data to someone else", "No hidden data upload found", sendF),
      B("clipboard", has("SITE_CLICKFIX", "SITE_CLICKFIX_TEXT"), true, "Wants you to paste and run a command", "Does not ask you to run commands", has("SITE_CLICKFIX", "SITE_CLICKFIX_TEXT")),
      B("wallet", tags.has("WALLET") ? "Connects to crypto wallets" : null, !!has("SITE_DRAINER", "SITE_SEED_PHISH"), "Wants access to your crypto wallet", "Does not touch crypto wallets", has("SITE_DRAINER", "SITE_SEED_PHISH")),
      B("download", dlF || (downloads.length ? downloads.length + " download link" + (downloads.length > 1 ? "s" : "") : null), !!has("SITE_AUTO_DOWNLOAD", "SITE_FAKE_UPDATE", "SITE_PASSWORD_ARCHIVE", "SITE_FILEHOST_DOWNLOAD"), "Offers files to download", "Offers no program downloads", dlF),
      B("hacked", hackF, true, "Contains injected or hidden code", "No injected or hidden code found", hackF),
      B("scam", scamF, true, "Uses scam tricks (fake captcha, fake virus alert, free Nitro …)", "No scam wording found", scamF),
      B("redirect", has("SITE_REDIRECT_OTHER", "SITE_META_REDIRECT", "SITE_REDIRECT_CHAIN"), false, "Sends you on to another site", "Stays on the address you opened", has("SITE_REDIRECT_OTHER", "SITE_META_REDIRECT", "SITE_REDIRECT_CHAIN"))
    ];
    return {
      kind: "site", fileName: host, url: start, final, title, verdict, score: Math.min(100, Math.round(score)), severityCounts, findings, behavior, classes: [], capabilities: [], entrypoints: [], containers: [],
      scannedAt: new Date().toISOString(), durationMs: Date.now() - t0,
      site: { host, domain: reg, ip: d.ip || null, status: d.code, chain: chain.map(c => ({ url: c.url, code: c.code })), created: created || null, registrar: d.domain && d.domain.registrar || null,
        cert: d.cert || null, server: H.server || null, poweredBy: H["x-powered-by"] || null, scripts: (d.scripts || []).map(s => ({ url: s.url, size: s.size || 0, status: s.body ? "checked" : s.error || s.skipped || "not loaded" })),
        inlineScripts: inline.length, links: links.length, forms: forms.length, passwordFields: pwInputs },
      downloads: downloads.slice(0, 40)
    };
  }

  return { init, scan, disassemble, deobfuscate, addDecrypted, patchClass, scanSource, deepen, scanSite, version: "2.1" };
})();
if (typeof module !== "undefined") module.exports = RatEngine;
