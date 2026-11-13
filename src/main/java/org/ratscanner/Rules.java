package org.ratscanner;

import com.google.gson.*;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

final class Rules {

    record StrRule(String id, Severity severity, String category, String tag, String title, String description, Pattern pattern) {
    }

    record CapInfo(String label, Severity alone, String category, String title, String description) {
    }

    record Combo(String id, Severity severity, String category, String title, String description, List<String> all, List<String> any, boolean jarLevel) {
    }

    record Family(String name, Severity severity, List<String> strings, List<String> classPrefixes, String description) {
    }

    static final List<StrRule> STRING_RULES = new ArrayList<>();
    static final Map<String, CapInfo> CAPS = new LinkedHashMap<>();
    static final List<Combo> COMBOS = new ArrayList<>();
    static final List<Family> FAMILIES = new ArrayList<>();
    static final Set<String> BAD_HASHES = new HashSet<>();

    static final List<String> LIBRARY_PREFIXES = List.of(
            "com/google/", "org/apache/", "io/netty/", "kotlin/", "kotlinx/", "okhttp3/", "okio/", "org/slf4j/", "org/json/",
            "com/fasterxml/", "org/lwjgl/", "net/fabricmc/", "org/spongepowered/", "it/unimi/", "org/yaml/", "com/mojang/",
            "org/objectweb/", "oshi/", "com/sun/jna/", "org/jetbrains/", "org/intellij/", "javax/annotation/", "org/checkerframework/",
            "net/kyori/", "me/shedaniel/", "dev/isxander/", "com/terraformersmc/", "org/joml/", "de/maxhenkel/", "com/jagrosh/discordipc/",
            "org/bstats/", "net/bytebuddy/", "org/reflections/", "javassist/", "com/llamalad7/mixinextras/", "com/github/benmanes/caffeine/",
            "org/sqlite/", "com/zaxxer/", "io/sentry/", "org/jline/", "net/minecraftforge/", "net/neoforged/", "cpw/mods/", "org/bukkit/",
            "io/papermc/", "net/md_5/", "com/velocitypowered/", "org/jspecify/", "org/hibernate/", "com/mysql/", "org/mariadb/", "org/postgresql/",
            "org/h2/", "io/lettuce/", "redis/clients/", "org/mongodb/", "com/mongodb/", "org/bson/", "dev/architectury/", "fuzs/", "org/quiltmc/",
            "com/electronwill/", "com/typesafe/", "org/jsoup/", "org/eclipse/", "javax/", "jakarta/", "com/ibm/icu/", "org/joda/", "org/lz4/",
            "net/jpountz/", "com/github/luben/", "org/tukaani/", "club/minnced/", "net/dv8tion/", "com/neovisionaries/", "gnu/trove/", "com/esotericsoftware/",
            "org/luaj/", "org/mozilla/", "com/formdev/", "net/java/", "org/xerial/", "com/github/oshi/", "io/github/classgraph/", "nonapi/io/github/classgraph/");

    static final Set<String> STANDARD_BOOTSTRAPS = Set.of(
            "java/lang/invoke/LambdaMetafactory", "java/lang/invoke/StringConcatFactory", "java/lang/runtime/ObjectMethods",
            "java/lang/runtime/SwitchBootstraps", "java/lang/invoke/ConstantBootstraps", "kotlin/jvm/internal/LambdaMetafactory",
            "groovy/lang/MetaClass", "org/codehaus/groovy/vmplugin/v8/IndyInterface", "jdk/internal/lambda/LambdaMetafactory");

    private static final String S = "[\\\\/]{1,2}";

    private static Pattern p(String regex) {
        return Pattern.compile(regex.replace("{S}", S), Pattern.CASE_INSENSITIVE);
    }

    private static Pattern pc(String regex) {
        return Pattern.compile(regex.replace("{S}", S));
    }

    private static void str(String id, Severity sev, String cat, String tag, String title, String desc, Pattern pattern) {
        STRING_RULES.add(new StrRule(id, sev, cat, tag, title, desc, pattern));
    }

    private static void cap(String tag, String label, Severity alone, String cat, String title, String desc) {
        CAPS.put(tag, new CapInfo(label, alone, cat, title, desc));
    }

    private static void combo(String id, Severity sev, String cat, String title, String desc, List<String> all, List<String> any, boolean jar) {
        COMBOS.add(new Combo(id, sev, cat, title, desc, all, any, jar));
    }

    static {
        cap("EXEC", "Starts processes", Severity.MEDIUM, "Execution", "Starts external programs",
                "Uses Runtime.exec / ProcessBuilder, so it can run any command on your PC.");
        cap("NET", "HTTP connections", null, "Network", null, null);
        cap("SOCKET", "Raw sockets", Severity.LOW, "Network", "Opens raw socket connections",
                "Opens TCP/UDP connections without HTTP – typical for C2 channels, but also used by proxies or voice chat.");
        cap("SERVER_SOCKET", "Listens on ports", Severity.LOW, "Network", "Opens a local server port",
                "Starts a server socket. Can be abused for remote access (backdoor).");
        cap("FILE_WRITE", "Writes files", null, "File system", null, null);
        cap("FILE_READ", "Reads files", null, "File system", null, null);
        cap("FILE_WALK", "Lists folders", null, "File system", null, null);
        cap("FILE_DELETE", "Deletes files", null, "File system", null, null);
        cap("CLASSLOAD", "URLClassLoader", Severity.MEDIUM, "Code loading", "Creates its own class loaders",
                "Creates a URLClassLoader, which can load foreign JARs or classes at runtime.");
        cap("DEFINE_CLASS", "Defines classes from bytes", Severity.MEDIUM, "Code loading", "Defines classes directly from bytes",
                "Calls defineClass – code is created from a byte array that is not a normal class in the JAR.");
        cap("REFLECT", "Reflection", null, "Obfuscation", null, null);
        cap("NATIVE", "Native libraries", Severity.LOW, "Execution", "Loads native libraries",
                "System.load/loadLibrary or JNA – native code runs outside the Java sandbox.");
        cap("DPAPI", "Windows DPAPI", Severity.HIGH, "Data theft", "Decrypts protected Windows data (DPAPI)",
                "CryptUnprotectData is almost only used to decrypt saved browser passwords and cookies.");
        cap("B64", "Base64 decoding", null, "Obfuscation", null, null);
        cap("CRYPTO", "Encryption", null, "Obfuscation", null, null);
        cap("SCREEN", "Screen capture", Severity.MEDIUM, "Spying", "Takes screenshots of the desktop",
                "java.awt.Robot.createScreenCapture captures the whole screen (not just the game).");
        cap("CLIPBOARD_READ", "Reads clipboard", null, "Spying", null, null);
        cap("CLIPBOARD_WRITE", "Writes clipboard", null, "Spying", null, null);
        cap("KEYHOOK", "Global keyboard hook", Severity.HIGH, "Spying", "Global keyboard/mouse hook (JNativeHook)",
                "Registers system-wide keyboard events – even outside Minecraft. Classic keylogger tool.");
        cap("ZIP_WRITE", "Writes ZIP/JAR", null, "File system", null, null);
        cap("JAR_READ", "Opens JAR files", null, "File system", null, null);
        cap("ENV", "Environment variables", null, "System", null, null);
        cap("SYSINFO", "System/hardware info", null, "System", null, null);
        cap("UNSAFE", "sun.misc.Unsafe", null, "Obfuscation", null, null);
        cap("INSTRUMENT", "Java instrumentation", Severity.LOW, "Code loading", "Uses Java instrumentation",
                "Can modify loaded classes at runtime.");
        cap("ATTACH", "Attaches to other JVMs", Severity.MEDIUM, "Code loading", "Attaches to other Java processes",
                "VirtualMachine.attach injects agents into other Java processes.");
        cap("CODESOURCE", "Own JAR path", null, "System", null, null);
        cap("DESKTOP", "Opens browser/files", null, "System", null, null);
        cap("MC_SESSION", "Minecraft session", null, "Minecraft", null, null);
        cap("MC_TOKEN", "Minecraft access token", Severity.MEDIUM, "Minecraft", "Reads the Minecraft access token",
                "The session token lets anyone log in as you without a password. Normal mods almost never need it.");
        cap("MC_CHAT_SEND", "Sends chat/commands", null, "Minecraft", null, null);
        cap("BUKKIT_OP", "setOp()", Severity.MEDIUM, "Server backdoor", "Grants operator rights (setOp)",
                "The plugin can give players OP. Legit for admin plugins, but the core of almost every force-OP backdoor.");
        cap("BUKKIT_DISPATCH", "Console commands", null, "Server backdoor", null, null);
        cap("BUKKIT_CHAT_EVENT", "Reads chat events", null, "Server backdoor", null, null);
        cap("BUKKIT_ECONOMY", "Vault economy", null, "Server backdoor", null, null);
        cap("BUKKIT_PERM", "Permission attachments", Severity.LOW, "Server backdoor", "Sets permissions directly",
                "Creates PermissionAttachments – can silently give players permissions.");

        str("EXFIL_DISCORD_WEBHOOK", Severity.HIGH, "Data exfiltration", "S_EXFIL", "Discord webhook URL",
                "A Discord webhook is the most common way to send stolen data (tokens, passwords, IP) to the attacker.",
                p("discord(app)?\\.com/api(/v\\d+)?/webhooks/|canary\\.discord\\.com/api/webhooks|ptb\\.discord\\.com/api/webhooks"));
        str("EXFIL_TELEGRAM", Severity.HIGH, "Data exfiltration", "S_EXFIL", "Telegram bot API",
                "Sends data through a Telegram bot – a popular exfiltration channel for stealers.",
                p("api\\.telegram\\.org/(bot|file/bot)"));
        str("EXFIL_CATCHER", Severity.HIGH, "Data exfiltration", "S_EXFIL", "Request catcher / exfil service",
                "Services like webhook.site or pipedream collect arbitrary HTTP requests – no legit mod needs that.",
                p("webhook\\.site|requestbin|pipedream\\.net|beeceptor\\.com|hookbin\\.com|interact\\.sh|\\.oast\\.(fun|me|pro|site|live)|canarytokens"));
        str("REMOTE_PASTE", Severity.MEDIUM, "Downloader", "S_REMOTE", "Loads content from paste sites",
                "Raw paste links are often used to fetch the real webhook URL or payload without changing the JAR.",
                p("pastebin\\.com/raw|hastebin\\.(com|skyra\\.pw)/raw|rentry\\.(co|org)/[^/]+/raw|paste\\.ee/r/|pastes\\.io/raw|ghostbin|controlc\\.com|privatebin|justpaste\\.it|paste\\.gg/p/"));
        str("REMOTE_TUNNEL", Severity.MEDIUM, "Downloader", "S_REMOTE", "Tunnel / dynamic DNS domain",
                "ngrok, DuckDNS, No-IP and co. hide the attacker's server behind changing addresses.",
                p("ngrok\\.io|ngrok-free\\.app|ngrok\\.app|trycloudflare\\.com|duckdns\\.org|no-ip\\.(com|org|biz|info)|ddns\\.net|hopto\\.org|zapto\\.org|serveo\\.net|localhost\\.run|loca\\.lt|portmap\\.io|bore\\.pub"));
        str("REMOTE_FILEHOST", Severity.MEDIUM, "Downloader", "S_REMOTE", "Anonymous file host",
                "Anonymous file hosts are used to deliver second-stage malware or upload stolen data.",
                p("transfer\\.sh|file\\.io|gofile\\.io|anonfiles|catbox\\.moe|litterbox|0x0\\.st|bashupload|temp\\.sh|mediafire\\.com/file|mega\\.nz|pixeldrain|uguu\\.se|filebin\\.net|krakenfiles"));
        str("REMOTE_DISCORD_CDN", Severity.MEDIUM, "Downloader", "S_REMOTE", "Discord CDN file link",
                "Downloading executables from Discord attachments is a typical loader pattern.",
                p("(cdn\\.discordapp\\.com|media\\.discordapp\\.net)/attachments/\\S+\\.(jar|exe|dll|bat|ps1|vbs|scr|zip|class|bin)"));
        str("REMOTE_RAW_IP", Severity.MEDIUM, "Network", "S_REMOTE", "URL with a hard-coded IP address",
                "Connecting to a fixed IP instead of a domain is typical for C2 servers.",
                p("(https?|wss?|tcp)://(?!127\\.|0\\.0\\.0\\.0|10\\.|192\\.168\\.|255\\.)\\d{1,3}(\\.\\d{1,3}){3}(:\\d+)?"));
        str("IP_GRABBER", Severity.MEDIUM, "Data theft", "S_IPGRAB", "Looks up your public IP",
                "Queries your public IP – a classic part of IP grabbers.",
                p("api\\d?\\.ipify\\.org|checkip\\.amazonaws\\.com|ip-api\\.com|ipinfo\\.io|icanhazip\\.com|ifconfig\\.(me|co)|myexternalip|ipapi\\.co|wtfismyip|ident\\.me|geolocation-db|ipwho\\.is|freegeoip|iplogger|grabify|2no\\.co|yip\\.su"));
        str("STEAL_BROWSER", Severity.HIGH, "Data theft", "S_STEAL", "Accesses browser passwords/cookies",
                "Paths to 'Login Data', 'Local State' or Firefox key files are only needed by password stealers.",
                p("Login Data|Local State|encrypted_key|Web Data|key[34]\\.db|logins\\.json|cookies\\.sqlite|Network{S}Cookies|User Data{S}Default|signons\\.sqlite|app_bound_encrypted_key"));
        str("STEAL_BROWSER_PATH", Severity.MEDIUM, "Data theft", "S_BROWSER", "Browser profile folders",
                "References browser profile folders (Chrome, Brave, Opera, Edge, Firefox …).",
                p("Google{S}Chrome|BraveSoftware|Opera Software|Yandex{S}YandexBrowser|Microsoft{S}Edge|Mozilla{S}Firefox|Vivaldi{S}User Data|Chromium{S}User Data|Epic Privacy Browser|CentBrowser|Iridium{S}User Data"));
        str("STEAL_DISCORD", Severity.HIGH, "Data theft", "S_STEAL", "Accesses Discord token storage",
                "Discord tokens live in 'Local Storage/leveldb'. A mod has no business there.",
                p("Local Storage{S}leveldb|discordcanary|discordptb|Lightcord|{S}discord{S}Local|AppData{S}Roaming{S}discord|\\.ldb$|leveldb"));
        str("STEAL_DISCORD_REGEX", Severity.CRITICAL, "Data theft", "S_STEAL", "Regex for finding Discord tokens",
                "This pattern searches files for Discord tokens – a clear sign of a token grabber.",
                p("\\[\\\\w-\\]\\{2[4-6]\\}|\\[a-zA-Z0-9_-\\]\\{2[3-6]\\}\\\\?\\.|mfa\\\\\\.\\[|dQw4w9WgXcQ:|\\[\\\\w-\\]\\{84\\}|\\[\\\\d\\\\w_-\\]\\{2[4-6]\\}"));
        str("STEAL_MC_ACCOUNTS", Severity.HIGH, "Data theft", "S_STEAL", "Accesses launcher accounts",
                "Reads account/token files of other launchers (Vanilla, Lunar, Feather, Essential, TLauncher, Prism …).",
                p("launcher_accounts(_microsoft_store)?\\.json|launcher_profiles\\.json|launcher_msa_credentials|\\.lunarclient{S}settings{S}game{S}accounts|lunarclient.{0,40}accounts\\.json|essential{S}microsoft_accounts|microsoft_accounts\\.json|TLauncherProfiles\\.json|tlauncher_profiles|\\.feather{S}accounts|feather{S}accounts\\.json|PrismLauncher{S}accounts\\.json|PolyMC{S}accounts\\.json|MultiMC{S}accounts\\.json|\\.tlauncher{S}|Badlion Client{S}accounts|ATLauncher{S}configs{S}accounts|GDLauncher.{0,30}accounts|salwyrr|labymod{S}accounts"));
        str("STEAL_WALLET", Severity.HIGH, "Data theft", "S_STEAL", "Accesses crypto wallets",
                "Paths/IDs of crypto wallets (Exodus, Electrum, MetaMask, Phantom …) – the target of wallet stealers.",
                p("exodus\\.wallet|Exodus{S}|Electrum{S}wallets|wallet\\.dat|Ethereum{S}keystore|atomic{S}Local Storage|Coinomi{S}|Jaxx{S}|Armory{S}|nkbihfbeogaeaoehlefnkodbefgpgknn|ejbalbakoplchlghecdalmeeeajnimhm|fhbohimaelbohpjbbldcngcnapndodjp|bfnaelmomeimhlpmgjnjophhpkkoljpa|ibnejdfjmmkpcnlpebklmnkoeoihofec|hnfanknocfeofbddgcijnmhnfnkdnaad|aholpfdialjgjfhomihkjbmgjidlcdno|egjidjbpglichdcondbcbdnbeeppgdph"));
        str("STEAL_TELEGRAM", Severity.HIGH, "Data theft", "S_STEAL", "Accesses Telegram session data",
                "The 'tdata' folder contains the Telegram Desktop session.",
                p("Telegram Desktop{S}tdata|{S}tdata({S}|$)|^tdata$"));
        str("STEAL_STEAM", Severity.HIGH, "Data theft", "S_STEAL", "Accesses Steam login data",
                "ssfn files and loginusers.vdf allow taking over Steam accounts.",
                p("loginusers\\.vdf|config{S}loginusers|^ssfn|{S}ssfn\\d*|Steam{S}config{S}config\\.vdf"));
        str("STEAL_OTHER", Severity.MEDIUM, "Data theft", "S_STEAL", "Accesses credentials of other programs",
                "FileZilla, VPN profiles, SSH keys, AWS credentials, authenticator data …",
                p("FileZilla{S}(recentservers|sitemanager)\\.xml|NordVPN{S}|ProtonVPN{S}|OpenVPN Connect{S}profiles|\\.ssh{S}id_(rsa|ed25519)|WinSCP|Authy Desktop|\\.aws{S}credentials|Outlook{S}Profiles|Thunderbird{S}Profiles|Pidgin{S}accounts\\.xml|Riot Games{S}"));
        str("CLIPPER_REGEX", Severity.HIGH, "Data theft", "S_CRYPTOADDR", "Crypto address pattern",
                "Regex for Bitcoin/Ethereum/Monero addresses – the basis of a clipboard hijacker that swaps copied addresses.",
                pc("\\(bc1\\|\\[13\\]\\)|\\[13\\]\\[a-km-zA-HJ-NP-Z1-9\\]|0x\\[a-fA-F0-9\\]\\{40\\}|\\^4\\[0-9AB\\]|\\[LM3\\]\\[a-km-zA-HJ-NP-Z1-9\\]|\\^T\\[A-Za-z1-9\\]\\{33\\}"));
        str("CRYPTO_ADDRESS", Severity.MEDIUM, "Data theft", "S_CRYPTOADDR", "Hard-coded crypto address",
                "A built-in wallet address – in clippers, the attacker's address.",
                pc("^(bc1q[a-z0-9]{38,58}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}|T[A-HJ-NP-Za-km-z1-9]{33})$"));
        str("PERSIST_WINDOWS", Severity.HIGH, "Persistence", "S_PERSIST", "Windows autostart persistence",
                "Startup folder, Run registry keys or scheduled tasks – the malware restarts with every Windows boot, even without Minecraft.",
                p("Start Menu{S}Programs{S}Startup|CurrentVersion{S}Run(Once)?\\b|reg(\\.exe)? add|schtasks|/sc (onlogon|onstart|minute)|Winlogon{S}|User Shell Folders|shell:startup|HKCU{S}Software{S}Microsoft{S}Windows|HKEY_CURRENT_USER{S}Software{S}Microsoft{S}Windows{S}CurrentVersion"));
        str("PERSIST_UNIX", Severity.MEDIUM, "Persistence", "S_PERSIST", "Linux/macOS autostart persistence",
                "LaunchAgents, crontab, systemd or shell rc files – the program restarts automatically.",
                p("Library{S}LaunchAgents|LaunchDaemons|crontab|\\.bashrc|\\.zshrc|\\.bash_profile|systemd{S}user|/etc/systemd/system|\\.config{S}autostart|/etc/rc\\.local|launchctl (load|bootstrap)"));
        str("EVASION_AV", Severity.CRITICAL, "Evasion", "S_EVASION", "Disables antivirus/Defender",
                "Adds Defender exclusions or disables real-time protection – clearly malicious.",
                p("Add-MpPreference|Set-MpPreference|ExclusionPath|ExclusionProcess|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableAntiSpyware|DisableIOAVProtection|vssadmin.{0,20}delete|bcdedit|wevtutil cl|netsh advfirewall set|sc stop WinDefend|Windows Defender{S}Exclusions"));
        str("SHELL_DOWNLOAD", Severity.HIGH, "Execution", "S_SHELL", "Shell download command (LOLBin)",
                "PowerShell/certutil/bitsadmin commands that download and run code.",
                p("Invoke-WebRequest|DownloadString|DownloadFile|Invoke-Expression|IEX\\s*\\(|-EncodedCommand|-ExecutionPolicy\\s+Bypass|-ep bypass|-w(indowstyle)? hidden|certutil.{0,20}-urlcache|bitsadmin.{0,10}/transfer|mshta(\\.exe)?\\s+https?|regsvr32.{0,20}/i:|rundll32.{0,30}javascript|curl[^|]{0,200}\\|\\s*(ba|z)?sh|wget[^|]{0,200}\\|\\s*(ba|z)?sh|Start-Process.{0,40}-WindowStyle Hidden"));
        str("SHELL_POWERSHELL", Severity.LOW, "Execution", "S_SHELL", "Calls PowerShell/script hosts",
                "Starts powershell, wscript, cscript or mshta.",
                p("^(powershell|pwsh|wscript|cscript|mshta)(\\.exe)?$|\\bpowershell(\\.exe)? -"));
        str("EXEC_FILE_EXT", Severity.LOW, "Execution", "S_EXECEXT", "Executable file name",
                "References .exe/.dll/.bat/.ps1/.vbs – often the target of a dropper.",
                p("^[^\\s<>\"]{1,120}\\.(exe|dll|scr|bat|cmd|ps1|vbs|vbe|hta|msi|lnk|jse)$"));
        str("MINER", Severity.CRITICAL, "Crypto miner", "S_MINER", "Crypto miner",
                "Mining pool addresses or XMRig parameters – your PC is secretly used for mining.",
                p("stratum\\+(tcp|ssl|tls)|xmrig|--donate-level|cryptonight|minexmr|nanopool\\.org|supportxmr|moneroocean|2miners\\.com|nicehash\\.com|hashvault\\.pro|--cpu-max-threads-hint|c3pool|herominers|unmineable|--coin\\s+monero|rx/0"));
        str("EVASION_ANALYSIS", Severity.MEDIUM, "Evasion", "S_EVASION", "Anti-VM / anti-analysis",
                "Looks for VirtualBox, sandboxes, debuggers or reverse-engineering tools to hide from analysis.",
                p("VBoxService|VBoxTray|vboxmrxnp|VBOX HARDDISK|VMware Tools|vmtoolsd|qemu-ga|SbieDll|sandboxie|wireshark|procmon|processhacker|x64dbg|ollydbg|ida64|fiddler|httpdebugger|Recaf|bytecode-?viewer|jd-gui|-agentlib:jdwp|-Xrunjdwp|HTTP Toolkit|charles proxy"));
        str("SYSINFO_STR", null, "System", "S_SYSINFO", null, null,
                p("^(COMPUTERNAME|USERNAME|USERPROFILE|PROCESSOR_IDENTIFIER|PROCESSOR_ARCHITECTURE|user\\.name|whoami|systeminfo|hwid|wmic.{0,60}|csproduct|SerialNumber|MachineGuid)$"));
        str("MODS_DIR", null, "File system", "S_MODSDIR", null, null,
                p("(^|[\\\\/])(mods|plugins)([\\\\/]|$)|\\.minecraft|^mods$|^plugins$"));
        str("JAR_EXT", null, "File system", "S_JAREXT", null, null, p("\\.jar$|^\\.jar$|^jar$"));
        str("UUID", null, "Minecraft", "S_UUID", null, null, p("^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$"));
        str("TOKEN_WORD", null, "Minecraft", "S_TOKENWORD", null, null,
                p("^(accessToken|access_token|sessionId|session_id|refresh_token|refreshToken|XBL3\\.0.*|mcToken|minecraft_token|ssid)$|\\\"accessToken\\\"|token=|&token|\\?token"));
        str("DEFINE_STR", null, "Code loading", "DEFINE_CLASS", null, null, pc("^(defineClass|defineClass0|defineClass1|defineHiddenClass|defineAnonymousClass)$"));
        str("DPAPI_STR", null, "Data theft", "DPAPI", null, null, pc("CryptUnprotectData|Crypt32Util|NCryptUnprotectSecret"));
        str("PAY_COMMAND", Severity.MEDIUM, "Minecraft", "S_PAY", "/pay or trade command in code",
                "The code contains a money/trade command. Combined with automatic chat sending this is a classic 'auto-pay' stealer that sends your in-game money to the author.",
                pc("^/?(pay|epay|tpay|givemoney|sendmoney|money (pay|give|send)|eco (give|set)|bal(ance)? (give|send)|coins? (give|pay|send)|gems? (pay|give)) [A-Za-z0-9_%{}$.\\-]|^/(trade|ah sell|ah list|auction (sell|list)|gift|withdraw|bank (transfer|send)|transfer) ?|^(pay|tpay|epay) $"));
        str("PAY_HARDCODED", Severity.HIGH, "Minecraft", "S_PAY", "Hard-coded /pay command with a target",
                "A /pay command with a fixed recipient and/or amount – sends your money to a specific player.",
                p("^/?(pay|epay|money pay|givemoney|sendmoney|tpay|coins? pay) [A-Za-z0-9_]{3,16} (\\d|all|%)"));
        str("OP_COMMAND", Severity.LOW, "Server backdoor", "S_OPCMD", "Operator/permission command in code",
                "Commands like /op, LuckPerms or PEX permission grants.",
                p("^/?(minecraft:)?(op|deop) [A-Za-z0-9_%{}$]|^/?(op|deop) $|^/?lp user .{1,40} (permission set|parent (add|set))|^/?luckperms user|^/?pex user .{1,40} (add|group set)|^/?(manuadd|mangadd) |^/?gamemode (creative|1) |^/?whitelist add |^/?(minecraft:)?op$"));
        str("C2_BLOCKCHAIN", Severity.HIGH, "Data exfiltration", "S_C2", "Blockchain used as C2 address book (EtherHiding)",
                "Queries a smart contract on Polygon/Ethereum/BSC via eth_call. Malware like SilentNet stores its current server address there so the server can never be taken down. No normal mod talks to a blockchain.",
                p("eth_call|eth_getStorageAt|eth_getLogs|polygon-rpc\\.com|polygon(-bor)?(-rpc)?\\.publicnode\\.com|polygon\\.drpc\\.org|1rpc\\.io/(matic|eth|bnb)|rpc-mainnet\\.matic|quiknode\\.pro|bsc-dataseed|bsc-rpc\\.|infura\\.io|alchemy(api)?\\.io|rpc\\.ankr\\.com|trongrid\\.io|api\\.zan\\.top|polygon-mainnet|llamarpc\\.com|cloudflare-eth\\.com"));
        str("DOH", Severity.MEDIUM, "Evasion", "S_REMOTE", "DNS-over-HTTPS",
                "Resolves domains itself over HTTPS (Cloudflare/Google DoH), bypassing DNS blocks and Pi-hole – typical for malware hiding its server.",
                p("dns-query|cloudflare-dns\\.com|dns\\.google/(resolve|dns-query)|doh\\.opendns|dns\\.quad9\\.net/dns-query|mozilla\\.cloudflare-dns"));
        str("PYTHON_RUNTIME", Severity.HIGH, "Execution", "S_SHELL", "Starts a bundled Python runtime",
                "Downloads or unpacks a portable Python environment and runs a script – Minecraft mods do not need Python. A classic way to load a stealer.",
                p("^pythonw?(\\.exe)?$|^main\\.py$|python-3\\.\\d+(\\.\\d+)?-embed|portable runtime|python3\\d\\._pth"));
        str("STEALER_WORDS", Severity.CRITICAL, "Data theft", "S_STEAL", "Stealer wording in code",
                "The code refers to itself as a stealer/grabber.",
                p("spawning stealer|stealer spawned|_stealer\\.log|token ?grabber|discord ?grabber|password ?stealer|cookie ?stealer|rat ?payload"));
        str("MC_TOKEN_REFLECT", Severity.HIGH, "Minecraft", "MC_TOKEN", "Reads the access token via reflection",
                "Method/field names of the Minecraft session token appear as text in the code, so the token is read via reflection – a trick to dodge scanners that only check direct calls.",
                pc("^(getAccessToken|method_1674|field_1983|func_148254_d|field_148258_c|f_92536_|m_92547_|getSessionId)$"));
        str("MC_TOKEN_JSON", Severity.MEDIUM, "Minecraft", "S_TOKENWORD", "Builds JSON containing accessToken",
                "A JSON object with an accessToken field is built – usually to send the token somewhere.",
                p("\"accessToken\"\\s*:|,\"accessToken\":\"|\"mcUuid\"|\"mcUsername\""));
        str("MC_SESSION_REFLECT", null, "Minecraft", "MC_SESSION", null, null,
                pc("^(net\\.minecraft\\.class_310|net\\.minecraft\\.client\\.MinecraftClient|net\\.minecraft\\.client\\.Minecraft|method_1548|field_1726|method_1551|field_1700|getSession|class_320)$"));
        str("RAW_HTTP", null, "Network", "S_RAWHTTP", null, null, pc("HTTP/1\\.[01]\\r?\\n|^Host: |^GET /|^POST /|^PUT /|Sec-WebSocket-Key|^Connection: (close|Upgrade)"));
        str("JAVA_LAUNCH", null, "Execution", "S_JAVALAUNCH", null, null, pc("^(javaw?(\\.exe)?|java\\.home|-cp|-classpath|-jar|bin)$"));
        str("DETACH", null, "Evasion", "S_DETACH", null, null, pc("^(NUL|/dev/null|-restarted|--restarted|-Detached|--detached|nohup|setsid)$|DETACHED|start /b|CREATE_NO_WINDOW"));
        str("MALFORMED_UTF", null, "Obfuscation", "S_WEIRD", null, null, pc("[\\u202E\\u200B\\u200C\\u200D\\uFEFF]"));

        combo("TOKEN_EXFIL", Severity.CRITICAL, "Minecraft", "Session token stealer",
                "Reads the Minecraft access token and sends data to a webhook/exfil service. The attacker can take over your account with it.",
                List.of("S_EXFIL"), List.of("MC_TOKEN", "S_TOKENWORD"), true);
        combo("TOKEN_EXFIL_B", Severity.CRITICAL, "Minecraft", "Session token stealer",
                "Reads the Minecraft access token and sends data to a webhook/exfil service. The attacker can take over your account with it.",
                List.of("S_EXFIL"), List.of("MC_TOKEN", "MC_SESSION"), true);
        combo("TOKEN_NET", Severity.HIGH, "Minecraft", "Access token + network",
                "The same class reads the Minecraft access token and opens a network connection.",
                List.of("MC_TOKEN"), List.of("NET", "SOCKET"), false);
        combo("STEALER", Severity.CRITICAL, "Data theft", "Data stealer with upload",
                "Accesses passwords/tokens/wallets of other programs and has a way to send them out.",
                List.of("S_STEAL"), List.of("S_EXFIL", "NET", "SOCKET"), true);
        combo("DPAPI_STEALER", Severity.CRITICAL, "Data theft", "Browser password stealer",
                "Combines DPAPI decryption with browser/credential paths – decrypts saved passwords and cookies.",
                List.of("DPAPI"), List.of("S_STEAL", "S_BROWSER"), true);
        combo("REMOTE_LOADER", Severity.CRITICAL, "Code loading", "Downloads code from the internet and runs it",
                "Loads bytes over the network and defines classes from them – the real malware is not in the JAR and can be swapped at any time.",
                List.of("DEFINE_CLASS"), List.of("NET", "SOCKET"), false);
        combo("URL_LOADER", Severity.HIGH, "Code loading", "Loads classes from a remote source",
                "A URLClassLoader combined with network access or suspicious download addresses (stage-2 loader).",
                List.of("CLASSLOAD"), List.of("NET", "S_REMOTE", "S_EXFIL"), false);
        combo("MEMORY_LOADER", Severity.HIGH, "Code loading", "Decrypts hidden code in memory",
                "Base64/encryption plus defineClass: hidden code is unpacked and loaded only at runtime.",
                List.of("DEFINE_CLASS"), List.of("B64", "CRYPTO"), false);
        combo("DROPPER", Severity.CRITICAL, "Downloader", "Dropper: download + save + execute",
                "Downloads a file, saves it and runs it or loads it as code. Classic behaviour of second-stage malware.",
                List.of("NET", "FILE_WRITE"), List.of("EXEC", "CLASSLOAD"), false);
        combo("DOWNLOAD_EXEC", Severity.HIGH, "Execution", "Network + process start",
                "The same class talks to the internet and starts external programs.",
                List.of("NET", "EXEC"), List.of(), false);
        combo("DOWNLOAD_EXE", Severity.HIGH, "Downloader", "Downloads executable files",
                "Download and save together with .exe/.dll/.bat/.ps1 file names.",
                List.of("NET", "FILE_WRITE", "S_EXECEXT"), List.of(), false);
        combo("MOD_INSTALLER", Severity.HIGH, "Downloader", "Installs extra JARs into mods/plugins",
                "Downloads JAR files into the mods/plugins folder. Legit auto-updaters do this too – check the download address carefully.",
                List.of("NET", "FILE_WRITE", "S_MODSDIR", "S_JAREXT"), List.of(), true);
        combo("JAR_INFECTOR", Severity.HIGH, "Infection", "Modifies other JAR files",
                "Reads JARs and writes new JAR/ZIP files – how worm infectors like fractureiser spread to other mods.",
                List.of("JAR_READ", "ZIP_WRITE", "FILE_WALK", "S_JAREXT"), List.of(), false);
        combo("JAR_INFECTOR_MODS", Severity.CRITICAL, "Infection", "Infects mods/plugins (worm)",
                "Searches the mods/plugins folder and rewrites JAR files – spreads to all your other mods.",
                List.of("JAR_READ", "ZIP_WRITE", "S_MODSDIR", "S_JAREXT"), List.of(), true);
        combo("CLIPPER", Severity.CRITICAL, "Data theft", "Clipboard hijacker (clipper)",
                "Reads/replaces the clipboard and knows crypto address patterns – copied wallet addresses get swapped for the attacker's.",
                List.of("S_CRYPTOADDR"), List.of("CLIPBOARD_WRITE", "CLIPBOARD_READ"), true);
        combo("SCREEN_EXFIL", Severity.HIGH, "Spying", "Screenshots with upload",
                "Captures your desktop and has an upload channel.",
                List.of("SCREEN"), List.of("NET", "S_EXFIL"), true);
        combo("KEYLOGGER", Severity.CRITICAL, "Spying", "Keylogger",
                "Global keyboard hook with a way to save or upload keystrokes.",
                List.of("KEYHOOK"), List.of("NET", "S_EXFIL", "FILE_WRITE"), true);
        combo("FORCE_OP", Severity.CRITICAL, "Server backdoor", "Force-OP backdoor",
                "Reads chat messages and grants OP – a secret chat password gives the attacker full server rights.",
                List.of("BUKKIT_CHAT_EVENT", "BUKKIT_OP"), List.of(), true);
        combo("CHAT_CONSOLE", Severity.HIGH, "Server backdoor", "Chat-controlled console commands",
                "Chat messages trigger console commands with permission commands.",
                List.of("BUKKIT_CHAT_EVENT", "BUKKIT_DISPATCH", "S_OPCMD"), List.of(), true);
        combo("CHAT_DISPATCH", Severity.MEDIUM, "Server backdoor", "Chat events + console commands",
                "The same class reads chat messages and runs commands as console – check for a hidden trigger.",
                List.of("BUKKIT_CHAT_EVENT", "BUKKIT_DISPATCH"), List.of(), false);
        combo("HARDCODED_OP", Severity.HIGH, "Server backdoor", "OP for a hard-coded UUID",
                "setOp combined with a built-in player UUID.",
                List.of("BUKKIT_OP", "S_UUID"), List.of(), false);
        combo("ECONOMY_BACKDOOR", Severity.HIGH, "Server backdoor", "Economy manipulation for fixed players",
                "Vault economy access together with hard-coded UUIDs or chat triggers.",
                List.of("BUKKIT_ECONOMY"), List.of("S_UUID", "BUKKIT_CHAT_EVENT"), false);
        combo("AUTO_PAY", Severity.CRITICAL, "Minecraft", "Auto-/pay stealer",
                "Sends /pay or trade commands from your account on its own – your in-game money ends up with the attacker.",
                List.of("MC_CHAT_SEND", "S_PAY"), List.of(), false);
        combo("FORCED_OP_CMD", Severity.HIGH, "Server backdoor", "Sends OP/permission commands",
                "Runs /op or permission commands automatically.",
                List.of("S_OPCMD"), List.of("MC_CHAT_SEND", "BUKKIT_DISPATCH"), false);
        combo("SYSINFO_EXFIL", Severity.HIGH, "Data theft", "System/IP info sent to webhook",
                "Collects PC name, user name, HWID or IP and has a webhook/exfil channel.",
                List.of("S_EXFIL"), List.of("S_SYSINFO", "SYSINFO", "S_IPGRAB"), true);
        combo("REVERSE_SHELL", Severity.CRITICAL, "Backdoor", "Remote shell / backdoor",
                "Socket connection combined with process execution – the attacker can run commands on your PC.",
                List.of("EXEC"), List.of("SOCKET", "SERVER_SOCKET"), false);
        combo("PERSIST_EXEC", Severity.HIGH, "Persistence", "Sets up autostart",
                "Autostart paths/commands together with process start or file writes.",
                List.of("S_PERSIST"), List.of("EXEC", "FILE_WRITE"), false);
        combo("BLOB_LOADER", Severity.HIGH, "Code loading", "Encrypted container + class loader",
                "The JAR contains encrypted data blobs and code that defines classes from bytes – typical for packed malware.",
                List.of("R_BLOB", "DEFINE_CLASS"), List.of(), true);
        combo("HIDDEN_CLASS_LOADER", Severity.HIGH, "Code loading", "Disguised classes get loaded",
                "Class files are disguised as resources and the JAR contains its own class loading code.",
                List.of("R_HIDDENCLASS"), List.of("DEFINE_CLASS", "CLASSLOAD"), true);

        combo("SELF_RELAUNCH", Severity.HIGH, "Evasion", "Relaunches itself as a separate Java process",
                "Finds the path of its own JAR and starts it with java/javaw as a separate process. The code keeps running independently of Minecraft – even after you close the game.",
                List.of("EXEC", "CODESOURCE", "S_JAVALAUNCH"), List.of(), true);
        combo("HIDDEN_PROCESS", Severity.CRITICAL, "Evasion", "Hidden background process",
                "Starts a Java process whose output goes to NUL or that is marked 'restarted/detached'. Malware keeps running invisibly this way (known from SilentNet).",
                List.of("EXEC", "S_JAVALAUNCH", "S_DETACH"), List.of(), true);
        combo("RAW_HTTP_CLIENT", Severity.HIGH, "Evasion", "Hand-made HTTP client over raw sockets",
                "Writes HTTP requests by hand over Socket/SSLSocket instead of using Java's HTTP classes, dodging scanners that look for URL/HttpClient.",
                List.of("SOCKET", "S_RAWHTTP"), List.of(), false);
        combo("BLOCKCHAIN_C2", Severity.CRITICAL, "Data exfiltration", "Blockchain-controlled C2 server",
                "Reads its server address from a blockchain and has a network channel – the attacker's server is practically impossible to take down.",
                List.of("S_C2"), List.of("NET", "SOCKET", "S_RAWHTTP"), true);
        combo("PAYLOAD_EXTRACT_EXEC", Severity.HIGH, "Downloader", "Unpacks a payload and runs it",
                "Unpacks archives to disk and then starts a process – second-stage malware is being deployed.",
                List.of("JAR_READ", "FILE_WRITE", "EXEC"), List.of(), false);
        combo("TOKEN_RAW_EXFIL", Severity.CRITICAL, "Minecraft", "Session token stealer",
                "Reads the Minecraft access token and has a hidden network channel (raw sockets/blockchain C2).",
                List.of("MC_TOKEN"), List.of("S_RAWHTTP", "S_C2", "S_EXFIL"), true);

        loadIocs();
    }

    private static void loadIocs() {
        try (var in = Rules.class.getResourceAsStream("/rules/iocs.json")) {
            if (in == null) return;
            JsonObject root = JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8)).getAsJsonObject();
            for (JsonElement e : root.getAsJsonArray("families")) {
                JsonObject o = e.getAsJsonObject();
                List<String> strings = new ArrayList<>();
                List<String> prefixes = new ArrayList<>();
                if (o.has("strings")) o.getAsJsonArray("strings").forEach(x -> strings.add(x.getAsString().toLowerCase(Locale.ROOT)));
                if (o.has("classes")) o.getAsJsonArray("classes").forEach(x -> prefixes.add(x.getAsString()));
                FAMILIES.add(new Family(o.get("name").getAsString(), Severity.valueOf(o.get("severity").getAsString().toUpperCase(Locale.ROOT)),
                        strings, prefixes, o.has("description") ? o.get("description").getAsString() : ""));
            }
            if (root.has("hashes")) root.getAsJsonArray("hashes").forEach(x -> BAD_HASHES.add(x.getAsString().toLowerCase(Locale.ROOT)));
        } catch (Exception e) {
            System.err.println("iocs.json: " + e);
        }
    }

    static boolean isLibrary(String internalName) {
        for (String p : LIBRARY_PREFIXES) if (internalName.startsWith(p)) return true;
        return false;
    }

    static void callTags(String owner, String name, List<String> out) {
        switch (owner) {
            case "java/lang/Runtime" -> {
                if (name.equals("exec")) out.add("EXEC");
                if (name.equals("load") || name.equals("loadLibrary")) out.add("NATIVE");
            }
            case "java/lang/ProcessBuilder" -> {
                if (name.equals("<init>") || name.equals("start") || name.equals("command") || name.equals("startPipeline")) out.add("EXEC");
            }
            case "java/lang/System" -> {
                if (name.equals("load") || name.equals("loadLibrary")) out.add("NATIVE");
                if (name.equals("getenv")) out.add("ENV");
            }
            case "java/net/URL" -> {
                if (name.equals("openConnection") || name.equals("openStream") || name.equals("getContent")) out.add("NET");
            }
            case "java/net/HttpURLConnection", "javax/net/ssl/HttpsURLConnection", "java/net/URLConnection", "java/net/http/HttpClient",
                 "java/net/http/HttpClient$Builder", "okhttp3/OkHttpClient", "okhttp3/Call", "java/net/http/WebSocket$Builder",
                 "org/apache/http/impl/client/CloseableHttpClient", "org/apache/http/client/HttpClient", "org/apache/hc/client5/http/impl/classic/CloseableHttpClient",
                 "org/java_websocket/client/WebSocketClient" -> {
                if (!name.equals("<clinit>")) out.add("NET");
            }
            case "java/net/Socket", "java/net/DatagramSocket", "javax/net/SocketFactory", "javax/net/ssl/SSLSocketFactory" -> {
                if (name.equals("<init>") || name.equals("connect") || name.equals("createSocket")) out.add("SOCKET");
            }
            case "java/nio/channels/SocketChannel", "java/nio/channels/AsynchronousSocketChannel" -> {
                if (name.equals("open") || name.equals("connect")) out.add("SOCKET");
            }
            case "java/net/ServerSocket", "java/nio/channels/ServerSocketChannel" -> {
                if (name.equals("<init>") || name.equals("open") || name.equals("bind")) out.add("SERVER_SOCKET");
            }
            case "com/sun/net/httpserver/HttpServer" -> {
                if (name.equals("create")) out.add("SERVER_SOCKET");
            }
            case "java/io/FileOutputStream", "java/io/FileWriter", "java/io/PrintWriter" -> {
                if (name.equals("<init>") && !owner.equals("java/io/PrintWriter")) out.add("FILE_WRITE");
            }
            case "java/nio/file/Files" -> {
                switch (name) {
                    case "write", "writeString", "copy", "newOutputStream", "newBufferedWriter", "move", "createFile" -> out.add("FILE_WRITE");
                    case "readAllBytes", "readString", "readAllLines", "newInputStream", "newBufferedReader", "lines" -> out.add("FILE_READ");
                    case "walk", "list", "find", "walkFileTree", "newDirectoryStream" -> out.add("FILE_WALK");
                    case "delete", "deleteIfExists" -> out.add("FILE_DELETE");
                    default -> {
                    }
                }
            }
            case "java/io/File" -> {
                if (name.equals("listFiles") || name.equals("list")) out.add("FILE_WALK");
                if (name.equals("delete") || name.equals("deleteOnExit")) out.add("FILE_DELETE");
            }
            case "java/io/FileInputStream", "java/io/FileReader", "java/io/RandomAccessFile" -> {
                if (name.equals("<init>")) out.add("FILE_READ");
            }
            case "org/apache/commons/io/FileUtils" -> {
                if (name.startsWith("copyURLToFile")) {
                    out.add("NET");
                    out.add("FILE_WRITE");
                } else if (name.startsWith("write") || name.startsWith("copy")) out.add("FILE_WRITE");
                else if (name.startsWith("read")) out.add("FILE_READ");
            }
            case "java/net/URLClassLoader" -> {
                if (name.equals("<init>") || name.equals("newInstance")) out.add("CLASSLOAD");
            }
            case "java/lang/invoke/MethodHandles$Lookup" -> {
                if (name.equals("defineClass") || name.equals("defineHiddenClass") || name.equals("defineHiddenClassWithClassData")) out.add("DEFINE_CLASS");
            }
            case "sun/misc/Unsafe", "jdk/internal/misc/Unsafe" -> {
                out.add("UNSAFE");
                if (name.equals("defineClass") || name.equals("defineAnonymousClass")) out.add("DEFINE_CLASS");
            }
            case "java/lang/reflect/Method" -> {
                if (name.equals("invoke")) out.add("REFLECT");
            }
            case "java/lang/Class" -> {
                if (name.equals("forName") || name.equals("getDeclaredMethod") || name.equals("getMethod")) out.add("REFLECT");
            }
            case "java/util/Base64$Decoder", "javax/xml/bind/DatatypeConverter", "org/apache/commons/codec/binary/Base64", "sun/misc/BASE64Decoder" -> {
                if (name.startsWith("decode") || name.equals("parseBase64Binary") || name.equals("decodeBuffer")) out.add("B64");
            }
            case "javax/crypto/Cipher" -> {
                if (name.equals("getInstance") || name.equals("doFinal")) out.add("CRYPTO");
            }
            case "java/awt/Robot" -> {
                if (name.equals("createScreenCapture") || name.equals("createMultiResolutionScreenCapture")) out.add("SCREEN");
            }
            case "java/awt/Toolkit" -> {
                if (name.equals("getSystemClipboard")) out.add("CLIPBOARD_READ");
            }
            case "java/awt/datatransfer/Clipboard" -> {
                if (name.equals("setContents")) out.add("CLIPBOARD_WRITE");
                if (name.equals("getContents") || name.equals("getData")) out.add("CLIPBOARD_READ");
            }
            case "org/lwjgl/glfw/GLFW" -> {
                if (name.equals("glfwSetClipboardString")) out.add("CLIPBOARD_WRITE");
                if (name.equals("glfwGetClipboardString")) out.add("CLIPBOARD_READ");
            }
            case "java/util/zip/ZipOutputStream", "java/util/jar/JarOutputStream" -> {
                if (name.equals("<init>")) out.add("ZIP_WRITE");
            }
            case "java/util/jar/JarFile", "java/util/zip/ZipFile", "java/util/jar/JarInputStream", "java/util/zip/ZipInputStream" -> {
                if (name.equals("<init>")) out.add("JAR_READ");
            }
            case "java/nio/file/FileSystems" -> {
                if (name.equals("newFileSystem")) out.add("JAR_READ");
            }
            case "java/security/ProtectionDomain", "java/security/CodeSource" -> {
                if (name.equals("getCodeSource") || name.equals("getLocation")) out.add("CODESOURCE");
            }
            case "java/net/NetworkInterface" -> {
                if (name.equals("getHardwareAddress")) out.add("SYSINFO");
            }
            case "java/net/InetAddress" -> {
                if (name.equals("getLocalHost")) out.add("SYSINFO");
            }
            case "com/sun/tools/attach/VirtualMachine" -> {
                if (name.equals("attach") || name.equals("loadAgent")) out.add("ATTACH");
            }
            case "java/lang/instrument/Instrumentation" -> {
                if (name.equals("redefineClasses") || name.equals("retransformClasses") || name.equals("addTransformer")) out.add("INSTRUMENT");
            }
            case "java/awt/Desktop" -> {
                if (name.equals("browse") || name.equals("open")) out.add("DESKTOP");
            }
            case "com/sun/jna/platform/win32/Crypt32Util", "com/sun/jna/platform/win32/Crypt32" -> {
                if (name.toLowerCase(Locale.ROOT).contains("unprotect")) out.add("DPAPI");
                out.add("NATIVE");
            }
            case "com/sun/jna/Native" -> {
                if (name.equals("load") || name.equals("loadLibrary") || name.equals("register")) out.add("NATIVE");
            }
            case "org/bukkit/Bukkit", "org/bukkit/Server", "net/md_5/bungee/api/plugin/PluginManager", "com/velocitypowered/api/command/CommandManager" -> {
                if (name.equals("dispatchCommand") || name.equals("executeAsync") || name.equals("executeImmediatelyAsync")) out.add("BUKKIT_DISPATCH");
            }
            case "org/bukkit/event/player/AsyncPlayerChatEvent", "org/bukkit/event/player/PlayerChatEvent", "org/bukkit/event/player/PlayerCommandPreprocessEvent",
                 "io/papermc/paper/event/player/AsyncChatEvent", "net/md_5/bungee/api/event/ChatEvent", "com/velocitypowered/api/event/player/PlayerChatEvent" -> {
                if (name.equals("getMessage") || name.equals("message") || name.equals("signedMessage") || name.equals("originalMessage")) out.add("BUKKIT_CHAT_EVENT");
            }
            case "net/milkbowl/vault/economy/Economy" -> {
                if (name.equals("depositPlayer") || name.equals("withdrawPlayer") || name.equals("bankDeposit")) out.add("BUKKIT_ECONOMY");
            }
            default -> {
            }
        }
        if (name.equals("defineClass") && !owner.startsWith("java/lang/invoke")) out.add("DEFINE_CLASS");
        if (name.equals("setOp") && (owner.startsWith("org/bukkit/") || owner.contains("bukkit"))) out.add("BUKKIT_OP");
        if (name.equals("addAttachment") && owner.startsWith("org/bukkit/")) out.add("BUKKIT_PERM");
        if ((name.equals("chat") || name.equals("performCommand")) && owner.startsWith("org/bukkit/entity/")) out.add("MC_CHAT_SEND");
        if (owner.startsWith("com/github/kwhat/jnativehook") || owner.startsWith("org/jnativehook")) out.add("KEYHOOK");
        if (owner.startsWith("oshi/hardware") || owner.equals("oshi/SystemInfo")) out.add("SYSINFO");
        if (owner.startsWith("net/minecraft/") || owner.startsWith("com/mojang/")) {
            boolean sessionOwner = owner.contains("class_320") || owner.endsWith("/Session") || owner.equals("net/minecraft/client/User")
                    || owner.endsWith("/session/Session");
            if (sessionOwner) out.add("MC_SESSION");
            switch (name) {
                case "getAccessToken", "method_1674", "func_148254_d", "getSessionID", "func_111286_b", "method_1675", "func_148255_b", "getSessionId" -> {
                    if (sessionOwner || owner.startsWith("com/mojang/authlib")) out.add("MC_TOKEN");
                }
                case "getSession", "method_1548", "func_110432_I", "getUser", "m_91094_" -> {
                    if (owner.contains("class_310") || owner.endsWith("MinecraftClient") || owner.equals("net/minecraft/client/Minecraft")) out.add("MC_SESSION");
                }
                case "sendChatCommand", "sendCommand", "sendChatMessage", "sendUnsignedCommand", "sendChat", "method_45730", "method_45731",
                     "method_45729", "method_44096", "func_71165_d", "m_246175_", "m_246623_", "m_234156_", "chat", "commandUnsigned", "commandSigned" -> {
                    if (!name.equals("chat") || owner.contains("Player")) out.add("MC_CHAT_SEND");
                }
                default -> {
                }
            }
        }
    }

    static void fieldTags(String owner, String name, List<String> out) {
        if (owner.startsWith("net/minecraft/") && (owner.contains("class_320") || owner.endsWith("/Session") || owner.equals("net/minecraft/client/User"))) {
            out.add("MC_SESSION");
            String n = name.toLowerCase(Locale.ROOT);
            if (n.contains("token") || n.equals("field_1985") || n.equals("field_148258_c") || n.equals("f_92536_") || n.contains("sessionid")) out.add("MC_TOKEN");
        }
    }

    static void typeTags(String type, List<String> out) {
        if (type.endsWith("ChatCommandC2SPacket") || type.endsWith("ChatMessageC2SPacket") || type.endsWith("ServerboundChatCommandPacket")
                || type.endsWith("ServerboundChatPacket") || type.endsWith("CPacketChatMessage") || type.endsWith("C01PacketChatMessage")
                || type.endsWith("CommandExecutionC2SPacket") || type.endsWith("class_7472") || type.endsWith("class_7640") || type.endsWith("class_2797"))
            out.add("MC_CHAT_SEND");
        if (type.equals("java/net/URLClassLoader")) out.add("CLASSLOAD");
    }
}
