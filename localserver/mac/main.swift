import Cocoa
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate, NSWindowDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var server: Process?
    var stdinPipe = Pipe()
    var baseURL: URL?

    func applicationDidFinishLaunching(_ n: Notification) {
        buildMenu()
        let cfg = WKWebViewConfiguration()
        cfg.websiteDataStore = .default()
        cfg.preferences.setValue(true, forKey: "developerExtrasEnabled")
        web = WKWebView(frame: .zero, configuration: cfg)
        web.navigationDelegate = self
        web.uiDelegate = self
        web.allowsBackForwardNavigationGestures = true
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 860), styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        window.title = "RatScanner"
        window.minSize = NSSize(width: 760, height: 560)
        window.contentView = web
        window.delegate = self
        window.setFrameAutosaveName("RatScannerMain")
        if !window.setFrameUsingName("RatScannerMain") { window.center() }
        web.loadHTMLString("<html><body style='background:#0b0b0d;color:#888;font:14px -apple-system;display:grid;place-items:center;height:100vh;margin:0'>Starting RatScanner…</body></html>", baseURL: nil)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        startServer()
    }

    func startServer() {
        let res = Bundle.main.resourceURL!
        let p = Process()
        p.executableURL = res.appendingPathComponent("node")
        p.arguments = [res.appendingPathComponent("server/appserver.js").path, res.appendingPathComponent("site").path, "0"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        p.standardInput = stdinPipe
        var buffer = ""
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            guard let s = String(data: h.availableData, encoding: .utf8), !s.isEmpty else { return }
            buffer += s
            if let r = buffer.range(of: #"LISTENING (\d+)"#, options: .regularExpression), self?.baseURL == nil {
                let port = buffer[r].split(separator: " ")[1]
                let url = URL(string: "http://127.0.0.1:\(port)/")!
                DispatchQueue.main.async { self?.baseURL = url; self?.web.load(URLRequest(url: url)); self?.ensureLoaded(tries: 6) }
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self = self, !self.quitting else { return }
                let a = NSAlert()
                a.messageText = "The RatScanner engine stopped"
                a.informativeText = "Exit code \(proc.terminationStatus). Restart the app."
                a.runModal()
                NSApp.terminate(nil)
            }
        }
        do { try p.run(); server = p } catch {
            let a = NSAlert(); a.messageText = "Could not start RatScanner"; a.informativeText = error.localizedDescription; a.runModal(); NSApp.terminate(nil)
        }
    }

    func ensureLoaded(tries: Int) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in
            guard let self = self, let b = self.baseURL, tries > 0 else { return }
            self.web.evaluateJavaScript("!!document.querySelector('header.top')") { r, _ in
                if (r as? Bool) != true { self.web.load(URLRequest(url: b)); self.ensureLoaded(tries: tries - 1) }
            }
        }
    }

    var quitting = false
    func applicationWillTerminate(_ n: Notification) { quitting = true; server?.terminate() }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }

    // Links to other sites open in the normal browser, never inside the app.
    func webView(_ w: WKWebView, decidePolicyFor a: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if a.shouldPerformDownload { decisionHandler(.download); return }
        if let u = a.request.url, u.host == "127.0.0.1" { decisionHandler(.allow); return }
        if let u = a.request.url, let base = baseURL, a.targetFrame?.isMainFrame ?? true, u.scheme == "http" || u.scheme == "https", u.host != base.host || u.port != base.port {
            NSWorkspace.shared.open(u); decisionHandler(.cancel); return
        }
        decisionHandler(.allow)
    }
    func webView(_ w: WKWebView, didFinish n: WKNavigation!) {
        if let b = baseURL, w.url?.host != "127.0.0.1" { w.load(URLRequest(url: b)) }
    }
    func webView(_ w: WKWebView, didFailProvisionalNavigation n: WKNavigation!, withError e: Error) {
        if let b = baseURL { DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { if w.url?.host != "127.0.0.1" { w.load(URLRequest(url: b)) } } }
    }
    func webView(_ w: WKWebView, decidePolicyFor r: WKNavigationResponse, decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        decisionHandler(r.canShowMIMEType ? .allow : .download)
    }
    func webView(_ w: WKWebView, navigationAction: WKNavigationAction, didBecome d: WKDownload) { d.delegate = self }
    func webView(_ w: WKWebView, navigationResponse: WKNavigationResponse, didBecome d: WKDownload) { d.delegate = self }
    func download(_ d: WKDownload, decideDestinationUsing r: URLResponse, suggestedFilename: String, completionHandler: @escaping (URL?) -> Void) {
        let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let safe = suggestedFilename.replacingOccurrences(of: "/", with: "_")
        var dest = dir.appendingPathComponent(safe)
        let ext = dest.pathExtension, stem = dest.deletingPathExtension().lastPathComponent
        var i = 2
        while FileManager.default.fileExists(atPath: dest.path) { dest = dir.appendingPathComponent("\(stem) \(i)" + (ext.isEmpty ? "" : ".\(ext)")); i += 1 }
        completionHandler(dest)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { NSWorkspace.shared.activateFileViewerSelecting([dest]) }
    }
    func webView(_ w: WKWebView, createWebViewWith c: WKWebViewConfiguration, for a: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let u = a.request.url, u.scheme == "http" || u.scheme == "https" { NSWorkspace.shared.open(u) }
        return nil
    }
    func webView(_ w: WKWebView, runOpenPanelWith p: WKOpenPanelParameters, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = p.allowsMultipleSelection
        panel.canChooseDirectories = false
        panel.beginSheetModal(for: window) { r in completionHandler(r == .OK ? panel.urls : nil) }
    }
    func webView(_ w: WKWebView, runJavaScriptAlertPanelWithMessage m: String, initiatedByFrame f: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = m; a.beginSheetModal(for: window) { _ in completionHandler() }
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let app = NSMenu()
        app.addItem(withTitle: "About RatScanner", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        app.addItem(.separator())
        app.addItem(withTitle: "Hide RatScanner", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        app.addItem(withTitle: "Quit RatScanner", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = app
        let fileItem = NSMenuItem(); main.addItem(fileItem)
        let file = NSMenu(title: "File")
        file.addItem(withTitle: "New Scan", action: #selector(newScan), keyEquivalent: "n")
        file.addItem(withTitle: "Open File…", action: #selector(openFile), keyEquivalent: "o")
        file.addItem(withTitle: "Close Window", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        fileItem.submenu = file
        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        let viewItem = NSMenuItem(); main.addItem(viewItem)
        let view = NSMenu(title: "View")
        view.addItem(withTitle: "Reload", action: #selector(reload), keyEquivalent: "r")
        view.addItem(withTitle: "Toggle Full Screen", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f").keyEquivalentModifierMask = [.command, .control]
        viewItem.submenu = view
        NSApp.mainMenu = main
    }
    @objc func newScan() { if let b = baseURL { web.load(URLRequest(url: b)) } }
    @objc func reload() { web.reload() }
    @objc func openFile() { web.evaluateJavaScript("location.hash='#/';setTimeout(()=>document.querySelector('input[type=file]').click(),150)") }

    // Files dropped on the Dock icon or opened with "Open With → RatScanner".
    var pendingFiles: [URL] = []
    func application(_ s: NSApplication, open urls: [URL]) { for u in urls { scanFile(u) } }
    func scanFile(_ u: URL) {
        guard baseURL != nil, web.url?.host == "127.0.0.1" else { DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { self.scanFile(u) }; return }
        guard let data = try? Data(contentsOf: u), data.count <= 300 << 20 else {
            let a = NSAlert(); a.messageText = "File is too large to open this way"; a.informativeText = "Drag files over 300 MB into the RatScanner window instead (up to 1 GB)."; a.runModal(); return
        }
        let b64 = data.base64EncodedString()
        let name = u.lastPathComponent.replacingOccurrences(of: "\\", with: "_").replacingOccurrences(of: "'", with: "_")
        let js = "(()=>{location.hash='#/';const s=atob('\(b64)');const u=new Uint8Array(s.length);for(let k=0;k<s.length;k++)u[k]=s.charCodeAt(k);const dt=new DataTransfer();dt.items.add(new File([u],'\(name)'));const i=document.querySelector('input[type=file]');i.files=dt.files;i.dispatchEvent(new Event('change',{bubbles:true}));})()"
        web.evaluateJavaScript(js)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
