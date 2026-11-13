package org.ratscanner;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;

final class UrlFetcher {

    record Download(String fileName, byte[] data) {
    }

    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    static Download fetch(String url, long max) throws IOException, InterruptedException {
        URI uri = URI.create(url.trim());
        for (int hop = 0; hop < 6; hop++) {
            check(uri);
            HttpRequest req = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60))
                    .header("User-Agent", "RatScanner/1.0 (+jar malware scanner)").GET().build();
            HttpResponse<InputStream> res = CLIENT.send(req, HttpResponse.BodyHandlers.ofInputStream());
            int code = res.statusCode();
            if (code >= 300 && code < 400) {
                String loc = res.headers().firstValue("location").orElseThrow(() -> new IOException("Redirect without target"));
                res.body().close();
                uri = uri.resolve(loc);
                continue;
            }
            if (code != 200) {
                res.body().close();
                throw new IOException("Server answered with HTTP " + code);
            }
            long len = res.headers().firstValueAsLong("content-length").orElse(-1);
            if (len > max) {
                res.body().close();
                throw new IOException("File is larger than " + (max >> 20) + " MB");
            }
            byte[] data;
            try (InputStream in = res.body()) {
                data = Scanner.readLimited(in, max);
            }
            String name = res.headers().firstValue("content-disposition")
                    .map(cd -> cd.replaceAll("(?i).*filename\\*?=(?:UTF-8'')?\"?([^\";]+)\"?.*", "$1"))
                    .filter(n -> !n.contains("=") && !n.isBlank())
                    .orElseGet(() -> {
                        String p = URLDecoder.decode(res.uri().getPath(), java.nio.charset.StandardCharsets.UTF_8);
                        String n = p.substring(p.lastIndexOf('/') + 1);
                        return n.isBlank() ? "download.jar" : n;
                    });
            return new Download(name, data);
        }
        throw new IOException("Too many redirects");
    }

    private static void check(URI uri) throws IOException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw new IOException("Only http(s) links are allowed");
        String host = uri.getHost();
        if (host == null || host.isBlank()) throw new IOException("Invalid host");
        if (uri.getPort() != -1 && uri.getPort() != 80 && uri.getPort() != 443 && uri.getPort() != 8080 && uri.getPort() != 8443)
            throw new IOException("Port not allowed");
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.equals("metadata.google.internal"))
            throw new IOException("Internal addresses are not allowed");
        for (InetAddress a : InetAddress.getAllByName(host)) {
            if (a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isLinkLocalAddress() || a.isSiteLocalAddress() || a.isMulticastAddress() || isSpecial(a))
                throw new IOException("Private, loopback and cloud metadata addresses are refused");
        }
    }

    private static boolean isSpecial(InetAddress a) {
        byte[] b = a.getAddress();
        if (b.length == 4) {
            int x = b[0] & 0xff, y = b[1] & 0xff;
            return x == 0 || x == 10 || x == 127 || (x == 100 && y >= 64 && y <= 127) || (x == 169 && y == 254) || (x == 172 && y >= 16 && y <= 31)
                    || (x == 192 && y == 168) || (x == 192 && y == 0 && (b[2] & 0xff) == 0) || (x == 198 && (y == 18 || y == 19)) || x >= 224;
        }
        if (b.length == 16) {
            int first = b[0] & 0xff;
            if ((first & 0xfe) == 0xfc) return true;
            boolean v4mapped = true;
            for (int i = 0; i < 10; i++) if (b[i] != 0) v4mapped = false;
            if (v4mapped && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) {
                try {
                    return isSpecial(InetAddress.getByAddress(new byte[]{b[12], b[13], b[14], b[15]})) || (b[12] & 0xff) == 127;
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }
        return false;
    }
}
