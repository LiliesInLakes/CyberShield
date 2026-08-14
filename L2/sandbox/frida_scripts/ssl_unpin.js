/**
 * L2 Sandbox: Universal SSL Pinning Bypass (ssl_unpin.js)
 *
 * Bypasses SSL/TLS pinning so mitmproxy can intercept traffic.
 * Uses hook-only approach (no Java.registerClass) for ART compatibility.
 */

setTimeout(function() {
Java.perform(function () {
    console.log("[+] Initializing SSL Unpinning Module (deferred)...");

    function report(technique, detail) {
        send({
            type: "finding",
            category: "ssl_unpin",
            severity: "medium",
            technique: technique,
            evidence: detail || "SSL pinning bypassed"
        });
    }

    // 1. SSLContext.init — replace TrustManagers arg with null (accepts all)
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (keyManagers, trustManagers, secureRandom) {
            report("SSLContext.init", "TrustManagers nulled to accept all certs");
            this.init(keyManagers, null, secureRandom);
        };
        console.log("  [✓] Hooked SSLContext.init()");
    } catch (e) {
        console.log("  [~] SSLContext.init hook failed: " + e);
    }

    // 2. OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        try {
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCerts) {
                report("OkHttp3", "CertificatePinner.check bypassed for " + hostname);
            };
            console.log("  [✓] Hooked CertificatePinner.check(String, List)");
        } catch (e) {
            console.log("  [~] CertificatePinner.check(String, List) not present");
        }
        try {
            CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
                report("OkHttp3", "CertificatePinner.check bypassed for " + hostname);
            };
            console.log("  [✓] Hooked CertificatePinner.check(String, Certificate[])");
        } catch (e) {
            console.log("  [~] CertificatePinner.check(String, Certificate[]) not present");
        }
    } catch (e) {
        console.log("  [~] OkHttp3 not present in this app");
    }

    // 3. Conscrypt TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        try {
            TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                report("Conscrypt", "verifyChain bypassed for " + host);
                return untrustedChain;
            };
            console.log("  [✓] Hooked Conscrypt verifyChain()");
        } catch (e) {
            console.log("  [~] Conscrypt verifyChain not hookable: " + e);
        }
    } catch (e) {
        console.log("  [~] Conscrypt TrustManagerImpl not present");
    }

    // 4. WebViewClient SSL error bypass
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        WebViewClient.onReceivedSslError.implementation = function (webView, handler, error) {
            report("WebViewClient", "onReceivedSslError bypassed, proceeding");
            handler.proceed();
        };
        console.log("  [✓] Hooked WebViewClient.onReceivedSslError()");
    } catch (e) {
        console.log("  [~] WebViewClient hook failed: " + e);
    }

    console.log("[+] SSL Unpinning Module ready.");
});
}, 2000);
