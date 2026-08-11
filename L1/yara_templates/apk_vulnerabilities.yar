// =============================================================================
// APK Vulnerability Patterns
// Target: Java/Kotlin source (jadx-decompiled) and raw APK
// Focus: Android security anti-patterns — WebView, crypto, storage, SSL, code loading
// =============================================================================

rule Android_WebView_JavascriptInterface {
    meta:
        category = "other"
        description = "WebView exposes JavaScript bridge — potential XSS-to-RCE if untrusted content loaded"
        severity = "critical"
        scope = "source"
    strings:
        $jsi = "addJavascriptInterface"
    condition:
        any of them
}

rule Android_WebView_JavaScriptEnabled {
    meta:
        category = "other"
        description = "WebView has JavaScript enabled — increases XSS attack surface"
        severity = "high"
        scope = "source"
    strings:
        $jse = "setJavaScriptEnabled"
    condition:
        any of them
}

rule Android_SSL_TrustAll {
    meta:
        category = "other"
        description = "Custom X509TrustManager detected — may bypass SSL validation (MITM risk)"
        severity = "critical"
        scope = "source"
    strings:
        $tm1 = "X509TrustManager"
        $tm2 = "checkServerTrusted"
    condition:
        all of them
}

rule Android_Crypto_WeakAlgorithm {
    meta:
        category = "other"
        description = "Weak or deprecated cryptographic algorithm in use"
        severity = "high"
        scope = "source"
    strings:
        $w1 = "\"DES\"" nocase
        $w2 = "\"AES/ECB\"" nocase
        $w3 = "\"RC4\"" nocase
        $w4 = "\"RSA/ECB\"" nocase
        $w5 = "\"PBEWithMD5\"" nocase
    condition:
        any of ($w*)
}

rule Android_Crypto_StaticIV {
    meta:
        category = "other"
        description = "IvParameterSpec usage — verify IV is not hardcoded or static"
        severity = "medium"
        scope = "source"
    strings:
        $iv = "IvParameterSpec("
    condition:
        any of them
}

rule Android_Storage_WorldReadable {
    meta:
        category = "other"
        description = "World-readable or world-writable file mode — sensitive data exposure risk"
        severity = "high"
        scope = "source"
    strings:
        $wr = "MODE_WORLD_READABLE"
        $ww = "MODE_WORLD_WRITEABLE"
    condition:
        any of them
}

rule Android_Dynamic_CodeLoading {
    meta:
        category = "other"
        description = "Dynamic class loading detected — potential code injection or tampering"
        severity = "high"
        scope = "source"
    strings:
        $dc1 = "DexClassLoader"
        $dc2 = "PathClassLoader"
        $dc3 = "loadDex"
    condition:
        any of ($dc*)
}

rule Android_Secrets_Hardcoded {
    meta:
        category = "other"
        description = "Potential hardcoded credential or secret — review for plaintext secrets"
        severity = "medium"
        scope = "source"
    strings:
        $pw1 = ".password" nocase
        $pw2 = ".secret" nocase
        $pw3 = ".api_key" nocase
        $pw4 = ".apikey" nocase
        $pw5 = ".auth_token" nocase
        $pw6 = ".secret_key" nocase
    condition:
        any of ($pw*)
}
