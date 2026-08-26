# YARA Rule Diversification: Evasion Techniques, Detection Strategies, and Rule Design Patterns

**Date:** 2026-08-16  
**Scope:** Android banking-malware detection research for CyberShield / APK Sentinel  
**Audience:** Rule engineers, L1 static-analysis maintainers

---

## 1. Evasion Techniques That Defeat Naive String-Matching YARA Rules on Android

### 1.1 Reflection-Based API Calls

**The Evasion:**  
Malware authors use Java Reflection API to invoke private methods and hide method invocations from static analysis. Instead of calling an API method directly by name (e.g., `sendTextMessage()`), the malware uses runtime reflection patterns: `Class.forName()` → `getMethod()` → `invoke()`. This destroys the bytecode call graph that naive string-matching YARA rules rely on.

**What YARA *can* still catch:**

- **Reflection sequence patterns:** The Class.forName(), getMethod(), and Method.invoke() calls themselves must still appear in bytecode. A rule scanning per-class DEX buffers can detect these patterns using structural conditions rather than literal method names.
- **String literals for class/method names:** Even when obfuscated, the string arguments passed to Class.forName() and getMethod() must exist in the DEX constant pool. Encrypted strings decay to high-entropy bytes, which YARA's `math.entropy()` module can flag.
- **Known reflection libraries:** Third-party reflection frameworks leave signature bytecode sequences that are consistent across variants.

**What YARA *cannot* catch without dynamic analysis:**

- **Runtime-resolved method names:** When the class or method name is downloaded from a C2 server, assembled from string fragments, or decrypted at runtime, no static bytecode analysis sees the final name.
- **Method invocation semantics:** YARA cannot determine *which* API the reflected call ultimately targets—that is only known at runtime.

**Recommended detection approach:** Monitor DEX invoke operands (not just string literals) for `Class.forName`, `getMethod`, `getDeclaredMethod` patterns co-located with known-dangerous API invoke operands (e.g., TelephonyManager.sendTextMessage via reflection detected via bytecode opcode sequences).

**Source:** [A Survey and Evaluation of Android-Based Malware Evasion Techniques and Detection Frameworks](https://doi.org/10.3390/info14070374); [Understanding Android Obfuscation Techniques: A Large-Scale Investigation in the Wild](https://arxiv.org/pdf/1801.01633); [Reflection-Aware Static Analysis of Android Apps](http://docteau.github.io/pubs/li-ase16.pdf)

---

### 1.2 String Encryption and Obfuscation

**The Evasion:**  
Malware encrypts strings (API names, C2 domains, command keywords) using XOR, AES, DES, Base64, or custom ciphers. Encrypted payloads appear as high-entropy byte runs rather than readable text. This directly breaks any YARA rule that searches for literal strings.

**What YARA *can* still catch:**

- **High-entropy byte runs:** YARA's `math.entropy()` module can flag sections with entropy > 7.0. This is a weak signal (many benign installers are also packed), but in combination with other indicators (e.g., code in `<clinit>` class initializers, decryption-loop opcodes) it becomes discriminative.
- **Base64-encoded payloads:** YARA provides `base64` and `base64wide` modifiers to search for base64-decoded forms of known strings. Works when the decryption key is static.
- **Single-byte XOR:** The `xor` modifier in YARA can search for XORed variants of known strings across all 256 key values. Applies only when the key is a single byte; cost is 255x search space (must be paired with tight scope guards).
- **Decryption routine signatures:** If malware uses a well-known decryption library (e.g., Bouncy Castle AES, OpenSSL EVP), the library initialization code and crypto operation sequences leave recognizable byte patterns. Signature detection tools like [APIARY](https://www.sciencedirect.com/science/article/pii/S0167404825000860) (2025) automatically generate regex-based rules from API call sequences, which can identify decryption patterns.
- **Entropy-based classifier pipelines:** Tools like DeStroid target string encryption specifically by analyzing entropy spikes and decryption-loop opcode patterns.

**What YARA *cannot* catch:**

- **Dynamically keyed encryption:** When the key is derived from device properties (IMEI, hardware serial) or downloaded from C2, no static rule can decrypt the payload.
- **Custom/rare ciphers:** YARA rules are built around known algorithms. Novel or proprietary ciphers leave no recognizable signature.

**Recommended detection approach:**

1. For **Base64-encoded strings:** Use YARA's base64 modifier on known IoCs (C2 domains, command keywords).
2. For **XOR-encrypted strings:** Use the xor modifier, but limit scope to classes where high entropy is detected first (to avoid false positives).
3. For **structured encryption (AES, DES):** Search for known library setup sequences (e.g., Cipher.getInstance() + key init). Pair with entropy checks on adjacent bytecode regions.
4. As a fallback, require decryption to be dynamic-analysis territory and score encrypted-string presence as a weak positive signal only.

**Source:** [Using Entropy to Identify Obfuscated Malicious Code](https://www.veracode.com/blog/detecting-obfuscated-malicious-code/); [YARA Rules Explained: Structure & Threat Detection Use Cases](https://cymulate.com/cybersecurity-glossary/yara-rules/); [DeStroid – Fighting String Encryption in Android Malware](https://cyberjournal.cecyf.fr/index.php/cybin/en/article/view/31); [Use of Cryptography in Malware Obfuscation](https://arxiv.org/pdf/2212.04008)

---

### 1.3 Dynamic Class Loading (DexClassLoader)

**The Evasion:**  
Malware uses `DexClassLoader` or `BaseDexClassLoader` to load a secondary DEX file at runtime. The primary DEX (what YARA typically scans) contains only a loader stub; the actual malicious code lives in an encrypted archive, downloaded from C2, or stored in a disguised resource. The primary DEX is thus benign-looking.

**What YARA *can* still catch:**

- **DexClassLoader initialization patterns:** YARA can detect the bytecode that instantiates DexClassLoader: the constructor call, argument patterns (paths to external DEX, optimization directories, library paths). This is a reliable per-class signal, though it has high base rate (also used benignly).
- **Dynamic loading in `<clinit>` or `onCreate()`:** Conditional checks in class initializers or Activity lifecycle callbacks (gated on emulator checks, device properties) are suspicious loading patterns.
- **ELF stub with dynamic DEX extraction:** If the primary DEX unpacks a secondary DEX from an ELF `.so` library (a packing pattern seen in Anatsa and others), YARA can detect the ELF extraction opcodes and high-entropy `.so` patterns.
- **Encrypted archive signatures:** If the encrypted DEX is stored as a Base64 blob or ZIP within a resource, YARA can search for ZIP magic bytes or Base64 padding within resource strings.
- **Known packer signatures:** Tools like [APKiD](https://github.com/rednaga/APKiD) use YARA rules to detect specific packers and protectors that rely on DexClassLoader. The rules match against packer library names, initialization sequences, and obfuscation patterns in both APK and DEX scopes.

**What YARA *cannot* catch:**

- **Secondary DEX content:** Once loaded dynamically, the secondary DEX is not present in the static APK, and YARA cannot scan it.
- **Runtime behavior:** Whether the loader actually executes the secondary DEX, what it does with it, or whether it applies anti-debugging checks before loading—all runtime decisions.

**Current CyberShield status:** The project already has a rule in `apk_droppers_loaders.yar` for DexClassLoader detection (from CLAUDE.md). The gap identified in todo.md is ensuring all 8 new 2024–2026 techniques are covered, including variants of delayed droppers and multi-stage loaders.

**Recommended detection approach:**

1. Detect DexClassLoader initialization as a base signal (high base rate, needs combination).
2. Require co-location with conditional emulator/AV checks (raises discriminability).
3. Detect ELF unpacking patterns in `.so` libraries (some malware decrypt the secondary DEX from native code).
4. In L2 dynamic analysis, intercept DexClassLoader.loadClass() calls and extract the secondary DEX for runtime scanning.

**Source:** [A Survey and Evaluation of Android-Based Malware Evasion Techniques and Detection Frameworks](https://doi.org/10.3390/info14070374); [DroidNative: Semantic-Based Detection of Android Native Code Malware](https://arxiv.org/pdf/1602.04693); [Unpacking the packed unpacker: reversing an Android anti-analysis native library (VB2018)](https://www.virusbulletin.com/virusbulletin/2019/01/vb2018-paper-unpacking-packed-unpacker-reversing-android-anti-analysis-native-library/); [APKiD GitHub](https://github.com/rednaga/APKiD)

---

### 1.4 Native Code Hiding (`.so` Libraries / ELF)

**The Evasion:**  
Malware moves core logic into compiled C/C++ native libraries (`.so` files, ELF format) instead of DEX bytecode. This bypasses DEX-scanning tools (YARA, androguard, etc.) because:
- Static bytecode analysis cannot inspect native code.
- Most Android static-analysis tools focus on Java/Kotlin.
- 86% of popular Android apps contain native code, creating high base rate noise.

**What YARA *can* still catch:**

- **Known `.so` packer signatures:** Tools like APKiD detect specific packers used in native libraries (e.g., LibEncryption). YARA rules can match against packer init code, magic bytes, and obfuscation markers in the ELF binary.
- **ELF structural anomalies:** YARA can check for stripped symbols, non-standard section names, unusual entry points, or missing standard sections (indicators of packing or obfuscation).
- **Entropy analysis of `.so` sections:** Individual ELF sections (`.text`, `.data`, `.rodata`) with entropy > 7.0 indicate encrypted or packed code within the native binary.
- **Known malware library signatures:** If a specific malware family (e.g., Anatsa, Flubot) uses a distinctive native library initialization pattern or hardcoded strings in native code, YARA can match those patterns.
- **Dynamic loader invocations:** If the native code uses dlopen/dlsym to load additional libraries at runtime, or if the APK manifest or DEX shows JNI method signatures calling known-malicious C functions, these can be detected statically.

**What YARA *cannot* catch:**

- **Native code semantics:** What the native code actually does—decryption, exfiltration, crypto—is opaque to static analysis.
- **Obfuscated native code:** Custom compilation, control-flow flattening, or stripped binaries defeat signature matching.
- **Encrypted `.so` files:** If the `.so` is encrypted and decrypted at runtime by a loader stub, YARA cannot scan the decrypted form.

**Complementary tools:**

- **Ghidra / IDA Pro:** For human-assisted reverse engineering of critical `.so` files (out of scope for pure YARA, but mentioned in CLAUDE.md as absent; would improve coverage of the ~12% of samples with native libs).
- **Dynamic analysis:** Intercept dlopen/dlsym calls and inspect runtime-loaded libraries.
- **LIEF:** Library to parse and analyze ELF files; can be integrated into a preprocessing step before YARA scanning to flag suspicious structures.

**Recommended detection approach:**

1. Use APKiD-style YARA rules to detect common packers and obfuscators in ELF sections.
2. Scan for JNI method signatures that call suspicious function names (e.g., `exfilData`, `decryptPayload`).
3. Flag native libraries with entropy > 7.0 co-located with DEX bootstrap code that invokes JNI methods.
4. For critical samples, fall back to Ghidra disassembly (longer, higher-skill analysis, not automated).

**Source:** [DroidNative: Semantic-Based Detection of Android Native Code Malware](https://arxiv.org/pdf/1602.04693); [A Risk Estimation Study of Native Code Vulnerabilities in Android Applications](https://arxiv.org/pdf/2406.02011); [Unpacking the packed unpacker: reversing an Android anti-analysis native library (VB2018)](https://www.virusbulletin.com/virusbulletin/2019/01/vb2018-paper-unpacking-packed-unpacker-reversing-android-anti-analysis-native-library/); [APKiD GitHub](https://github.com/rednaga/APKiD)

---

## 2. Rule-Diversification Patterns Beyond String Matching

### 2.1 Entropy-Based Detection

**Purpose:** Detect obfuscated, packed, or encrypted code without knowing the exact payload.

**YARA Implementation:**

```yara
import "math"

rule high_entropy_indicator {
    meta:
        description = "Detects encrypted or packed code regions"
        severity = "Medium"
    condition:
        uint32be(0) == 0x504B0304 and           // APK magic
        math.entropy(0, filesize) > 7.0
}
```

**Scope limitations:**

- Entire APK entropy is a weak signal (many benign installers are packed).
- Per-section entropy (DEX, resources, individual `.so` files) is more discriminative.
- Entropy threshold (7.0) is heuristic; calibrate against your benign corpus.

**CyberShield applicability:**  
In L1 per-class DEX scanning, entropy checks should be applied to:
1. Class constant-pool strings (high entropy → likely encrypted).
2. Method bodies (high entropy bytecode → packed/obfuscated control flow).
3. `.so` sections within the APK.

The project should measure entropy distribution across benign BFSI apps vs. malware to set a threshold that discriminates without false positives on banking apps (which may themselves be obfuscated legitimately).

**Source:** [Using Entropy to Identify Obfuscated Malicious Code](https://www.veracode.com/blog/detecting-obfuscated-malicious-code/); [Capturing the symptoms of malicious code in electronic documents by file's entropy signal combined with Machine learning](https://arxiv.org/pdf/1903.10208)

---

### 2.2 Structural Conditions

**Purpose:** Exploit APK and DEX file format properties to constrain rules.

**Examples:**

| Condition | Detection Value |
|-----------|-----------------|
| `filesize < 1MB` | Narrows scope to smaller apps (reduces false-positive search space) |
| `uint32be(0) == 0x504B0304` | Confirms ZIP container (required for APK rules; fixes T1 endianness bug) |
| `uint32be(30) == 0x504B0304` | Detects nested ZIPs (dropper APKs) |
| `APK.manifest.uses_permission contains "SEND_SMS"` | Requires SMS permission declaration |
| `dex_header.version == 035` | Targets specific DEX version (Android 5.0+) |
| Archive has > N files | Obfuscated or multi-component apps |

**CyberShield usage:**

Per CLAUDE.md T20, APK member scanning uses a **separate member ruleset** with container gates stripped. The pattern is:
```yara
rule member_scope_example {
    // scope = "member" (scans decompressed ZIP members, NOT the container)
    // Container-gate conditions removed (e.g., no uint32be(0) == 0x504B0304)
    strings:
        $api = "sendTextMessage" nocase
    condition:
        $api
}
```

**Recommended additions:**

1. **Per-class structure:** When scanning DEX per-class, require:
   - Class is not a library class (common.is_library_class() or similar).
   - Class has methods (not just a stub).
   - Method bytecode length > threshold (skips empty/trivial methods).

2. **Manifest structure:** Check if the app is missing standard Android classes (stub malware) or has suspicious permission combinations.

3. **Resource anomalies:** Detect corrupted ZIP headers (anti-analysis technique seen in Anatsa) or non-standard resource structures.

**Source:** [What are YARA rules? Components, Examples, and Guidelines](https://corelight.com/resources/glossary/yara-rules); CLAUDE.md T20, T28

---

### 2.3 Module-Based Detection (Beyond Raw Bytes)

**Available YARA modules relevant to Android:**

| Module | Use Case |
|--------|----------|
| `math` | Entropy, frequency analysis |
| `androguard` | Custom DEX analysis (Koodous / APKiD) |
| `pe` / `elf` | Native library structure (ELF headers, sections, entropy per section) |
| `hash` | Imphash-equivalent for DEX? Not standard; would require custom work |
| `vt` (VirusTotal) | Behavioral data, scan results, URL reputation (hunt-only, not offline scanning) |

**Androguard Module (Koodous):**

Koodous maintains a custom YARA module that wraps androguard for DEX analysis:
```yara
import "androguard"

rule android_reflection {
    condition:
        androguard.method_calls("Ljava/lang/reflect/Method;", "invoke")
}
```

This is not part of standard YARA, but is available in [Koodous rules](https://docs.koodous.com/yara/index.html) and through the [Koodous/androguard-yara](https://github.com/Koodous/androguard-yara) fork.

**Realistic additions for CyberShield (no custom module required):**

1. **ELF module for `.so` scanning:** Standard YARA ELF support can check section names, entropy per section, symbol table presence.
2. **Custom entropy per-class logic:** Integrate with L1's jadx_src scanner to compute entropy per class and fold into YARA via preprocessor flags or separate scoring.
3. **Opcode frequency analysis:** Count bytecode instruction types (e.g., "how many invoke instructions?"). Not a built-in YARA feature; would require Python preprocessing.

**Not realistic without custom YARA module compilation:**

- Hash-based DEX "imphash"-equivalent (would require DEX bytecode parser in YARA).
- Call-graph properties (would require control-flow analysis built into YARA).
- API call co-occurrence graph (requires graph analysis, not pattern matching).

**CyberShield recommendation:** Stick with `math` module for entropy and standard ELF/PE modules. Layer call-graph and co-occurrence detection outside YARA (in L1 Python code, as already done for per-class co-location).

**Source:** [What are YARA rules? Components, Examples, and Guidelines](https://corelight.com/resources/glossary/yara-rules); [YARA documentation](https://yara.readthedocs.io/en/stable/writingrules.html); [Koodous YARA docs](https://docs.koodous.com/yara/index.html); [APKiD GitHub](https://github.com/rednaga/APKiD)

---

### 2.4 Why Traditional Hash-Based Approaches Don't Work for DEX

Unlike Windows PE imphash or other hash-based malware clustering:

- **DEX has no stable import table:** The class constant pool is a flat list, not a hierarchical import table. Trivial reordering of strings changes the hash.
- **Obfuscation trivially breaks hashes:** Renaming a single class breaks an imphash-equivalent.
- **High false-negative rate:** Two samples from the same malware family often have different class orderings, constant-pool layouts, or string encodings.

**Workaround:** CyberShield should use **fuzzy hashing (SSDEEP, tlsh)** on DEX constant pools or opcode sequences, not cryptographic hashes. This is already implied by the per-class co-occurrence mining mentioned in the codebase (B1 detection repair used measured per-class API co-occurrence to rewrite rules).

**Source:** Implicit in CLAUDE.md B1 (per-class co-occurrence detection); [Understanding Android Obfuscation Techniques: A Large-Scale Investigation in the Wild](https://arxiv.org/pdf/1801.01633)

---

## 3. How Other Android-Malware YARA Rulesets Are Structured

### 3.1 Koodous Community Rules

**Repository:** [github.com/Koodous/rules](https://github.com/Koodous/rules)

**Organization:**

- Rulesets are **community-contributed** and tagged by malware family, behavior, or packer.
- Rules use a **category taxonomy** (e.g., `banking`, `dropper`, `sms_abuse`) rather than naming individual malware families.
- Strong emphasis on **per-file scoping**: rules document whether they apply to full APK, DEX, resources, or manifest.
- Integration with **Koodous web interface:** Rules can be applied to live sample submissions, with confidence scoring.

**Key pattern:** Koodous emphasizes **"high-confidence weak signals combined"** rather than single-string rules. A banking-trojan rule requires:
- SMS/Call permissions + SEND_SMS permission
- Accessibility service declaration
- Event handler registration (WINDOW_STATE_CHANGED or NOTIFICATION_STATE_CHANGED)
- (Optionally) HTTP exfil patterns

**Scope calibration:** Rules distinguish between:
- **Whole-file rules** (rare; used for packer signatures, which are consistent across a packer family)
- **APK rules** (ZIP container + uncompressed members)
- **DEX rules** (bytecode-level, scanned per-class or whole-DEX depending on rule type)
- **Manifest rules** (AndroidManifest.xml parsing, permissions, components)

**Relevant observation for CyberShield:** The CyberShield project already implements per-file/per-class scoping (CLAUDE.md T2, T20), which aligns with Koodous best practices. The 18 dead rules in L1 likely violate this pattern (either too narrowly scoped or over-conjunctive).

**Source:** [Koodous rules repository](https://github.com/Koodous/rules); [Koodous YARA docs](https://docs.koodous.com/yara/index.html); [Koodous blog: Howto: Writing Yara Rules in Koodous](http://blog.koodous.com/2016/03/howto-writing-yara-rules-in-koodous.html)

---

### 3.2 InQuest YARA Rules

**Repository:** [github.com/InQuest/yara-rules](https://github.com/InQuest/yara-rules)

**Organization:**

- Rules are **organized by target platform and category** (e.g., `Android/trojan.yar`, `Android/dropper.yar`).
- Strong **VirusTotal integration:** Rules are designed for threat hunting on VirusTotal's LiveHunt service.
- Rules **prioritize precision over recall**: InQuest prefers high-confidence detections to reduce false positives on VirusTotal (where a high false-positive rate wastes analyst time).

**Key pattern:** InQuest rules often use **"3 of 5"** or **"2 of 3"** conditional logic to combine weak signals. Example structure:
```yara
rule flubot_banking_trojan {
    strings:
        $api1 = "sendTextMessage" nocase
        $api2 = "getDeviceId" nocase
        $c2_url = /https?:\/\/[a-z0-9]+\.(top|ru|cn)/ nocase
        $perm = "SEND_SMS" nocase
        $overlay = "com/example/overlay" nocase
    condition:
        (any of ($api*) and 2 of ($c2_url, $perm, $overlay))
}
```

This "N of M" approach balances sensitivity (catches variants) with specificity (requires enough co-evidence).

**Scope calibration:** InQuest rules are **not explicitly scoped** (unlike Koodous), which means they risk T2-style false positives when batching multiple files. However, because InQuest rules are used on VirusTotal (single-file submissions), this is mitigated in practice. For CyberShield's per-class scanning, **explicit scope guards are mandatory**.

**Relevant observation for CyberShield:** The project's dead rules (B29) may be trying to use InQuest's precision-over-recall philosophy in a per-class scanning context, where the search space is smaller. Rewriting them as "2 of 3" weak signals instead of conjunctions may improve hits.

**Source:** [InQuest YARA rules](https://github.com/InQuest/yara-rules); [InQuest blog (implicit via GitHub)](https://blog.inquest.net/); [awesome-yara](https://github.com/InQuest/awesome-yara)

---

### 3.3 APKiD Rule Structure (Packers, Protectors, Obfuscators)

**Repository:** [github.com/rednaga/APKiD](https://github.com/rednaga/APKiD)

**Organization:**

- Rules are **segmented by target** (DEX, APK, ELF).
- Within each, rules target **specific tools/packers** (AppGuard, PangXie, DexGuard, Proguard, etc.).
- Rules detect **tool signatures** (initialization code, library names, obfuscation markers) rather than malware behavior.
- Designed for **metadata tagging**, not security alerting (i.e., "this APK was packed with X", not "this is malware").

**Key pattern:** APKiD rules are **artifact-detection rules**, not behavioral rules. They use:
- **Exact byte patterns** for packer magic numbers and init routines.
- **Structural checks** (e.g., presence of specific DEX class names like `Ljava/lang/reflect/...` co-located with obfuscator-specific library init).
- **Version detection** (different versions of the same packer have different signatures).

**Scope calibration:** APKiD has separate rulesets for DEX (`obfuscators.yara`, `packers.yara`, `compilers.yara`, etc.) and APK (`common.yara`). This is **modular best practice**: rules that apply to DEX bytecode are kept separate from APK-level rules (T28 anti-pattern violation in the original CyberShield rules).

**Relevant observation for CyberShield:** APKiD's modular per-target structure (DEX vs. APK vs. ELF) is a model for the fix to T28. The project's behavior rules that were matching container scope should be restructured into **container-scoped rules** (for ZIP structure anomalies only) and **member-scoped rules** (for behavioral patterns in DEX). This is already implemented (CLAUDE.md T28 fix), but APKiD provides a reference for how to document the separation.

**Packer evasion relevance:** Detection of packing is important for banking malware because:
- **Anatsa** variants use DEX obfuscators and DES encryption (Anatsa Blog posts confirm ZScaler analysis).
- **Flubot** uses both DEX packers and native code packing.
- Detecting the packing tool is a **base-rate weak signal** (many benign apps are packed too), but combined with behavioral signals (SMS, accessibility, overlay), it increases confidence.

**Source:** [APKiD GitHub](https://github.com/rednaga/APKiD); APKiD rule files: [DEX obfuscators](https://github.com/rednaga/APKiD/blob/master/apkid/rules/dex/obfuscators.yara), [DEX packers](https://github.com/rednaga/APKiD/blob/master/apkid/rules/dex/packers.yara), [ELF packers](https://github.com/rednaga/APKiD/blob/master/apkid/rules/elf/packers.yara)

---

### 3.4 VirusTotal Community YARA Hunting Rules

**Platform:** [VirusTotal LiveHunt](https://www.virustotal.com/getstarted/advanced-hunting)

**Organization:**

- Rules are **community-published** for malware hunting on the VirusTotal file stream.
- Rule quality varies; VirusTotal curates a **confidence score** based on false-positive rate measured over historical submissions.
- Rules distinguish between **exact detection** (very few false positives, high specificity) and **hunting detection** (more generic, higher false-positive rate).

**Key pattern:** VirusTotal rules favor **behavioral patterns over malware-family-specific IOCs**, because the filestream is global and family-specific rules have short shelf lives. Example structure:
- Rules detect **anti-analysis techniques** (emulator checks, debugger detection, VM detection).
- Rules detect **exfiltration patterns** (DNS, HTTPS callbacks, encrypted payloads).
- Rules detect **Android-specific behaviors** (SMS interception, overlay registration, accessibility abuse).

**Confidence scoring on VirusTotal:**
- Calculated as: `(most_common_label_count) / (total_scanner_count)`.
- Threshold > 0.90 is considered "stable" (https://blog.virustotal.com/2023/09/its-all-about-structure-creating-yara.html).
- This is a **label consensus measure**, not a per-rule false-positive rate. CyberShield's approach (benign corpus baseline + weight learning) is more principled.

**Scope:** VirusTotal rules are **whole-file rules** (no per-class scanning). This is appropriate for hunting (single submissions), but CyberShield's per-class approach is better for precision in static analysis pipelines.

**Relevant observation for CyberShield:** VirusTotal's confidence scoring (label consensus) is orthogonal to CyberShield's weight-learning approach. The project should publish rules (once validated against benign BFSI) to VirusTotal's community. The weight scores computed by L5 on the local corpus will be different from VirusTotal's consensus, which is expected (different base rates).

**Source:** [VirusTotal Advanced Hunting](https://www.virustotal.com/getstarted/advanced-hunting); [VirusTotal blog: It's all about the structure!](https://blog.virustotal.com/2023/09/its-all-about-structure-creating-yara.html); [VirusTotal blog: From zero to Zanubis](https://blog.virustotal.com/2022/11/from-zero-to-zanubis.html)

---

### 3.5 Academic and Automatic Rule Generation

**Recent work (2023–2025):**

- **APIARY** ([2025](https://www.sciencedirect.com/science/article/pii/S0167404825000860)): Automatic rule generation from API call sequences using clustering and trie automata. Generates regex-based patterns for both Windows and Android.
- **GenRex**: Algorithm for generating YARA rules by extracting regex patterns from dynamic execution traces.
- **Malware Detection Using Automated Generation of Yara Rules on Dynamic Features** ([2023](https://dl.acm.org/doi/10.1007/978-3-031-17551-0_21)): Proposes generating YARA rules from dynamic analysis behavioral features (API calls, file I/O, network activity) instead of static strings.

**Relevance to CyberShield:**

The project's approach (static per-class analysis + dynamic L2 detonation) is well-positioned to use **automatic rule generation**:
1. Mine co-occurring API calls from confirmed banking trojans (L1 already does this via `apk_bfsi_primitives.yar`, per CLAUDE.md B1).
2. From L2 dynamic analysis, extract **runtime API sequences** (e.g., "Class.forName(TelephonyManager) → getMethod(sendTextMessage) → invoke within WINDOW_STATE_CHANGED handler").
3. Synthesize new YARA rules or rule conditions that capture these sequences at the static level.

This is already partially implemented (the 8 rules in `apk_bfsi_primitives.yar` were "authored from measured per-class API co-occurrence (50 malware vs 4 benign)", per CLAUDE.md B1). Scaling this to the full malware corpus and integrating L2 behavioral data would further improve rule quality.

**Source:** [APIARY: An API-based automatic rule generator for yara to enhance malware detection](https://www.sciencedirect.com/science/article/pii/S0167404825000860); [Malware Detection Using Automated Generation of Yara Rules on Dynamic Features](https://dl.acm.org/doi/10.1007/978-3-031-17551-0_21); [Automatic YARA Rule Generation](https://www.researchgate.net/publication/347980928_Automatic_YARA_Rule_Generation)

---

## 4. General Guidance for Rewriting Over-Conjunctive Rules

### 4.1 What "Over-Conjunctive" Means

An **over-conjunctive rule** requires so many co-located conditions within a single class (or file) that the rule never fires on real variants. Examples from CyberShield context (CLAUDE.md T25):

```yara
rule overly_strict_sms_stealer {
    strings:
        $sms_api = "sendTextMessage"
        $recv_sms = "registerReceiver"
        $contacts = "getContacts"
        $sim = "getSimSerialNumber"
        $persist = "registerBootReceiver"
        $overlay = "WindowManager.addView"
        $a11y = "AccessibilityService"
    condition:
        all of them  // ALL 7 signals must appear in the SAME class
}
```

**Problem:** A real SMS stealer may:
- Declare the accessibility service in the manifest, but register it in a different class.
- Call `getContacts()` in one class, `registerReceiver()` in another (per typical Android app structure).
- Load `sendTextMessage` via reflection, so the literal string never appears.

Result: **zero real-world hits**, even though the rule logic is sound in principle.

**CyberShield status:** 18 of 51 rules are dead (B29). T25 verified that these rules fire on their own declared strings (condition logic is fine); the **malware corpus simply lacks the vocabulary co-located in one class**. Rewriting requires understanding the real distribution of API calls across malware samples.

### 4.2 Recalibration Strategies

#### Strategy 1: Reduce to "N of M" (Most Common)

Replace all-of-the-above with "at least N of M" conditions:

```yara
rule sms_stealer_relaxed {
    strings:
        $sms_api = "sendTextMessage"
        $recv_sms = "registerReceiver"
        $contacts = "getContacts"
        $sim = "getSimSerialNumber"
        $persist = "registerBootReceiver"
        $overlay = "WindowManager.addView"
        $a11y = "AccessibilityService"
    condition:
        (3 of ($sms_api, $recv_sms, $contacts, $sim, $persist)) and
        ($overlay or $a11y)
}
```

**Calibration rule of thumb:**
- If a class has 7 candidate signals, start with N = 3 (relaxed).
- Test against malware corpus; measure false-positive rate on benign.
- If FPR > 5%, increase N to 4. If detection drops below 50%, decrease to 2.

**How CyberShield should calibrate:**
1. Run the original strict rule against the malware corpus → count hits.
2. Relax to N = M−1, then M−2, etc., and re-run until hits > 0.
3. For each N value, also run against the F-Droid benign corpus.
4. Choose N where (malware_hits / malware_total) > 30% and (benign_hits / benign_total) < 2%.

#### Strategy 2: Split into Multiple Weaker Rules + External Scoring

Instead of one strict rule, create 2–3 focused rules and let L5 combine them:

```yara
rule sms_stealer_api_calls {
    strings:
        $sms = "sendTextMessage"
        $recv = "registerReceiver"
    condition:
        all of them  // Narrow scope: just SMS APIs
}

rule sms_stealer_sensitive_data {
    strings:
        $contacts = "getContacts"
        $sim = "getSimSerialNumber"
    condition:
        any of them  // Detect sensitive data access
}

rule sms_stealer_persistence {
    strings:
        $boot = "registerBootReceiver"
    condition:
        $boot  // Weak signal on its own, but combined with above...
}
```

Then in L5, assign weights:
- `sms_stealer_api_calls`: +2.5 points
- `sms_stealer_sensitive_data`: +1.5 points
- `sms_stealer_persistence`: +1.0 point

A sample with all three scores +5.0; with two, +4.0; etc. This allows gradual confidence scaling.

**Advantage:** Rules are independently testable, and the L5 weighting system already supports this (CLAUDE.md mentions "auditable additive score").

**Disadvantage:** Requires careful weight calibration; T24 warns that at `n_benign = 4`, weights are sign-inverted. The requirement is `B ≥ 213` benign samples.

#### Strategy 3: Relax String Patterns (Regex, Modifiers)

For rules that search for exact method names, use broader patterns:

```yara
rule sms_stealer_behavior {
    strings:
        // Instead of exact method name...
        $sms_exact = "sendTextMessage"
        // ...allow variations via regex
        $sms_regex = /send(Text)?Message|submitSMS|postSMS/i
        
        // Use base64 modifier if strings might be encoded
        $contact_b64 = "getContacts" base64
        
        // Use xor for single-byte obfuscation
        $boot_xor = "registerBootReceiver" xor
    condition:
        ($sms_exact or $sms_regex) and
        ($contact_b64 or $boot_xor)
}
```

**Caveat:** Regex and xor modifiers multiply search cost and increase false positives. Use only after confirming the malware variant uses these obfuscation techniques.

### 4.3 Standard "N of M" Scoring Idioms

**The most robust YARA idiom for weak signals is:**

```yara
rule malware_behavior {
    meta:
        description = "Combines weak signals to detect malware family"
    strings:
        // Behavior group 1: C2 communication
        $c2_url = /https?:\/\/[a-z0-9-]+\.(top|cn|ru)/ nocase
        
        // Behavior group 2: Sensitive data access
        $contact_api = "getContacts"
        $call_log = "getCallLog"
        
        // Behavior group 3: Obfuscation / anti-analysis
        $reflection = "Class.forName"
        $emulator_check = "getProperty" // for "ro.kernel.qemu" checks
        
        // Behavior group 4: Exfiltration
        $http_post = "POST /upload"
        $encrypted_data = {00 01 02 03 04 05 06 07 08 09 0A}  // Example pattern
    condition:
        // At least 1 from group 1, 2 from group 2 or 3, 1 from group 4
        (1 of ($c2_url*)) and
        (2 of ($contact_api, $call_log, $reflection, $emulator_check)) and
        (1 of ($http_post, $encrypted_data))
}
```

**How practitioners calibrate N:**

1. **Measure baseline:** Run rule against 100+ confirmed malware samples of the target family. Count hits.
2. **Adjust N:** If hits < 50%, reduce N. If hits > 90%, increase N (more selective).
3. **Verify FP rate:** Run rule against 100+ benign apps. If FP rate > 5%, increase N.
4. **Final sweet spot:** Aim for ~70–80% detection on malware, < 2% FP on benign.

**For CyberShield specifically:**

The F-Droid benign corpus (245/600 in progress, eventually 600) and malware corpus (640) are sufficient for calibration:
1. For each dead rule, determine the minimum N value where hits > 30% on malware (640 samples).
2. For that N value, run against benign corpus and measure FP rate.
3. If FP > 5%, bump N up and re-test; if detection < 10%, bump N down.

This is deterministic and repeatable; `tools/rule_firing_report.py` already supports this workflow.

### 4.4 Per-Class Scoping: How to Avoid Over-Conjunction

**CyberShield's advantage:** Per-class scanning (CLAUDE.md T2, T21) naturally reduces over-conjunction because:
- Each class is smaller (fewer bytes to search).
- Class boundaries are semantic (methods in one class are more related).
- Whole-dex scanning is explicitly forbidden (T21).

**Recommendation:** When rewriting a dead rule, explicitly declare the class scope:

```yara
rule sms_stealer_handler {
    meta:
        scope = "per_class"  // Scan each DEX class separately
        category = "sms_interception"
        severity = "Critical"
    strings:
        // Expect these in the SAME handler class, not across the whole DEX
        $sms_intercept = "registerReceiver"
        $handler_method = "onReceive"
        $send_sms = "sendTextMessage"
    condition:
        // 2 of 3, not all 3, because handler classes may delegate
        2 of them
}
```

**Process for CyberShield:**

1. Take a dead rule (e.g., `android_sms_stealer` with 0 hits on 640 malware).
2. Manually inspect 5–10 confirmed banking trojans (SMS stealers) in the corpus.
3. Note: which classes contain which APIs? Are they co-located or split across multiple classes?
4. Rewrite the rule to match the **observed distribution** (e.g., "API calls are split; expect them across 2–3 classes").
5. Switch from whole-dex scanning to per-class scanning with relaxed conjunction (N of M).
6. Re-run; target > 30% hit rate.

---

## 5. Actionable Recommendations for CyberShield

### 5.1 Short Term (Address T25 Dead Rules)

1. **Triage the 18 dead rules (B29):**
   - Use `tools/rule_firing_report.py` (already exists, per CLAUDE.md A4).
   - For each rule, run it against confirmed samples from the target family (if available in the corpus).
   - Determine whether the rule fires on *any* variant or hits zero.

2. **For rules with zero hits:**
   - Manually inspect 5–10 samples of the target malware family.
   - Determine API call distribution (co-located or spread across classes).
   - Rewrite the rule condition from strict conjunction to "N of M".
   - Set N = (M / 2) as a starting point; tune based on FP rate on benign.

3. **For rules with hits on some variants:**
   - Understand why: is the rule too specific (e.g., exact method name) or over-conjunctive?
   - Add regex/base64/xor modifiers if obfuscation is detected.
   - Relax the condition.

### 5.2 Medium Term (Rule Diversification)

1. **Integrate entropy detection:**
   - Add per-class entropy checks to `apk_bfsi_primitives.yar`.
   - Measure entropy distribution on confirmed malware vs. benign BFSI apps.
   - Set threshold to detect encrypted strings without false-flagging legitimate banks.

2. **Expand packer detection:**
   - Integrate APKiD rules or write APKiD-compatible rules for DexClassLoader, ELF packing, etc.
   - Focus on malware families in the corpus (Anatsa, Flubot variants, GriftHorse if present).
   - Keep packer rules separate from behavior rules (per T28 fix).

3. **Mine L2 dynamic data for rules:**
   - Once L2 detonation is working (Phase 4 pending), extract API call sequences from successful detections.
   - Use APIARY-style automatic rule generation to create new YARA rules from these sequences.
   - Validate new rules against benign BFSI apps before merging.

### 5.3 Long Term (Rule Quality Metrics)

1. **Establish rule SLOs:**
   - Each rule should have a documented detection rate (e.g., "detects 60% of Anatsa variants") and FP rate (e.g., "< 1% on F-Droid").
   - Make this a gating criterion for rule commits (similar to L5's policy validation, CLAUDE.md L5).

2. **Continuous rule calibration:**
   - As the corpus grows (especially with CICMalDroid banking integration), re-calibrate rule weights via A4 (rule-firing report) and L5 scoring.
   - Use `tools/compare_measurements.py` (already exists, per CLAUDE.md §6.5) to track rule quality across measurement rounds.

3. **Publish validated rules to community:**
   - Once rules are validated against benign BFSI apps, publish to VirusTotal community and Koodous.
   - This feeds the global threat-hunting community and may surface new malware variants via VirusTotal LiveHunt.

---

## 6. References

### Core YARA Documentation
- [YARA Official Documentation](https://yara.readthedocs.io/en/stable/writingrules.html)
- [VirusTotal YARA-X](https://virustotal.github.io/yara-x/docs/writing_rules/rule-conditions/)
- [Neo23x0 YARA Style Guide](https://github.com/Neo23x0/YARA-Style-Guide)
- [Neo23x0 YARA Performance Guidelines](https://github.com/Neo23x0/YARA-Performance-Guidelines)
- [Stairwell YARA Rule Best Practices](https://docs.stairwell.com/docs/yara-rule-best-practices)

### Android Malware & YARA
- [Koodous YARA Rules Repository](https://github.com/Koodous/rules)
- [Koodous YARA Documentation](https://docs.koodous.com/yara/index.html)
- [InQuest YARA Rules](https://github.com/InQuest/yara-rules)
- [APKiD: Android Application Identifier](https://github.com/rednaga/APKiD)
- [A Survey and Evaluation of Android-Based Malware Evasion Techniques and Detection Frameworks (2023)](https://doi.org/10.3390/info14070374)
- [The Rise of Obfuscated Android Malware and Impacts on Detection Methods](https://pmc.ncbi.nlm.nih.gov/articles/PMC9044361/)
- [Understanding Android Obfuscation Techniques: A Large-Scale Investigation in the Wild (2018)](https://arxiv.org/pdf/1801.01633)

### Evasion Techniques
- [Reflection-Aware Static Analysis of Android Apps](http://docteau.github.io/pubs/li-ase16.pdf)
- [Using Entropy to Identify Obfuscated Malicious Code (Veracode)](https://www.veracode.com/blog/detecting-obfuscated-malicious-code/)
- [DeStroid – Fighting String Encryption in Android Malware](https://cyberjournal.cecyf.fr/index.php/cybin/en/article/view/31)
- [Use of Cryptography in Malware Obfuscation (2022)](https://arxiv.org/pdf/2212.04008)
- [DroidNative: Semantic-Based Detection of Android Native Code Malware](https://arxiv.org/pdf/1602.04693)
- [A Risk Estimation Study of Native Code Vulnerabilities in Android Applications (2024)](https://arxiv.org/pdf/2406.02011)
- [Unpacking the packed unpacker: reversing an Android anti-analysis native library (VB2018)](https://www.virusbulletin.com/virusbulletin/2019/01/vb2018-paper-unpacking-packed-unpacker-reversing-android-anti-analysis-native-library/)

### Banking Malware Families (Context)
- [Anatsa Banking Trojan Analysis (Zimperium)](https://zimperium.com/blog/mobile-threat-watch/anatsa-banking-trojan-continues-to-target-android-users)
- [Anatsa Campaign Technical Analysis (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/technical-analysis-anatsa-campaigns-android-banking-malware-active-google)
- [Anatsa Banking Trojan Updates (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/android-document-readers-and-deception-tracking-latest-updates-anatsa)

### Automatic Rule Generation & Academic Work
- [APIARY: An API-based automatic rule generator for YARA to enhance malware detection (2025)](https://www.sciencedirect.com/science/article/pii/S0167404825000860)
- [Malware Detection Using Automated Generation of YARA Rules on Dynamic Features (2023)](https://dl.acm.org/doi/10.1007/978-3-031-17551-0_21)
- [Automatic YARA Rule Generation](https://www.researchgate.net/publication/347980928_Automatic_YARA_Rule_Generation)
- [Trident: Improving Malware Detection with LLMs and Behavioral Features](https://arxiv.org/pdf/2605.00297)

### Threat Hunting & VirusTotal
- [VirusTotal Advanced Hunting](https://www.virustotal.com/getstarted/advanced-hunting)
- [VirusTotal Blog: It's all about the structure!](https://blog.virustotal.com/2023/09/its-all-about-structure-creating-yara.html)
- [VirusTotal Blog: From zero to Zanubis](https://blog.virustotal.com/2022/11/from-zero-to-zanubis.html)

### MITRE ATT&CK & Detection Mapping
- [MITRE ATT&CK: State of the Art and Way Forward (2023)](https://arxiv.org/pdf/2308.14016)
- [Enhance Your Mobile Cybersecurity Posture with MITRE ATT&CK® Matrix for Mobile (Lookout)](https://www.lookout.com/documents/whitepapers/us/enhance-your-mobile-cybersecurity-posture-us.pdf)
- [MITRE ATT&CK Mobile Techniques](https://attack.mitre.org/techniques/T1407/)
- [Rule-ATT&CK Mapper (RAM): Mapping SIEM Rules to TTPs Using LLMs](https://arxiv.org/pdf/2502.02337)

---

## Document Metadata

- **Prepared for:** CyberShield / APK Sentinel (PSB Hackathon 2026)
- **Research date:** 2026-08-16
- **Status:** Research-only; no code changes
- **Applies to:** L1 YARA rule improvement (B29, dead rules; T25 over-conjunctive rules), rule diversification beyond string matching
- **Next steps:** Triage dead rules using tools/rule_firing_report.py, rewrite with "N of M" conditions, validate against benign BFSI corpus
