# Corpus Expansion Sources — Android Banking Malware & Hard-Negative Benign Apps

**Research Date:** 2026-08-16  
**Purpose:** Identify sources for expanding the APK Sentinel test corpus with recent (2023–2026) Android banking malware samples and legitimate BFSI-adjacent benign apps to stress-test false-positive rates.

**Context:** Current corpus is ~699 malware samples (mostly 2020–2022 via GitHub `AndroidMalware_20XX` collections) + 600 F-Droid benign apps. F-Droid gap (T27): zero commercial BFSI apps, 5 accessibility apps, 79 SMS-permission apps out of 4,178 total — cannot validate accessibility-abuse or SMS-handling rule classes.

---

## Section 1: Malware Sample Sources

### 1.1 GitHub Collections (Known, Already in Use)

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| `sk3ptre/AndroidMalware_2020` | 233 samples from 2020 | General Android malware | Public GitHub repo, zip download | No metadata; zip-member extension-less; password `infected` | **4 samples** — fakeAarogyaSetu (4×), general overlap with Indian public health/UPI lures |
| `sk3ptre/AndroidMalware_2021` | 256 samples from 2021 | General + India-targeted | Public GitHub repo, zip download | Password `infected`, AES members (T13) | **8 samples** — novTargetedIndianBanks (SBI, 12 samples), mayJioTarget (Jio/COVID lures), sepTaxPayer (ICICI impersonation, SMS trifecta), high BFSI relevance |
| `sk3ptre/AndroidMalware_2022` | 210 samples from 2022 | General + India-targeted | Public GitHub repo, zip download | Password `infected`, AES members | **3 samples** — Sep_infoStealer (ICICI Rewards impersonation), SMS-stealing focus |

**Action:** Check for 2023/2024/2025 years in the same `sk3ptre` GitHub org; if absent, search for similar maintained Android malware collections.

---

### 1.2 MalwareBazaar (Hatching ThreatIntel)

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **MalwareBazaar Android Category** | ~25K Android malware samples (as of 2026) | Recent (daily updates), global malware | Free API (no registration required for download); bulk API has rate limits (50 req/min default, 500 with token) | Requires Hatching account for API token; no guarantee of India-specific filtering; samples may be singletons without corpus context | **Potentially high** — MalwareBazaar aggregates from AnyRun/Joe Sandbox detonations, includes banking trojans; India-targeted subset unknown without filtering |
| **Metadata:** Tags, detections, first-seen, C2, behavioral reports | — | — | Queryable via API (`/api/v1/query/`) | Detonation reports are 3rd-party; may have false positives | Can filter by tag/detection to identify banking trojans |

**Access Steps:**
1. Register free account at https://malwarebazaar.abuse.ch/
2. API endpoint: `https://mb-api.abuse.ch/api/v1/query/get_sample/`
3. Download via Tor or direct (IP geolocking may apply)

**Caveats:**
- Bulk sample download requires agreement to use for **research only, non-commercial**
- Rate limits can throttle large corpus pulls; consider staggered batch approach
- Samples verified via VirusTotal consensus; India-BFSI tag filtering unclear
- No guarantee of sample provenance traceability (useful for cross-referencing)

**Recommended:** Query API for samples tagged `Banking|Trojan|UPI` + first-seen 2023-2026 to identify India/BFSI-relevant subset.

---

### 1.3 Koodous (Public Mobile Malware Repository)

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **Koodous** (koodous.com) | ~300K Android APKs (malware + benign); community-tagged | Global; modern (live updates) | Free API (no registration); web search + download of individual samples | Community tags vary in quality; samples flagged by AVs rather than attributed to threat families; India-specific taxonomy weak | **Medium** — global banking trojan coverage exists; India-specific samples need manual identification via search |
| **Search API:** `/api/v2/apks/?search=` | Queryable by tag, AV detections, package name, developer | — | Free, no token required | Query results paginated (100/page); no bulk export | Can search for `trojan`, `banking`, `UPI`, `SBI` etc. |

**Access Steps:**
1. API: `https://api.koodous.com/v2/apks/?search=banking&av_count__gte=5`
2. Download: individual sample download or bulk via `apks.csv` export

**Caveats:**
- Community-driven tagging; inconsistent naming (e.g., `banking_trojan` vs `Banking Trojan`)
- No verified India-BFSI subset; manual search required
- Rate limits (free tier ~1000 req/day)
- Samples verified by Koodous community, not a single authoritative source

**Recommended:** Use search API to identify banking trojans with high AV consensus, then filter for India package-name impersonations manually.

---

### 1.4 VirusShare Android Repository

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **VirusShare** (virushare.com) | ~45K Android samples; unverified community submissions | Sparse; older samples | **Registration required** (free tier available); bulk download via Tor only | Samples are user-submitted with minimal curation; high noise/obsolete | **Low** — VirusShare Android is less maintained than desktop malware collections; India coverage unknown |

**Access:**
- Web: https://virushare.com/ (manual browsing slow)
- Bulk download: via Tor, requires API key
- **Note:** Bulk download request requires research-use justification

**Caveats:**
- Minimal metadata (hashes, filenames only)
- No detonation reports or behavioral data
- Highly dependent on community contributions (quality variance)
- Registration + Tor access overhead

**Recommendation:** Skip unless corpus needs breadth over depth; MalwareBazaar and Koodous are better-maintained alternatives.

---

### 1.5 Academic Datasets

#### 1.5.1 Drebin (University of Göttingen / TU Braunschweig)

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **Drebin Dataset** (drebin.cs.uni-goettingen.de) | 5,560 Android malware samples (2010–2012) | Historical; pre-Lollipop era | **Request via email** (research use license required); institutional affiliation expected | Samples are from 2010–2012; modern Android/API changes make static analysis less effective; no India-specific curation | **Very Low** — pre-2013 malware; India banking app ecosystem barely existed; obsolete compared to 2023–2026 trojans |

**Access:** Email authors (Arp, Spreitzenbarth, Hübner); requires research affiliation + use-case justification.

**Recommendation:** Skip for current corpus; too dated to represent modern banking trojans.

---

#### 1.5.2 AMD (Android Malware Dataset) / CICAndMal2017

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **Android Malware Dataset (AMD)** (Lincoln Lab, MIT) | 24,553 Android apps (2010–2014) | Historical; academia-curated | **Not publicly available** — requires direct request to MIT Lincoln Lab with research proposal | Highly curated; strong ground truth; but severely dated (pre-4.0 era) | **Very Low** — pre-2015; India banking malware did not yet exist at scale |
| **CICAndMal2017** | ~20K Android malware + benign (2017) | 2017-era malware | **Academic request** via Carleton University; requires institutional email + research statement | Moderate age; better than Drebin; still pre-UPI explosion | **Low-Medium** — 2017 is early for India-BFSI trojans; UPI launched 2016, but mass adoption 2018+ |

**Recommendation:** Lower priority than recent (2023+) sources; useful only as comparative baseline if timeline justifies.

---

#### 1.5.3 CICMalDroid (Canadian Institute for Cybersecurity)

| Source | Contents | Coverage | Access | Caveats | India/BFSI Relevance |
|---|---|---|---|---|---|
| **CICMalDroid** (already in project) | 2,505 APKs labeled `Banking` (main category); also `Trojan`, `Adware`, etc. | 2015–2018 era | **Already downloaded** at `$SENTINEL_DATA_ROOT/cicmaldroid/Banking/` | Extracted and audited; 3.8% filename mismatch (B39); well-labeled but aging (pre-2020 bulk) | **Medium** — labeled `Banking` but pre-2020; suitable for cross-validation with recent sources; integration pending decision (§7 item 3 of CLAUDE.md) |
| **Other CICMalDroid categories** | `Trojan` (1,000s), `Adware`, `Ransom`, `SMS`, `Riskware` | — | Same source, same download state | May be duplicates with `Banking` category; SMS/Ransom categories could provide domain-specific validation | **Check before folding in:** verify category boundaries and deduplication strategy |

**Action:** Before integrating, check for overlap with Banking category; if independent, consider analyzing `SMS` and `Riskware` subsets for accessibility/SMS-handling rule validation.

---

### 1.6 GitHub: Other Malware Collections (To Search)

| Source Pattern | Search Terms | Expected Coverage | Notes |
|---|---|---|---|
| Maintained malware repos (recent) | `android malware 2024`, `android malware 2025`, `banking trojan samples` | 2023+ samples | Check GitHub for repos maintained in last 6 months |
| Academic mirror repos | `android malware dataset mirror`, `malware corpus github` | Any curated collection | May include Drebin/AMD mirrors; document provenance |
| Threat-intel org repos | `emotet android`, `flubot`, `teabot`, `guloader` (known banking trojan family names) | Recent trojan families | Specific family repos often have samples + IOCs |
| India-specific repos | `android malware india`, `upi trojan samples`, `sbi fake app` | India-targeted specifically | Niche repos; may overlap with existing corpus |

**Recommended Search Strategy:**
```bash
# Quick GitHub search simulation:
# github.com/search?q=android+malware+trojan+2024+language:python (finds analysis tools)
# github.com/search?q=androidmalware+2024+stars:>10 (finds maintained collections)
```

---

### 1.7 Recent Threat Intel Reports (IOC Extraction)

| Source | What It Offers | Access | Notes |
|---|---|---|---|
| **Recorded Future / ThreatConnect / Talos Intelligence** | Threat reports w/ APK hashes, C2 domains, family attribution | Subscription / free blogs | Search blogs for `banking trojan` + `APK` + date 2023-2026 |
| **Kaspersky Securelist / McAfee Blogs** | Quarterly banking trojan threat reports | Free blogs | Search for India-specific campaigns, extract APK hashes, cross-reference MalwareBazaar |
| **Check Point Research** | Weekly threat reports | Free blogs | Often include APK samples; search for `UPI trojan`, `banking`, India |
| **Phishing & APK repositories (ThreatStream)** | APK hashes + metadata | Requires registration | Aggregate threat feeds; may have India-BFSI focus |

**Recommended:** Instead of bulk download, use threat reports to identify **specific families** (e.g., Flubot, Teabot, SentinelOne's recent India banking trojan), then search MalwareBazaar / Koodous for those families.

---

## Section 2: Hard-Negative Benign BFSI-Adjacent App Sources

The goal: legitimate apps that **look risky by permissions/behavior** (finance-adjacent, accessibility services, SMS handling, OTP) but are demonstrably benign. These stress-test false-positive rates.

### 2.1 F-Droid Unexplored Categories

F-Droid has 4,178 total packages; current benign corpus is 600 random samples (T27 identified gaps).

| Category | Total in F-Droid | Relevance | Access | Notes |
|---|---|---|---|---|
| **Finance** | ~30–50 apps (estimated) | Direct BFSI match | F-Droid API + category browse | Includes personal finance trackers, expense managers, budget apps; legitimate but finance-adjacent (permissionable false positives) |
| **Banking** | ~0 (confirmed in T27) | None | — | Commercial banks not in F-Droid (Google Play only) |
| **Accessibility** | **5 confirmed** (T27) | High risk of false positives | F-Droid category filter | Screen readers, input helpers, magnification tools; legitimate accessibility services (stress-test `accessibility_abuse` rule) |
| **Communication** | ~200–300 apps | SMS/OTP handling subset | F-Droid category filter | Includes SMS readers, OTP autofill, message managers; filter for SMS-permission subset |
| **System** | ~150–200 apps | Keyboard input, system hooks | F-Droid category filter | Some use accessibility services legitimately (e.g., custom keyboards) |
| **Tools** | ~500+ apps | SMS/OTP subset | F-Droid category filter | Many legitimate tools with SMS permission (notification readers, backup, etc.) |

**Action Steps:**
1. Use F-Droid API (`https://f-droid.org/api/v1/`) to enumerate packages by category
2. Filter by permission set: `android.permission.READ_SMS`, `android.permission.SEND_SMS`, `android.permission.RECEIVE_SMS`, `android.permission.BIND_ACCESSIBILITY_SERVICE`
3. Sample 50–100 apps from intersection of (Finance OR Accessibility OR Communication) + (SMS/accessibility permissions)
4. Validate they are truly open-source (check source repo links)

**Expected yield:** 50–150 hard-negative BFSI-adjacent apps (currently missing from benign corpus)

---

### 2.2 GitHub: Open-Source Finance/Fintech Apps

| Repository / Project | What It Is | Licensing | Access | Caveats | BFSI Stress-Test Value |
|---|---|---|---|---|---|
| **florisboard** (Florist) | Open-source Android keyboard; uses accessibility services legitimately | Apache 2.0 | https://github.com/florisboard/florisboard | Modern, well-maintained; accessibility hooks are necessary (not malicious) | **High** — accessibility service + user input interception (legitimate for keyboard); good false-positive stress-test |
| **Aegis Authenticator** | FOSS 2FA/OTP authenticator app | GPL-3.0 | https://github.com/beemdevelopment/Aegis | Well-maintained; handles OTP secrets; legitimate but permission-heavy | **High** — OTP handling + credential storage; stress-tests OTP-parsing rules |
| **Nextcloud Android** | Open-source cloud sync client | GPL-3.0 | https://github.com/nextcloud/android | Legitimate, widely used; may handle SMS/2FA in enterprise context | **Medium** — financial data handling (legitimate); general risky-permission baseline |
| **OpenBanking / Open Banking SDK samples** | Legitimate open-source fintech SDKs and demo apps | Apache/MIT/proprietary | GitHub search `open banking android sdk` | SDKs are reference implementations, may not be runnable as standalone APKs; verify they compile | **High (if APK-compilable)** — actual banking API interaction code; legitimate but rule-triggering |
| **Your Money App** (FOSS personal finance) | Personal finance tracker | GPL-3.0 | https://github.com/orhanobut/frame (similar projects) | Multiple FOSS money apps exist; search `personal finance github android` | **Medium** — finance app with SMS permission (expense categorization from bank SMS) |
| **Strongswan** | VPN/IPSec client (some apps use it for secure finance transactions) | GPL-2.0 | https://github.com/strongswan/strongswan | Network-level security; legitimate but permission-heavy | **Low-Medium** — not finance-specific, but legitimate crypto/network code |

**Search Queries:**
```
github.com search:
- "open source banking app android"
- "personal finance tracker android"
- "otp authenticator android" language:java/kotlin stars:>10
- "accessibility service android example" language:java (legitimate accessibility implementations)
- "upi sdk" or "payment sdk" (legitimate payment libraries)
```

---

### 2.3 GitHub: OTP/2FA Autofill Libraries & SMS-Parsing Tools

| Project | What It Is | Licensing | Caveats | BFSI Value |
|---|---|---|---|---|
| **Google Play Services GmsCore (microG)** | FOSS Play Services reimplementation; includes SMS-reading APIs | Apache 2.0 | Substantial codebase; SMS permissions needed for OTP reading | **Very High** — legitimate SMS reading for OTP autofill; direct false-positive stress-test |
| **OWASP Mobile Security Testing Guide (MSTG) sample apps** | Reference vulnerable + secure examples | Creative Commons | Sample apps, may not be production-ready | **Medium** — "secure example" apps are explicitly benign with risky permissions |
| **Autofill Framework reference implementations** | Android Autofill Service samples | Apache 2.0 | Official Android samples; minimal but correct | **High** — legitimate autofill apps using sensitive APIs |
| **SMS Retriever API (Google samples)** | Example apps using SMS Retriever (secure alternative to READ_SMS) | Apache 2.0 | Minimal reference; shows legitimate SMS interaction | **High** — legitimate SMS handling without READ_SMS permission (modern best practice) |
| **Twilio Android SDK samples** | Legitimate SMS/OTP integration samples | Apache 2.0 | Not standalone APKs; require compilation | **Medium** — legitimate 2FA/OTP integration in real-world context |

**Search Queries:**
```
github.com:
- "otp autofill android" language:java/kotlin
- "sms retriever" language:java
- "android autofill" language:java
- "2fa android app" OR "two factor" language:java
```

---

### 2.4 F-Droid Individual Curated Picks (Accessibility + SMS)

Recommended apps to manually add to hard-negative panel (pre-audited for legitimacy):

| App | Package Name | Category | Why It's Hard-Negative | License |
|---|---|---|---|---|
| **TalkBack** (AOSP fork available) | com.google.android.marvin.talkback | Accessibility | Screen reader; legitimate accessibility service; heavy permissions | Apache 2.0 (AOSP) |
| **Pluma** (custom keyboard) | com.darshan.pluma (or similar) | Accessibility/Input | Custom keyboard with accessibility service (legitimate) | GPL-3.0 |
| **OpenBoard** (keyboard) | org.dslul.openboard.inputmethod.latin | Accessibility/Input | FOSS keyboard; accessibility hooks for accessibility | GPL-3.0 |
| **NetGuard** | eu.faircode.netguard | Network/Tools | Firewall app; legitimate system-level monitoring (looks like network C2 interception) | GPL-3.0 |
| **Infinity for Reddit** (or similar) | ml.docilealligator.infinityforreddit | Communication/Tools | Social media app; may have SMS permission for authentication | GPL-3.0 |
| **Amaze File Manager** | com.amaze.filemanager | Tools | File manager; may request SMS permission for backup/recovery; legitimate | GPL-3.0 |

**Note:** These are starting points; actual F-Droid category scanning will yield more comprehensive list.

---

### 2.5 GitHub Topic Searches (Bootstrap)

| Topic Search | Expected Yield | BFSI Relevance |
|---|---|---|
| `github.com/topics/otp-authenticator` | ~50 repos | High |
| `github.com/topics/2fa` | ~100+ repos | High |
| `github.com/topics/accessibility` + language:Java | ~500+ repos | Medium (non-BFSI accessibility frameworks) |
| `github.com/topics/sms` + language:Java | ~100+ repos | Medium-High (many legitimate SMS handling apps) |
| `github.com/topics/banking` + language:Java | ~50 repos | High (likely fintech SDKs / reference implementations) |
| `github.com/topics/payment` + language:Java | ~200+ repos | Medium (legitimate payment libraries) |

---

### 2.6 Ethical & Licensing Caveats

| Category | Caveat | Mitigation |
|---|---|---|
| **Research-Only Use** | Most academic malware datasets (Drebin, AMD, CICAndMal) require "research use only" license agreement | Document agreements in project; never redistribute samples |
| **Registration & ToS** | MalwareBazaar, Koodous require free account + ToS agreement (non-commercial, research use) | Maintain account credentials securely; log access for audit |
| **Open-Source Licensing** | F-Droid + GitHub apps must be GPL/Apache/MIT/etc; confirm before download | Check LICENSE file in each repo; document license per sample |
| **Malware Handling** | Live malware samples (GitHub AndroidMalware_20XX, MalwareBazaar) must be stored encrypted at rest, executed only in isolated emulator | Follow CLAUDE.md §4 safety rules (zips password-protected, no extractall, emulator-only execution) |
| **India-Specific Content** | Some Indian banking trojans may target real victims; verify samples are from public threat intelligence (not private breach databases) | Only use samples from public GitHub repos, MalwareBazaar, or published threat reports |
| **Institutional Affiliation** | Some sources (Drebin, AMD, CICAndMal) require researcher affiliation with accredited institution | Not applicable to hackathon context; prioritize sources requiring only free registration |

---

## Section 3: Recommended Next Steps (Ranked by Effort-to-Value)

### Immediate (High Value, Low Effort)

1. **F-Droid Category Scan** (~2–4 hours)
   - Use F-Droid API to enumerate `Finance`, `Accessibility`, `Communication` categories
   - Filter by permissions (SMS, accessibility binding)
   - Download 50–100 samples; add to hard-negative benign panel
   - **Value:** Closes T27 gap directly; zero India/BFSI app false positives from this set

2. **GitHub Topic Trawl for OTP/Accessibility** (~3–5 hours)
   - Search topics: `otp-authenticator`, `2fa`, `accessibility`
   - Identify 20–30 well-maintained, compilable repos
   - Download APKs or compile from source
   - **Value:** OTP/2FA handling validation; accessibility service legitimate-behavior baseline

3. **MalwareBazaar API Query for Recent Banking Trojans** (~2–3 hours)
   - Register free account; query API for samples tagged `Banking` OR `Trojan` + first-seen 2023-2026
   - Filter for India-BFSI keywords in metadata (UPI, SBI, ICICI, Paytm, PhonePe)
   - Extract 50–200 samples; add to malware corpus
   - **Value:** Recent 2023–2026 banking trojans; likely India-BFSI coverage; direct refresh of corpus vintage

### Medium Effort (Medium Value)

4. **GitHub Maintained Malware Collections Search** (~2–3 hours)
   - Search for `sk3ptre` org for 2023/2024/2025 years (if not already done)
   - Search GitHub for other maintained Android malware collections (stars >5 in last 6 months)
   - Document findings; attempt to contact maintainers for 2025 data
   - **Value:** If found, 100–500 recent samples; likely overlaps MalwareBazaar but may have different metadata

5. **CICMalDroid Integration Decision & Analysis** (~4–6 hours)
   - Audit existing 2,505 Banking samples (already downloaded)
   - Check overlap with existing 699-sample corpus (via hash)
   - Decide: separate analysis (§7 option 1) or fold in (option 2)
   - If separate, analyze SMS/Riskware categories for accessibility/SMS-rule validation
   - **Value:** 2,505 labeled banking trojans; well-curated; but decision delays downstream

6. **Koodous Search for India-Specific Banking Trojans** (~3–5 hours)
   - Use Koodous API to search for banking trojans
   - Manually filter for package-name impersonations (SBI, ICICI, PhonePe, Google Pay, etc.)
   - Download India-BFSI subset (estimated 50–200 samples)
   - **Value:** Complements MalwareBazaar; different aggregation may catch unique samples

### Lower Priority (Higher Effort, Medium Value)

7. **Threat Intel Report Mining** (~4–6 hours)
   - Search Kaspersky Securelist, McAfee, Check Point blogs for India banking trojan reports (2024–2026)
   - Extract APK hashes; cross-reference with MalwareBazaar/Koodous
   - Compile list of specific families to prioritize (e.g., Flubot variants targeting India)
   - **Value:** Identifies recent campaigns; enables targeted corpus expansion by threat family

8. **Open-Source Fintech SDK Compilation** (~6–10 hours)
   - Identify GitHub fintech SDKs (Open Banking, UPI SDKs, payment integrations)
   - Attempt to compile reference/demo apps to APK
   - Validate they are FOSS and redistributable
   - **Value:** Hard-negatives with legitimate financial code; validates fintech-specific rules

### Deferred (Low Priority, High Effort)

9. **CICAndMal2017 / AMD Datasets** (~1–2 weeks for request + delivery)
   - Contact Carleton / MIT for academic dataset request
   - Requires research affiliation + formal proposal
   - **Value:** Moderate (comparative baseline) but outdated (2017 era); not urgent for 2023+ India banking focus
   - **Recommendation:** Defer unless longitudinal study is planned

10. **Drebin Dataset** (~2+ weeks for request + delivery)
    - Contact authors; requires research affiliation
    - **Value:** Very low (2010–2012 era); skip unless historical comparison needed
    - **Recommendation:** Skip

---

## Section 4: Implementation Checklist

### Pre-Integration Validation (For Each Source)

- [ ] **Source authenticity:** Verify GitHub repos are maintained (last commit <6 months) or repos are official (MalwareBazaar, Koodous, F-Droid)
- [ ] **Licensing:** Confirm FOSS apps have LICENSE files; confirm research datasets have use-only agreements documented
- [ ] **Safety:** Live malware samples encrypted at rest (password-protected zips or MalwareBazaar TLS); benign apps scanned for false-positive tampering
- [ ] **Deduplication:** Check new samples against existing corpus (via SHA-256 hash); avoid double-counting
- [ ] **Metadata:** Preserve source attribution, first-seen date, threat family (if applicable) in corpus labels
- [ ] **Compliance:** Log download source, access date, any registration/ToS agreements accepted

### Corpus Integration Steps (In Order)

1. **Expand malware corpus:**
   - [ ] Query MalwareBazaar API for 2023–2026 banking trojans (~50–200 samples)
   - [ ] Run `corpus_run.py` on new malware samples to produce L0/L1 evidence
   - [ ] Generate `rule_firing_report.py` to measure impact on malware-category detection rate

2. **Build hard-negative benign panel:**
   - [ ] F-Droid category enumeration + download (50–100 samples)
   - [ ] GitHub OTP/accessibility app download (20–30 samples)
   - [ ] Run benign samples through `corpus_run.py` as labeled `benign_fdroid_finance`, `benign_fdroid_accessibility`, etc.

3. **Recompute L5 weights & evaluation:**
   - [ ] Run `fit_calibration.py` with expanded benign set (B > 213 threshold from T24)
   - [ ] Run `L5/l5.py --all` to score all spines with new weights
   - [ ] Run `evaluate.py --ablation` to measure impact on false-positive rate

4. **Validate accessibility/SMS rules:**
   - [ ] Check `rule_firing_report.py` for accessibility_abuse and sms_intercept firing rates on hard-negative panel
   - [ ] Compare benign vs malware rate; refine rules if high false-positive rate persists

---

## Section 5: Metadata Template (For Corpus Labels)

When adding samples from these sources, capture:

```json
{
  "source": "MalwareBazaar|Koodous|GitHub|F-Droid|CICMalDroid",
  "source_id": "mb-12345|koodous-sha256-abcd|github-repo-org|fdroid-com.package",
  "category": "malware|benign",
  "subcategory": "banking_trojan|accessibility_app|otp_authenticator",
  "label": "malware_banking_recent|benign_fdroid_finance|benign_github_accessibility",
  "first_seen": "2025-11-15",
  "threat_family": "Flubot|TeaBot|SentinelOne.Banking.Trojan|None",
  "india_targeted": true|false,
  "india_impersonation": "ICICI|SBI|PhonePe|None",
  "notes": "URL: ..., Threat Report: ..., Compiler: ..."
}
```

---

## Summary

**Malware corpus expansion pathway:**
- **Immediate:** MalwareBazaar (API, 50–200 samples, 2023–2026)
- **Quick:** GitHub AndroidMalware_20XX latest years (if they exist)
- **Medium:** Koodous search + CICMalDroid integration decision
- **Deferred:** Threat intelligence mining (low-priority optimization)

**Hard-negative benign panel pathway:**
- **Immediate:** F-Droid Finance/Accessibility/SMS categories (50–100 samples)
- **Quick:** GitHub OTP/2FA/accessibility topic crawl (20–30 samples)
- **Medium:** Open-source fintech SDK compilation (6–10 hours, 5–10 samples)

**Expected corpus growth:**
- Malware: 699 → 900–1,200 (focus on 2023–2026 banking trojans, India-targeted subset >50)
- Benign hard-negative panel: 0 → 100–200 (BFSI-adjacent, current gaps: accessibility, SMS, finance)

**Timeline:** Immediate + quick steps achievable in **1–2 weeks**; medium-effort steps in **2–4 weeks**; critical for closing T27 and enabling L5 weight recomputation.

