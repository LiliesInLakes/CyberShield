# APK Sentinel — Pipeline Study

*A teaching reference for the APK Sentinel / CyberShield banking-malware analysis
pipeline (PSB Cybersecurity, Fraud & AI Hackathon 2026). Written for a new team
member or judge: it covers the problem domain, the threat landscape, the Indian
regulatory context, competitors, and then a layer-by-layer technical walkthrough
(L0→L6) including every fix made in the 2026-08-25 work session.*

*The project's ethos is **measure before claiming** — this document is honest
about what works, what is an upper bound, and what is still blocked.*

---

## Table of contents

**Part A — Domain & Product Context**
1. [What is an APK?](#1-what-is-an-apk)
2. [The Android malware landscape](#2-the-android-malware-landscape)
3. [Indian government guidelines & context](#3-indian-government-guidelines--context)
4. [Competitors & positioning](#4-competitors--positioning)

**Part B — Technical Deep-Dive**
5. [Architecture overview](#5-architecture-overview)
6. [L0 & L1 — triage, impersonation, static analysis](#6-l0--l1--triage-impersonation-and-static-analysis)
7. [L2 — dynamic analysis](#7-l2--dynamic-analysis)
8. [L3 — ML classifier](#8-l3--ml-classifier)
9. [L4 — GenAI reasoning](#9-l4--genai-reasoning)
10. [L5 — hybrid scoring](#10-l5--hybrid-scoring)
11. [GenAI use & app-navigation integration](#11-genai-use--app-navigation-integration)
12. [Fixes, known gaps, and roadmap](#12-fixes-this-session-known-gaps-and-roadmap)

> **Note on the L3 dataset numbers (§8).** The current unified model uses a
> **3,319 × 7,834** matrix — the 7,834 includes the 13 `cap:*` capability
> columns added late in the session. The frozen analysis report
> (`docs/reports/unified_dataset_analysis.json`) reads **3,317 × 7,821** because
> it was generated on the pre-capability build (7,821 columns) after the
> density-floor filter dropped 2 rows. Both describe the same dataset; §8 uses
> whichever is appropriate to the point being made.

---

# Part A — Domain & Product Context

This part gives the background a new team member or a hackathon judge needs
before the technical deep-dive in Part B: what an APK actually is, how
Android banking malware works and who the well-known families are, what the
Indian regulatory and law-enforcement landscape around this fraud looks
like, and how existing tools compare to what APK Sentinel is trying to do.
Nothing here is project-internal — it is external, researched, and cited at
the end. Product-positioning claims in §4 are drawn only from the project's
own fact sheet, not invented.

---

## 1. What is an APK?

An APK (**Android Package Kit**) is the file format Android uses to
distribute and install an application. Structurally it is nothing exotic: a
standard ZIP archive with a conventional internal layout and, on top of the
ZIP, one or more cryptographic signatures that Android's package manager
verifies before it will install anything.

### 1.1 Internal structure

| Component | What it is | Why it matters for analysis |
|---|---|---|
| `AndroidManifest.xml` | A binary-XML file declaring the app's package name, permissions, components (activities, services, receivers, providers), and the SDK/target API levels. | The single richest static-triage artifact: permissions and declared components tell you what an app *could* do before you've decompiled a single class. |
| `classes.dex` (and `classes2.dex`, `classes3.dex`, …) | Java/Kotlin source compiled to Dalvik bytecode. A single DEX file has a 64K-method-reference ceiling, so apps with more code ship multiple DEX files ("multidex"). | This is where the app's actual logic lives — and where a decompiler (jadx) and bytecode scanner (YARA over dex operands, this project's approach) do their work. |
| `resources.arsc` | A compiled binary table mapping resource IDs (strings, layouts, styles, colors, drawables) to their values across locales/densities/configurations. | Holds app-visible strings (including phishing-page text, spoofed bank names) without requiring the DEX to be touched. |
| `res/` | Compiled XML resources (layouts, drawables, values) referenced from `resources.arsc`. | Overlay/phishing UI layouts and icon assets — including the icon used for the impersonation pHash check — live here. |
| `assets/` | Arbitrary raw files bundled verbatim (not compiled), commonly used for config files, ML models, web content, or — in malware — encrypted payloads and second-stage droppers. | A common hiding spot for payloads that never touch the manifest or DEX until unpacked at runtime. |
| `lib/<abi>/*.so` | Native (C/C++) shared libraries, one directory per target ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`, …). | Native code is opaque to DEX-level tooling and needs a disassembler (Ghidra); present in only a minority of samples but a common home for packers/obfuscators. |
| `META-INF/` | v1 (JAR) signing metadata: `MANIFEST.MF`, `*.SF`, and the `*.RSA`/`*.DSA`/`*.EC` certificate. | The oldest signing scheme, still present for backward compatibility; per-entry signing makes v1 the weakest of the three schemes. |

### 1.2 Signing: v1, v2, v3 (and v4)

Every installable APK must be signed; Android refuses to install an
unsigned or a tampered-and-improperly-resigned package. There are several
signature scheme generations, and a real-world APK is often signed with
more than one simultaneously for backward compatibility:

- **v1 (JAR signing, since 2008/Android 1.0).** Signs each ZIP entry
  individually via `META-INF/MANIFEST.MF` and a `.SF`/`.RSA` signature
  block. Because it signs entries, not the archive layout, v1-only APKs are
  historically vulnerable to "Janus"-style and other ZIP-structure
  manipulation attacks that add or reorder unsigned bytes without
  invalidating the signature.
- **v2 (APK Signature Scheme, Android 7.0 Nougat).** Signs the archive as a
  whole — manifest, entries, and central directory — via a dedicated "APK
  Signing Block" inserted between the ZIP content and the central
  directory, outside `META-INF/`. Full-file signing closes the v1
  entry-level gaps and is significantly faster to verify.
- **v3 (Android 9 Pie).** Adds **key rotation**: an app can prove a
  historical lineage from an old signing key to a new one, letting
  developers rotate compromised or outdated keys without breaking upgrade
  continuity for already-installed devices.
- **v4 (Android 11).** A separate, incremental scheme built for the
  ADB/Play "incremental installs" fast-install feature; not relevant to
  most static-analysis pipelines.

For malware analysis, the signing block is a triage signal in its own
right: self-signing is universal on Android (essentially every APK,
benign or not, is self-signed — see the project's own T6 trap), so the
presence of a signature says little. What *does* discriminate is
**anomalies** — certificate validity windows, issuer fields that don't
match the claimed developer, signer identity that doesn't match the
brand being impersonated, or a scheme downgrade to v1-only on an app that
claims to be a modern banking client.

### 1.3 Distribution: Play Store vs. sideloading

Android apps reach a device by one of two broad paths:

1. **Official/managed stores** — primarily Google Play, plus OEM stores
   (Samsung Galaxy Store, Xiaomi GetApps) and enterprise MDM channels.
   These enforce Google Play Protect scanning, developer registration,
   policy review, and (for Play specifically) app-signing key custody by
   Google itself for apps that opt into Play App Signing.
2. **Sideloading** — installing an APK obtained from anywhere else: a
   direct download link, a WhatsApp/SMS/Telegram-forwarded file, a
   third-party app store, or a QR code. Android requires the user to
   explicitly enable "install unknown apps" for the installing source, a
   permission most users grant without hesitation when a message claims
   urgency ("update your KYC now" / "your bank app is outdated").

### 1.4 Why sideloaded APKs are India's fraud vector

India's fraud landscape is unusually concentrated on sideloaded APKs for a
specific, well-documented combination of reasons:

- **Scale of digital-payments adoption.** UPI has made near-universal,
  low-friction digital payment the default, which means a compromised
  phone is a direct line to a bank account or wallet balance — not merely
  a data-harvesting target.
- **Social-engineering vector matches habits already in use.** Fraudsters
  distribute APKs over WhatsApp, SMS links, and fake customer-care calls
  that direct victims to "install this app to complete KYC / receive your
  refund / update your banking app" — channels Indian users already treat
  as legitimate for OTPs, UPI collect requests, and bank communication.
- **No install-time gatekeeper for sideloaded files.** Once "install
  unknown apps" is granted, there is no Play Protect-equivalent review;
  the app runs with whatever permissions it requests at install/runtime.
- **High-value, well-known brand impersonation.** Because the same handful
  of major banks, UPI apps, and government services (Income Tax, Aarogya
  Setu) are used by hundreds of millions of people, a single fake-app
  template scales across an enormous victim pool — this is precisely the
  pattern behind Drinik and the SBI/ICICI/Aarogya-Setu impersonators
  described in §2.

This is why a detector purpose-built for *this* threat model needs to treat
"does this app's name, icon, and package identity impersonate a known
Indian financial or government brand" as a first-class, cheap, pre-decompilation
signal — not an afterthought bolted onto a generic mobile-security scanner.
That is the role of this project's L0 layer (see Part B, §6).

---

## 2. The Android malware landscape

### 2.1 Malware, trojan, dropper, RAT — the vocabulary

These terms describe overlapping but distinct properties, and Android
banking malware typically wears several hats at once:

- **Malware** is the umbrella term: any software designed to cause harm,
  gain unauthorized access, or operate against the user's interest.
- **Trojan** describes the delivery mechanism, not the payload: software
  that misrepresents itself as something benign (a bank app, an antivirus
  update, a QR scanner) to get installed. Almost every family below is a
  trojan by this definition.
- **Dropper** is a trojan whose primary job is to install a *second*,
  usually more heavily obfuscated, payload after the initial install —
  splitting the "get past the user/store" problem from the "do the
  actual banking fraud" problem, and letting the operator swap payloads
  without republishing the loader.
- **RAT (Remote Access/Administration Trojan)** grants an operator live,
  interactive control of the device — screen viewing/streaming, remote
  input injection, file access — as opposed to malware that only executes
  a fixed, pre-programmed routine.

Modern Android banking trojans (Cerberus, Hook, and others below) blur all
three: they are trojans by delivery, often ship as droppers to stay small
and pass initial review, and increasingly bundle RAT-style live screen
control (hidden VNC, `MediaProjection` abuse) alongside their automated
theft routines.

### 2.2 Banking-trojan mechanics

The core toolkit a modern Android banking trojan draws from:

- **Overlay / phishing attacks.** The malware detects when a targeted
  banking or UPI app comes to the foreground and immediately draws a
  full-screen fake login/PIN-entry window on top of it, indistinguishable
  from the real app, to capture credentials directly. This is the oldest
  and still most common technique.
- **SMS/OTP theft.** By requesting SMS-read/receive permissions (or, once
  installed, abusing Accessibility Service to read the notification
  shade), the malware intercepts one-time passwords in real time and
  forwards them to a command-and-control (C2) server or directly
  auto-fills them into a fraudulent transaction — defeating SMS-based
  two-factor authentication without the user ever seeing the OTP.
- **Accessibility-service abuse.** Android's Accessibility Service exists
  to let assistive technology read screen content and simulate input for
  users with disabilities. Banking trojans request it under a pretext and
  then use the same APIs to read arbitrary on-screen text (including
  banking-app balances and OTP notifications), auto-grant themselves
  further dangerous permissions by clicking through system dialogs, and
  simulate taps/swipes to perform an entire fraudulent transaction
  automatically ("Automatic Transfer System" / ATS-style automation).
- **Screen capture / live streaming.** Newer families combine
  `MediaProjection` screen recording or hidden-VNC-style remote control
  with the overlay/accessibility toolkit, letting an operator watch the
  live screen and drive input interactively — collapsing the trojan into
  a full RAT.
- **Device-admin abuse.** Requesting Device Administrator privileges makes
  the app materially harder to uninstall (it can block or delay
  uninstallation attempts) and can be used to lock the screen or wipe the
  device as leverage/anti-forensics.

### 2.3 Famous Android banking-malware families

| Family | Known for |
|---|---|
| **Cerberus** | Malware-as-a-Service (MaaS) banking trojan/RAT first seen ~2019: credential theft via overlays, SMS/2FA interception, keylogging, full remote control. Its source code (builder, C2 panel, admin logic) leaked after a dispute between operators, seeding an entire lineage of successor families. |
| **Anubis** | Long-running MaaS banking trojan family contemporaneous with Cerberus, offering overlay phishing, SMS interception, screen recording and ransomware-style file-locking add-ons; frequently distributed via fake utility/Play-lookalike apps. |
| **Alien** | A direct fork of Cerberus's leaked code, adding remote shell execution and stronger obfuscation; distributed heavily via phishing/smishing across SMS, messaging apps, and social platforms. Alien's emergence effectively marked "Cerberus is out, Alien-lineage malware is in." |
| **Hydra** | Cerberus/Anubis-lineage European-focused banking trojan using overlay attacks and Accessibility-service abuse to automate credential theft and device takeover; historically distributed through fake apps and dropper campaigns. |
| **SOVA** | Evolved rapidly (2021 onward) into a broad-spectrum trojan targeting 200+ banking, wallet and crypto-exchange apps, adding keylogging, screen recording, cookie theft and — in later versions — ransomware-style file encryption as a bolt-on. |
| **Sharkbot** | First seen late 2021; specializes in **Automatic Transfer System (ATS)** attacks — instead of just stealing credentials, it initiates a money transfer itself and silently substitutes the destination IBAN/account, bypassing multi-factor confirmation that only re-shows the (unaltered-looking) recipient name. Has been distributed even through Google Play under fake antivirus/cleaner disguises. |
| **TeaBot (Anatsa)** | Targets an unusually large number of financial-institution apps; after install it fingerprints which targeted banking apps are present on the device and downloads a payload tailored to each one, combined with real-time screen-sharing/remote-access capability. |
| **FluBot** | SMS/smishing-distributed worm-like banking trojan (2020 onward) that harvests the victim's own contact list to self-propagate via further malicious SMS links, alongside standard credential and personal-data theft. |
| **BankBot** | One of the earliest widely-tracked "family name" Android banking trojans (predating the Cerberus lineage), using overlay attacks against a list of targeted bank apps; its code and technique lineage influenced many later families. |
| **Ginp** | Began as a simple SMS-stealer and evolved into a full banking trojan specializing in credit-card-detail theft via SMS interception, combined with overlay attacks against banking-app logins. |
| **Octo** | A Cerberus-lineage descendant offering full remote-control screen-streaming ("Octo" recording/streaming its own screen-share to the operator) layered on the standard overlay/Accessibility toolkit — one of the more RAT-like members of this family tree. |

### 2.4 India-specific: Drinik and BFSI/gov impersonators

**Drinik** is the clearest, most extensively documented India-specific
case study. First observed as a basic SMS-stealer around 2016, it
resurfaced from 2021 onward as a full banking trojan impersonating the
**Income Tax Department of India**, typically distributed as an APK named
something like "iAssist" and pushed via SMS links claiming a tax refund or
KYC update. Once installed it:

- disables/intercepts incoming calls without the user noticing;
- encrypts its internal strings to evade signature-based antivirus;
- walks the victim through entering income-tax portal credentials, net
  banking login, PAN, Aadhaar, and card details on a convincing fake form;
- and in its most advanced revisions abuses Accessibility Service to add
  screen recording, keylogging, and overlay attacks — expanding its target
  list to **18 Indian banks** including SBI.

Beyond Drinik, the broader pattern documented repeatedly in India (and
directly reflected in this project's own malware corpus — see the
`CLAUDE.md` §4 sample table) is **namespace and brand squatting** against
the country's most recognized BFSI and government-service brands:

- **SBI impersonators** — fake "SBI Quick Support" / "SBI complaint
  register" apps under package identifiers like `com.sbi.complaintregister`
  that mimic the real bank's customer-support tooling.
- **ICICI impersonators** — apps claiming to be "iMobile" (ICICI's real
  mobile-banking product name) or "ICICI Rewards" under generic/placeholder
  package names such as `direct.uujgiq.imobile` or
  `com.example.test_app` — a strong signal in itself, since a genuine bank
  app is never shipped under a leftover Android Studio template package
  name.
- **Aarogya Setu impersonators** — fake versions of India's COVID-era
  government contact-tracing app, exploited during the pandemic as a
  trusted, mandatory-feeling install to smuggle a banking-trojan payload
  onto victims' phones under a health/government pretext rather than a
  banking one.

The common thread across all of these — and the reason a generic malware
scanner is not enough — is that the *malicious payload code* is often
reused, generic, or even absent until a second stage downloads, while the
**identity deception** (name, icon, package name, claimed developer) is
what actually gets the app installed and trusted by the victim. Detecting
that deception is a distinct problem from detecting the payload, and is
the specific gap this project's L0 layer targets (Part B, §6).

---

## 3. Indian government guidelines & context

Fake-app BFSI (Banking, Financial Services and Insurance) fraud sits at
the intersection of several Indian regulatory and law-enforcement bodies,
each covering a different slice of the problem.

### 3.1 RBI — mobile banking & digital payment security

The Reserve Bank of India regulates banks and payment system providers
directly, and has progressively tightened authentication requirements as
fraud patterns shifted toward defeating SMS-OTP-based two-factor
authentication (exactly the capability every family in §2.3 targets):

- The **RBI (Authentication Mechanisms for Digital Payment Transactions)
  Directions, 2025** (issued September 2025, compliance required from
  April 1, 2026) mandate at least one *dynamic* authentication factor for
  non-card-present digital transactions, with a **risk-based** model that
  allows lighter checks for small/low-risk payments and requires stronger,
  multi-factor checks for high-value or anomalous transactions.
- RBI's broader master-circular guidance on digital payment security
  requires banks to implement mobile-app security controls, robust fraud
  detection/risk-management systems, and continuous customer education
  about evolving digital-payment fraud patterns.
- RBI has separately been moving to **phase out plain SMS-OTP** as a sole
  authentication factor, precisely because SIM-swap, device-spoofing and
  malware-based SMS interception (Drinik and the family list in §2.3) have
  made it an increasingly weak control on its own.

### 3.2 CERT-In — the 2022 directions

The Indian Computer Emergency Response Team (CERT-In), operating under
Section 70B of the IT Act 2000, issued binding **Cyber Security Directions**
on April 28, 2022 (in force from June 28, 2022 after a transition period)
that materially raised the bar for incident handling across all regulated
and unregulated entities operating in India, including banks and payment
providers:

- **Mandatory 6-hour incident reporting** — any cyber incident (a list
  that explicitly includes data breaches, ransomware, and — relevantly
  here — malicious mobile applications) must be reported to CERT-In within
  six hours of the entity becoming aware of it, a materially stricter
  window than GDPR's 72 hours or the US CIRCIA's 72 hours.
- **180-day log retention**, with ICT system logs required to be
  maintained (and stored within India) for a rolling 180-day window.
- **NTP clock synchronization** with NIC/NPL time servers, ensuring
  incident timelines across organizations are comparable.
- A **6-hour response requirement** to CERT-In's own information requests.

For a project whose output is meant to feed an incident-response or
fraud-detection workflow, this reporting clock is the practical reason
"how fast can we produce a citable, evidence-backed verdict" is not an
academic question — it is the operational window a real BFSI security team
would actually have.

### 3.3 MeitY, DoT/Sanchar Saathi, and the wider ecosystem

- **MeitY (Ministry of Electronics & Information Technology)** is CERT-In's
  parent ministry and, jointly with CERT-In, CSIRT-Fin and SISA, publishes
  an annual **Digital Threat Report for India's BFSI sector** (2025–26
  edition released as the second edition of this collaboration) — an
  executive-level assessment of the threats reshaping banking, financial
  services, insurance and digital payments in India, explicitly flagging
  AI-driven phishing and automated exploitation as a growing concern.
- **DoT's Sanchar Saathi** platform (sancharsaathi.gov.in) is the
  Department of Telecommunications' citizen-facing anti-fraud portal. Its
  **Chakshu** facility lets citizens report suspected fraud communications
  (call/SMS/WhatsApp) — including fake-bank-app lures — *before* any
  financial loss occurs; DoT also operates the **Digital Intelligence
  Platform (DIP)**, a coordination system among telecom, banks and law
  enforcement to curb misuse of telecom resources (spoofed numbers,
  SIM-swap-adjacent fraud) in cybercrime.
- **I4C (Indian Cyber Crime Coordination Centre)**, under the Ministry of
  Home Affairs, is the counterpart for cases where a loss has **already**
  occurred: it runs the national cybercrime reporting portal
  (cybercrime.gov.in) and the 1930 helpline, which is the front door for
  victims of exactly this kind of fake-banking-app fraud.
- **NPCI (National Payments Corporation of India)**, as the operator of
  UPI, issues its own safety guidance and has rolled out a **real-time
  risk-alert system** integrated into major UPI apps (Google Pay, PhonePe,
  Paytm, BHIM and bank apps) warning users about risky payments before
  they complete. NPCI's core user guidance — verify the recipient name in
  your own app rather than trusting a screenshot/SMS, never share a UPI
  PIN or OTP, only install apps from official stores — is precisely the
  set of behaviors that fake-bank-app social engineering is designed to
  defeat.

### 3.4 Why this is a national priority

Fake-app BFSI fraud sits exactly where India's two biggest recent policy
successes — near-universal digital-payments adoption (UPI) and near-universal
smartphone/mobile-internet access — meet its biggest new attack surface.
A single well-crafted fake-bank APK, distributed at negligible cost over
WhatsApp or SMS, can defeat authentication mechanisms regulators have
spent years hardening (RBI's dynamic-factor and risk-based rules), simply
by running on the device *before* the transaction and reading or replaying
whatever second factor the bank sends. That is why the response spans
so many agencies at once — RBI (financial-system rules), CERT-In/MeitY
(cybersecurity directions and threat reporting), DoT (the telecom/SIM/SMS
channel malware rides in on), I4C (post-loss investigation), and NPCI (the
payment rail itself) — and why a tool that can say, quickly and citably,
"this specific APK is impersonating this specific Indian financial or
government brand" has a natural home in that ecosystem rather than being
a generic malware-scanning exercise.

---

## 4. Competitors & positioning

### 4.1 What existing tools do — and what they miss

| Tool | Type | What it does | What it misses (for this problem) |
|---|---|---|---|
| **MobSF** (Mobile Security Framework) | Open-source, self-hostable | Automated static analysis (manifest/permissions/certs/hardcoded secrets/insecure storage/weak crypto/exported components) plus Frida-based dynamic analysis (network traffic, filesystem, crypto calls, runtime behavior) for Android/iOS/Windows; REST API/CLI for CI/CD integration. | Answers "is this app insecure" as a generic mobile-appsec scanner — it is not built to ask "is this app pretending to be a specific bank," has no brand/identity-impersonation model, and (as a general-purpose scanner) is not tuned to India-specific BFSI brand namespaces. |
| **VirusTotal** | Cloud, multi-engine aggregator | Runs a submitted file/URL against 70+ third-party AV engines plus its own analysis tooling (including a Cuckoo-based dynamic sandbox); strong for "has anyone already flagged this exact file." | Fundamentally an AV-consensus aggregator, not a purpose-built Android-banking-fraud analyst — verdicts are only as good as whichever underlying AV engines have seen this specific (often freshly repackaged/never-before-seen) sample; no bank-impersonation reasoning; and every submission becomes visible to the wider ecosystem, which is a problem for confidential, in-progress fraud investigations. |
| **Hybrid Analysis** (Falcon Sandbox / payload-security.com) | Cloud sandbox | Free automated dynamic/static malware analysis service producing behavioral reports. | General-purpose cross-platform sandbox, not BFSI/India-focused; like VirusTotal, samples and results typically become part of a shared corpus rather than staying private to the analyst. |
| **Joe Sandbox** | Commercial cloud/on-prem sandbox | Deep dynamic analysis across Windows/macOS/Android/Linux/iOS; notably includes AI-driven **brand/logo-impersonation detection** (template matching, perceptual hashing, ORB feature detection against uploaded logos/templates) and live browser interaction for phishing flows. | Its brand-detection is logo/visual-template matching against whatever templates a customer uploads — powerful, but generic and commercial (not India-BFSI-curated out of the box), and it is a closed, paid platform rather than an auditable, evidence-cited pipeline. |
| **Koodous** | Collaborative community platform | Combines automated static/dynamic Android malware analysis over a large shared sample repository with community YARA-rule matching (public and private) and social/crowdsourced triage, explicitly including fraud-pattern detection. | Community/crowd-sourced signal quality varies; not India-specific; oriented around a shared public corpus rather than a private, per-case evidence trail for a specific suspect APK. |
| **Pithus** | Open-source, community-run (beta) | Aggregates several open tools — APKiD (obfuscation/packing detection), MobSF, Quark-Engine (rule-based malware detection), and Androguard (bytecode disassembly) — into one automated threat-intelligence report per APK; oriented toward activists, journalists, NGOs and independent researchers vetting apps for spyware/tracking risk. | Static-analysis only at present (no dynamic detonation); a general privacy/spyware-vetting tool rather than a BFSI-fraud-specific one; no bank-impersonation model or India-specific brand corpus. |
| **Quark-Engine** | Open-source Python library | A fast, rule-based Dalvik-bytecode analysis engine: extracts permissions and native API calls, evaluates them against five-stage behavioral "rules" (e.g., permission → API sequence chains characteristic of known malicious behaviors), and produces a threat score plus call-graph/summary/radar-chart reports within seconds. | A generic behavioral-rule engine over bytecode, with no notion of brand identity, no dynamic/network capture, and no India-specific rule corpus; it is a building block other tools (like Pithus) compose with, not an end-to-end fraud-verdict pipeline. |

### 4.2 Our positioning

The single-sentence framing, and the reason this project exists alongside
tools that already do competent general-purpose mobile security scanning:

> **MobSF answers "is this app insecure?" APK Sentinel answers "is this
> app pretending to be your bank, and how do we know?"**

Concretely, the differences the fact sheet establishes:

- **An evidence spine, not a scanner log.** Every layer (L0 through L6)
  writes into one merged, versioned record per sample
  (`artifacts/<sha256>/evidence.json`) with stable evidence IDs. Every
  claim the system makes — a verdict, a score contribution, a GenAI
  explanation — traces back to a citable evidence ID rather than being a
  free-text summary a human has to trust on faith.
- **India-specific L0 impersonation as the differentiator, not an
  add-on.** Where MobSF, VirusTotal, Hybrid Analysis, Koodous, Pithus and
  Quark-Engine all treat "what does this code do" as the primary question,
  this project treats "who is this app pretending to be" as a first-class,
  cheap, pre-decompilation triage question, backed by a hand-curated
  brand/whitelist corpus of Indian banks, UPI apps and government services
  (deliberately hand-curated rather than auto-derived — see the project's
  own T7/T8 traps on why naive fuzzy/derived brand matching produces
  dangerous false positives). Joe Sandbox is the closest existing analogue
  with its logo/template matching, but it is generic and commercial, not
  India-BFSI-curated.
- **Verified GenAI, not trusted GenAI.** Where GenAI is used (deobfuscation
  explanation, report narrative, the L2 UI-navigation agent), its outputs
  are mechanically verified rather than taken at face value — a lesson
  learned directly from failure modes like T26, where an LLM confidently
  mis-decoded a base64 C2 URL and RAG-based grounding alone could not have
  caught it, because retrieval grounds claims about the *threat landscape*,
  not claims about *this specific sample's bytes*.
- **Offline, deterministic-first — better and faster.** The pipeline runs
  on-prem/offline by default (no dependency on submitting a sample to a
  shared cloud corpus the way VirusTotal, Hybrid Analysis, or Koodous
  fundamentally require), processes one sample at a time from the corpus
  deliberately rather than batch-blind (a design choice directly informed
  by traps like T2, where batching files together for YARA scanning
  produced a 100% false-positive rate), and treats deterministic,
  measurable signals (hashing, manifest facts, certificate anomalies,
  per-class bytecode pattern matches) as the foundation that GenAI
  reasoning is layered on top of and checked against — not the other way
  around. That ordering is both a correctness property (a wrong
  deterministic fact cannot be argued away by a confident LLM) and a speed
  property (the cheap, offline checks run first and can already produce
  an evidenced verdict before any model call is needed).

---

## Sources

**APK structure & signing**
- [Android APK Reverse Engineering: From APK to Source — ROBINX0](https://robinx0.github.io/blogs/mobile-security/apk-reverse-engineering/)
- [APK Structure and Building Process — Medium (0xkenway)](https://medium.com/@0xkenway/apk-structure-and-building-process-learning-the-why-e25609a139de)
- [Structure of an Android App Binary (.apk) — Appdome](https://www.appdome.com/how-to/devsecops-automation-mobile-cicd/appdome-basics/structure-of-an-android-app-binary-apk/)
- [APK File Contents - In-Depth Explanation — Ajin Asokan](https://ajinasokan.com/posts/apk-file-contents/)

**Banking-trojan mechanics & 2025 examples**
- [Cerberus RAT: Android malware's dark legacy in 2025 — Prey Project](https://preyproject.com/blog/cerberus-rat-android-malware-dark-legacy)
- [Android Banking Trojan OverlayPhantom Abuses Accessibility Service — Cyber Security News](https://cybersecuritynews.com/android-banking-trojan-overlayphantom/)
- [OverlayPhantom Android banking trojan hiding in plain sight — Cyble](https://cyble.com/blog/overlayphantom-android-banking-trojan/)
- [New Android Banking Trojan "Klopatra" Uses Hidden VNC — The Hacker News](https://thehackernews.com/2025/10/new-android-banking-trojan-klopatra.html)
- [Top 4 Malware Targeting the Financial Sector — Bitsight](https://www.bitsight.com/blog/top-4-targeting-financial-sector)

**Malware families**
- [Alien Banking Trojan — Lookout Threat Intelligence](https://www.lookout.com/threat-intelligence/article/alien-banking-trojan)
- [Cerberus - A new banking Trojan from the underworld — ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld)
- [Alien - the story of Cerberus' demise — ThreatFabric](https://www.threatfabric.com/blogs/alien_the_story_of_cerberus_demise)
- [Cerberus (Malware Family) — Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/apk.cerberus)
- [TeaBot — Zimperium Mobile Security Glossary](https://zimperium.com/glossary/teabot)
- [FluBot — Zimperium Mobile Security Glossary](https://www.zimperium.com/glossary/flubot/)
- [SharkBot — Zimperium Mobile Security Glossary](https://zimperium.com/glossary/sharkbot)
- [Octo — Zimperium Mobile Security Glossary](https://zimperium.com/glossary/octo)
- [SharkBot: a "new" generation Android banking Trojan — NCC Group](https://www.nccgroup.com/research-blog/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store/)
- [SharkBot: a new generation of Android Trojans targeting banks in Europe — Cleafy Labs](https://www.cleafy.com/cleafy-labs/sharkbot-a-new-generation-of-android-trojan-is-targeting-banks-in-europe)

**Drinik & India-specific impersonation**
- [Drinik Android malware now targets users of 18 Indian banks — BleepingComputer](https://www.bleepingcomputer.com/news/security/drinik-android-malware-now-targets-users-of-18-indian-banks/)
- [Drinik Malware Targets Indian Taxpayers With Upgrades — Cyble](https://cyble.com/blog/drinik-malware-returns-with-advanced-capabilities-targeting-indian-taxpayers/)
- [18 Indian Banks Targeted by New Version of Drinik Android Malware — Heimdal Security](https://heimdalsecurity.com/blog/18-indian-banks-targeted-by-new-version-of-drinik-android-malware/)
- [Drinik: Malware targeting Indian taxpayers for bank frauds resurfaces? — MediaNama](https://www.medianama.com/2022/11/223-android-malware-drinik-indain-taxpayers-it-dept-fraud/)

**RBI**
- [RBI (Authentication Mechanisms for Digital Payments Transactions) Directions, 2025 — Lexology](https://www.lexology.com/library/detail.aspx?g=5481786f-8d45-48a6-97cd-a2b218f82d73)
- [RBI's new authentication directions: Strengthening digital payment security — IBM](https://www.ibm.com/think/perspectives/strengthening-digital-payment-security-with-rbi-new-authentication-directions)
- [RBI Revises Customer Protection Framework for Fraudulent Transactions — Lexology](https://www.lexology.com/library/detail.aspx?g=07edd0d8-9eed-4245-9cb1-10befde4e608)
- [2FA Changes by Reserve Bank of India to phase out SMS OTP — Corbado](https://www.corbado.com/blog/rbi-2fa-directives)
- [RBI's New Digital Payment Authentication Rules — Ujjivan SFB](https://www.ujjivansfb.bank.in/banking-blogs/personal-finance/rbi-digital-payment-authentication-rules)

**CERT-In**
- [India CERT-In Cybersecurity Directions 2022 — Internet Society](https://www.internetsociety.org/resources/doc/2022/internet-impact-brief-india-cert-in-cybersecurity-directions-2022/)
- [An Overview on the CERT-IN Cyber Security Directions, 2022 — Lexology](https://www.lexology.com/library/detail.aspx?g=899f3b94-c31f-4983-868f-5ee5abbf78c8)
- [CERT-In's six hour reporting rule — Argus Partners](https://www.argus-p.com/papers-publications/thought-paper/cert-ins-six-hour-reporting-rule-for-cyber-security-incidents-statutory-interpretation-and-analysis/)
- [A comprehensive guide to India's CERT-In 6-hour cyber incident reporting mandate — SIRI Law LLP](https://sirilawllp.com/a-comprehensive-guide-to-indias-cert-in-6-hour-cyber-incident-reporting-mandate/)

**MeitY / DoT / I4C / NPCI**
- [MeitY releases 2nd edition of the Digital Threat Report 2025-26 for BFSI — PIB](https://www.pib.gov.in/PressReleasePage.aspx?PRID=2284051&reg=48&lang=2)
- [MeitY Releases Digital Threat Report 2025-26 — Adda247 Current Affairs](https://currentaffairs.adda247.com/meity-releases-digital-threat-report-2025-26-to-strengthen-cybersecurity-in-indias-bfsi-sector/)
- [Chakshu facility of Sanchar Saathi enables citizens to report suspected fraud communications — ANI News](https://www.aninews.in/news/business/chakshu-facility-of-sanchar-saathi-enables-citizens-to-report-suspected-fraud-communications-govt20260205163602/)
- [MoC Ashwini Vaishnaw launches DoT's Digital Intelligence Platform (DIP) — PIB](https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=2011383)
- [Chakshu and DIP: Shielding Citizens from Online Frauds — CyberPeace](https://cyberpeace.org/resources/blogs/chakshu-and-dip-shielding-citizens-from-online-frauds)
- [Sanchar Saathi Suspected Fraud Communication Reporting](https://sancharsaathi.gov.in/sfc/)
- [What is NPCI UPI Risk Policy? — Hero FinCorp](https://www.herofincorp.com/blog/upi-risk-policy)
- [New NPCI Alerts Reduce UPI Payment Scams in India — BillCut](https://www.billcut.com/blogs/new-npci-alerts-fewer-upi-payment-scams/)
- [Passwords to vigilance: NPCI shares 5 tips for safe digital transactions — Business Standard](https://www.business-standard.com/finance/personal-finance/passwords-to-vigilance-npci-shares-5-tips-for-safe-digital-transactions-125071000494_1.html)

**Competitors**
- [Mobile Security Framework (MobSF) — official site](https://mobsf.github.io/Mobile-Security-Framework-MobSF/)
- [MobSF GitHub repository](https://github.com/mobsf/mobile-security-framework-mobsf)
- [Hybrid Analysis — SourceForge listing](https://sourceforge.net/software/product/Hybrid-Analysis/)
- [Deep Malware and Phishing Analysis — Joe Sandbox](https://www.joesecurity.org/)
- [Compare Hybrid Analysis vs. Joe Sandbox vs. VirusTotal — Slashdot](https://slashdot.org/software/comparison/Hybrid-Analysis-vs-Joe-Sandbox-vs-VirusTotal/)
- [Koodous — Collaborative Platform for Android Malware Analysts](https://koodous.com/)
- [Pithus — About](https://beta.pithus.org/about/)
- [Quark-Engine Book — official documentation](https://quark-engine.readthedocs.io/)
- [Quark-Engine Workflow documentation](https://quark-engine.readthedocs.io/en/latest/quark_inside_workflow.html)


---

# Part B — Technical Deep-Dive

This part walks through the repository as it actually is: what each layer
does, what the code contains, and where the measured numbers came from. It is
written to be read against the files it cites — every code claim below points
at a real path in the repo (e.g. `L1/engines/yara_scan.py`) so you can open it
and check. Where the project's own honesty rules require a caveat (an upper
bound, an unsupported score, an open gap), that caveat is stated here rather
than smoothed over — this is the project's explicit ethos ("measure before
claiming"), not editorial modesty.

---

## 5. Architecture overview

APK Sentinel is seven layers (`L0`–`L6`) glued by one merged evidence record
per sample, the **evidence spine**. The pipeline is a straight line for
gathering evidence (`L0 → L1 → L2`) and a fan-out for interpreting it (`L3`,
`L4`, `L5` each read the spine independently; `L6` renders the result):

```
APK ──► L0 triage ──► L1 static ──► L2 dynamic ─┐
        hash              jadx         emulator │
        manifest           YARA        Frida    │
        certificate        IOC pass    mitm     │
        icon pHash                              │
        bank impersonation                      ▼
                                     artifacts/<sha256>/evidence.json
                                       the evidence spine
                                                │
                    ┌───────────────┬───────────┴────────────┐
                    ▼               ▼                        ▼
                L3 ML prior     L4 GenAI              L5 hybrid scoring
                ±10 points      0 points              additive log-odds
                                                      + smoking-gun gates
                                                                │
                                                                ▼
                                                          L6 output
```

| Layer | Purpose | Status |
|---|---|---|
| L0 | Hashing, manifest, cert, icon pHash, bank-impersonation check | ✅ works |
| L1 | jadx decompile + YARA (source/dex/APK scopes) + IOC extraction | ⚠️ 37% malware-category detection, 18 dead rules |
| Spine | Merged `artifacts/<sha256>/evidence.json` | ✅ works |
| L2 | Emulator detonation, Frida, mitmproxy, DroidBot/GenAI navigator | ✅ MVP-ready; payload-triggering open gap |
| L3 | ML maliciousness prior, bounded ±10 | ⚠️ unified model trained, confound-bounded |
| L4 | GenAI verified deobfuscation + reasoning | ✅ works, 0 score points |
| L5 | Additive log-odds scoring + gates | ⚠️ scores stamped `unsupported` |
| L6 | Report/API/STIX/CSV/YARA/Sigma | ✅ works |

### The evidence spine (`spine.py`)

Three design constraints, each documented in the module's own docstring
because each was learned the hard way:

1. **The spine cannot live under `L0/artifacts/`.** `L0/ingest.py:run_l0`
   rewrites its own `evidence.json` from scratch on every run, resetting
   `l1`…`l6` to a placeholder — a spine stored there would be destroyed by
   the next L0 run. It lives instead at the top-level `artifacts/<sha256>/evidence.json`.
2. **One writer, and it merges rather than overwrites.** `spine.update_layer()`
   is the *only* function that writes a spine. It reads the current document,
   replaces only the caller's layer block and that layer's findings, and
   writes the result atomically (`tempfile` + `os.replace`, plus an `fsync` of
   both the file and its parent directory so the rename itself survives a
   power loss). A per-sample lock file (`_SpineLock`) prevents two concurrent
   writers from each reading the same document and overwriting the other's
   update. This is what lets L0 and L1 update the same spine independently
   without one destroying the other's findings.
3. **Findings need two identities.** `id` (`F001`, `F002`, …) is assigned
   after a deterministic sort (`assign_ids`) and is what a report or a score
   cites — but it *shifts* whenever a finding is inserted ahead of it (a new
   rule, a re-run). `fingerprint` is a stable hash of the finding's identity
   (detector + category + discriminator, e.g. the YARA rule name), and stays
   constant across ruleset edits. The convention: **cite `id`, diff on
   `fingerprint`.**

Layers are ordered (`spine.LAYERS = ("l0","l1","l2","l3","l3b","l4","l5","l6")`),
and only `l0`/`l1`/`l2` are `EVIDENCE_LAYERS` — the ones that can leave a
coverage gap. `_recompute()` derives `analysis_gaps` from every layer's status
(a `not_attempted` or `failed` evidence layer becomes e.g.
`detonation_not_attempted`), and derives finding counts by severity,
category, layer, and a frozen `MALWARE_CATEGORIES` set (nine categories:
`sms_intercept`, `overlay_attack`, `accessibility_abuse`, `c2_communication`,
`data_exfiltration`, `ransomware`, `native_payload`, `clipboard_hijack`,
`phishing_impersonation`). That set is explicitly *frozen* — widening it
silently redefines every historical before/after measurement, which is
exactly the kind of drift the project's traps (`T15`) warn about.

`update_layer()` is also idempotent by design: if a re-run produces an
identical document (ignoring timestamps), the file is left byte-for-byte as
it was, so "did anything change?" is answerable from a timestamp rather than
a diff.

---

## 6. L0 & L1 — triage, impersonation, and static analysis

### L0: triage and the bank-impersonation differentiator

L0 (`L0/ingest.py` and friends) computes hashes, parses the manifest,
extracts the icon and computes a perceptual hash, parses the signing
certificate, and — the differentiator — checks whether the app is
impersonating a known Indian bank, UPI platform, or government service.

`L0/impersonation.py` replaced an earlier `difflib.SequenceMatcher`
similarity gate that was simultaneously too weak and too strong: it scored
"SBI Quick Support" vs "YONO SBI" at only 0.31 (missing a real SBI clone)
while scoring "duckAssist" vs the Income Tax alt-label "iAssist" at 0.706 —
enough to raise a *critical* bank-impersonation finding on a benign
note-taking app (this is trap **T7**). The fix is **whole-token and
whole-phrase matching** against a curated per-entity brand vocabulary
(`L0/bank_whitelist.json`, 39 entities): "SBI Quick Support" tokenises to
`{sbi, quick, support}` and hits the token `sbi`; "duckAssist" camel-splits to
`{duck, assist}`, which cannot hit `iassist`. Two things are deliberately
*not* done, both measured against a 110-pair inventory before being cut:

- **No substring matching** — "BOI Mobile" compacts to "boimobile", which
  contains "imobile" (ICICI's brand token), a cross-brand false positive
  manufactured purely by compaction.
- **No fuzzy/edit-distance matching on labels** — that is what produced the
  duckAssist failure in the first place.

`brand_tokens` are hand-curated, never auto-derived (**T8**): derivation
would recreate T7 by proposing "assist" for Income Tax and Devanagari "बैंक"
for every bank. A `GENERIC_TOKENS` stoplist (bank, banking, pay, upi, secure,
…) and a load-time `validate_whitelist()` check catch a curated token that
accidentally collides with it. Package-name matching (`match_package`) checks
both vendor-namespace squatting (a package that starts with a bank's curated
prefix, only trusted when `package_verified: true` — **T9**, since 22 of the
original 39 package names were fabricated and returned HTTP 404) and brand
segments inside the package path.

L0 matches **only manifest-declared identity** (package name, app label) —
never dex or string content. This is a load-bearing scope boundary: it is
the structural reason PennyWise (an expense tracker that legitimately
mentions bank names in its own strings) stays clean at L0. String-level bank
references are L1's job.

### L1: static analysis — jadx, YARA, IOC extraction

L1 (`L1/l1.py`) decompiles the APK with jadx, then runs the YARA engine
(`L1/engines/yara_scan.py`) and an IOC pass over the result. This is also
where the project's other flagship claim lives, and it deserves the detailed
walkthrough the brief asks for: **the YARA engine is not simple text matching,
and getting that right was most of the layer's engineering effort.**

#### Why naive matching would produce ~100% false positives

A YARA rule's condition (e.g. `3 of ($wm*) and 2 of ($phish*)`) is evaluated
against whatever single buffer it is handed. If that buffer is the
concatenation of many unrelated files, the condition can be satisfied by
strings scattered across files that have nothing to do with each other. This
is **T2**, and it was measured directly: batching 500 `.java` files together
let multi-group conditions be satisfied by unrelated files, and the scanner
started matching benign apps against banking-overlay, ransomware, and dropper
rules simultaneously. `scan_sources()` in `yara_scan.py` therefore scans
**one Java file at a time, never concatenated** — a correctness requirement,
not a performance choice (measured cost: ~1.2 s on the corpus's largest
sample, actually *faster* than the batched path it replaced).

The same defect exists one level down inside a compiled dex. **A `classes.dex`
is the entire application concatenated**, third-party SDKs included (**T21**).
Scanning it as one buffer reproduces T2's bug: `_dex_class_buffers()`
(`yara_scan.py`) measured that whole-dex scanning made PennyWise, an expense
tracker, match *both* `Android_India_SMS_OTP_Stealer` and
`Android_Ransomware_Generic_File_Encryption`. So the dex is split into
**one buffer per class** via androguard, restoring the co-location
requirement a multi-group rule actually needs.

#### Member vs container scope

A raw APK is a ZIP, and almost everything inside it is deflated — so a scan
of the raw container sees the format (headers, central directory) but is
structurally blind to content (**T3**). Worse, `classes.dex` begins with the
magic bytes `dex\n035`, not `PK\x03\x04` — so any behaviour rule gated on
`uint32be(0) == 0x504B0304` (a ZIP-magic check meant for container-structure
rules) can **never** fire on a dex member, no matter what it contains
(**T20**). This silently blinded the scanner to the one place the
application's own strings live in plaintext. The fix, confirmed by measurement
in `scan_apk()`, is two separate rulesets and two required passes:

1. **Container pass** — the *container ruleset*, byte gates intact, run
   against the raw APK. Only rules that explicitly declare `scope = "apk"`
   are compiled into it (`_compile_rules()`), because a `scope = "both"`
   behaviour rule leaking into this pass previously matched
   `Android_BFSI_Accessibility_Driven_Exfil` **82 times on benign apps and 0
   on malware** (**T28**) — benign F-Droid apps have a median of 3,519
   decompressed files vs malware's 426, so a larger archive simply offers
   more raw bytes for a coincidental hit, and a conjunction across a
   compressed archive means nothing (co-location inside one class is the
   entire claim of a multi-group condition).
2. **Member pass** — the *member ruleset*, with container gates stripped
   (`_compile_member_rules()`, restricted to rules that still assert
   something about content after stripping — `_is_content_rule()`), run
   against decompressed members: `classes*.dex` (per class), `AndroidManifest.xml`,
   `assets/`, `res/raw/`, `lib/`. This is the pass that closed most of the
   detection gap: removing the container gate on the dex path took
   malware-category detection on the dex from 30% to 60% of samples and
   revived 16 previously-dead rules.

#### Dex API calls are invoke operands, not string literals

Even with per-class buffers, a buffer built only from `const-string`
literals is not enough. **A dex stores API calls as invoke operands into the
method pool, not as string literals** (**T22**). Measured directly on a
confirmed SMS trojan: a `const-string`-only buffer found **0 of 4** target
SMS APIs (`SmsManager`, `createFromPdu`, `getMessageBody`,
`sendTextMessage`); adding `invoke-*`/`sget`/`iget`/`sput`/`iput`/`new-instance`
operand names to the buffer found all four, with `createFromPdu` and
`getMessageBody` landing in the *same class* — exactly the co-location a
multi-group condition needs. `_dex_class_buffers()` walks each method's
bytecode instructions and appends the operand name for every
`const-string`/`invoke`/`new-instance`/`s{get,put}`/`i{get,put}` instruction.

#### Dead and library code

Two more failure modes were measured and handled explicitly:

- **Library/bloat code.** A source scan excludes framework/SDK path prefixes
  (`androidx/`, `kotlin/`, `com.google.android.gms/`, `com/google/firebase/`,
  `okhttp3/internal/`, …) via `_EXCLUDE_SOURCE_PREFIXES`, applied both to
  source files and to dex class names, so third-party library noise never
  enters a scan buffer in the first place.
- **Dead rules are not broken rules (T25).** 18 of 51 rules currently fire on
  nothing in the corpus. The project's test for whether a rule is *broken* is
  to compile it alone against a buffer of its own declared strings — all 18
  pass this self-match test. The conclusion drawn (and pinned in
  `CLAUDE.md` as T25) is that the *corpus* lacks the co-located vocabulary
  those rules look for, not that the rule's condition is wrong — which is
  why the fix path is "mine real per-class co-occurrence and rewrite the
  condition," not "assume the rule is malformed."

#### Severity, category, and finding shape

`_severity()` folds severity strings case-insensitively (Title Case rules had
been silently downgrading to MEDIUM — **T11**). `_categorize()` prefers a
rule's declared `category` meta field and falls back to a regex catalog
matched against the rule name/description only when no category is declared
(several `Category` members were previously unreachable this way — **T12**).
A YARA rule's condition is the unit of detection, so a rule that fires
becomes **one finding** regardless of how many strings or files matched
(`_RuleHit`/`_acc_to_findings`); breadth (locations, match count, string ids,
up to 8 samples) is preserved as `detail` fields rather than inflating the
finding count. `merge_findings()` then structurally collapses a rule that
fired in several scopes (source + apk) into one finding by construction.

Every ruleset change — including a pure *scanner behaviour* change that
edits no `.yar` file, like the T28 container-scope fix — bumps
`SCANNER_BEHAVIOUR_VERSION`, which is hashed into `ruleset_version()`
alongside the rule files themselves. This matters operationally: the corpus
runner resumes on `ruleset_version`, so a behaviour change that left the
constant alone would have silently shipped while every already-run sample
was skipped as "already done" (**T29**).

---

## 7. L2 — dynamic analysis

L2 (`L2/sandbox/orchestrator.py` and supporting modules) detonates a sample
on the `sentinel30` AVD (Android 30) and instruments it while an interaction
engine drives its UI. This section is deliberately candid: **capture is now
reliable; getting a sample's actual malicious logic to fire is the one thing
that still hasn't happened.**

### Full flow

`L2Orchestrator.run()`:

1. `DetonationSafety.pre_check()` — structural go/no-go (is this really an
   emulator serial, is there enough disk).
2. `safety.enforce_isolation()` — iptables rules applied *inside* the
   emulator via `adb shell su 0 iptables`: NAT `DNAT` redirects TCP 80/443 to
   the host's mitmproxy (`10.0.2.2:8080`); a custom `st_OUTPUT` chain accepts
   loopback and the emulator's own host subnet (`10.0.2.0/24` — covers proxy,
   DNS relay, adb) and **drops everything else**.
3. `ProxyManager.up()` — belt-and-suspenders: sets the system HTTP proxy
   setting, and blackholes known C2/telemetry hostnames (`firebaseio.com`,
   `fcm.googleapis.com`, `api.telegram.org`, `mtalk.google.com`) via
   `/etc/hosts` redirects.
4. `start_network_interception()` — launches `mitmdump` (not the interactive
   `mitmproxy` TUI, which exits immediately under a non-tty `Popen` — a
   real bug the code documents fixing) with the honeypot addon, then starts
   `PcapCapture` (`tcpdump -i any`).
5. `safety.verify_isolation()` — **fail-closed** verification, run only after
   isolation is applied: a ping to `8.8.8.8` must *fail* (a successful ping
   means isolation did not take), and a `nc` TCP probe to the proxy address
   must *succeed* (so "block everything, including the proxy" is not
   mistaken for a working isolation state). Both are required; either
   failing aborts the run via `DetonationSafetyError`.
6. `_ensure_frida_server()` — pushes and starts `frida-server` on the device
   if it is not already running (see below — this was itself a real,
   previously-undiagnosed bug).
7. `prepare_environment()` — installs the APK, pre-grants the dangerous
   permissions malware needs to run its real logic (`READ_SMS`,
   `RECEIVE_SMS`, `READ_CONTACTS`, `READ_PHONE_STATE`, `SEND_SMS`,
   `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, …), enables the
   app's accessibility service if it declares one, dismisses the legacy
   permission-review screen, and seeds honeypot data (fake Indian
   contacts, fake bank SMS via a silent content-provider insert, a spoofed
   New Delhi GPS location).
8. `detonate()` — launches the interaction engine (DroidBot or the GenAI
   navigator), schedules three fake-OTP SMS injections, and keeps Frida
   attached for the whole window (see below).
9. Teardown: stop pcap and pull `capture.pcap`, kill mitmproxy, copy
   `network_evidence.json` into the sample's artifact directory, uninstall
   the app, and `safety.post_restore()` (flush the iptables rules, clear the
   proxy setting).

### jadx

jadx decompilation is not part of L2 itself — it is L1's static pipeline —
but its output (`jadx_src`) is what L4's deobfuscation reads, and L2's
Frida instrumentation targets the same running code jadx decompiled
statically, so the three layers describe the same artifact from three angles
(static source, YARA match locations, and runtime hook events).

### Frida: re-attach-by-PID

Frida hooking went through three rounds of debugging documented in
`docs/l2_droidbot_reliability_log.md`, and the final design has three fixes
worth naming because each defeats a specific, previously-invisible failure:

1. **`frida-server` was never deployed.** `frida-ps`/`pidof`-style process
   enumeration works over plain `adb` and doesn't need `frida-server` at all
   — so every "process liveness" check kept reporting success while every
   actual *attach* failed with a misleading error, because there was never a
   server to attach to (`-wipe-data`, used for clean AVD boots, wipes
   `/data/local/tmp` on every fresh boot). `_ensure_frida_server()` now
   checks, pushes, and starts it before every run.
2. **Attach by PID, not by package identifier.** `frida -U <package_name> -l
   script` fails with `Failed to spawn: unable to find process with name
   '...'` on this frida-tools/Android combination — even when `frida-ps -Uai`
   lists the exact identifier. Resolving the PID via `adb shell pidof` and
   attaching with `frida -U <pid> -l script` (`_wait_for_pid`,
   `_frida_hook_loop`) attaches reliably.
3. **The CLI's output is Python-repr, not JSON.** `frida`'s non-interactive
   REPL emits lines like `[Android Emulator 5554::PID::21717 ]-> message:
   {'type': 'send', ...} data: None`. A naive `json.loads()` on every stdout
   line silently discarded every hook that fired. `_parse_frida_cli_line()`
   is a bracket/string-aware scanner (never `eval` — this parses adversarial
   sandbox output) that extracts the dict with `ast.literal_eval` and
   re-emits real JSON.

Because DroidBot can force-restart the target (observed as tight as every
2–3 s on a splash-looping sample, which kills the attached `frida`
subprocess with it), `_frida_hook_loop` runs as a background thread for the
whole detonation window, **re-resolving the PID and relaunching `frida`
every time the previous attach dies** — confirmed on the SBI sample: 7–8
separate re-attachments across one 90 s run. An unconditional diagnostic
`send({type:"diagnostic", note:"frida_attached"})` ping was added to every
combined hook script, because every real hook script only sends when the
target app actually calls the hooked API — without the ping, "attached fine,
nothing suspicious happened" was indistinguishable from "never attached at
all."

The hook scripts themselves (`L2/sandbox/frida_scripts/`):

| Script | Purpose |
|---|---|
| `stealth_init.js` | Spoofs `Build.FINGERPRINT`/`MODEL` etc. so the AVD looks like a Pixel 7, defeating emulator-detection checks |
| `dynamic_hooks.js` | Hooks security-relevant APIs (SMS send/receive, etc.) and reports structured `finding` events |
| `auth_fill.js` | Detects login/auth screens by EditText hint text and fills plausible fake Indian credentials (mobile, account, MPIN, OTP, Aadhaar, password) |
| `auth_bypass.js` | Bypasses `BiometricPrompt`/`FingerprintManager`/`KeyguardManager` checks and forces `SharedPreferences` login/session flags |
| `accessibility_hooks.js` | Hooks `onAccessibilityEvent`, `performGlobalAction`, `AccessibilityNodeInfo.performAction` — the abuse pattern banking trojans use to read screens and auto-click through dialogs |
| `ssl_unpin.js` | Universal SSL pinning bypass so mitmproxy can see HTTPS traffic (no system CA install — `/system` is read-only on this AVD build) |

### DroidBot: UI exploration via UTG/uiautomator

DroidBot (`_run_droidbot()`) explores with a greedy DFS UI-transition-graph
(UTG) policy, writing `utg.js` and screenshots to `droidbot_utg/`. The
reliability log records a genuine restart-loop bug (permission-review dialog
never dismissed → DroidBot sees a foreign system activity → force-restarts)
that was fixed as a *side effect* of the Frida re-attach fixes above, then
independently re-verified live: 3/3 runs where DroidBot reaches and
genuinely operates the SBI sample's real `MainActivity` (touch events,
long-touch, `SetTextEvent`), not stuck on a splash screen. `device_state.py`
carries a small patch so DroidBot's field-filling heuristic can type the
actual OTP value about to arrive, read from the hint file (below).

### Network isolation, verified fail-closed

Covered above in the flow (`safety.py`); worth restating because it is the
part of L2 the project is most confident about, having been re-verified by
reading the code line-by-line: `enforce_isolation()` is called at
`orchestrator.py:947`, `verify_isolation()` at `:951`, and the verification
is fail-closed in both directions (ping must fail, proxy path must succeed)
rather than a single "can I reach the internet" check that a
block-everything misconfiguration would pass by accident.

### mitmproxy active honeypot

`L2/sandbox/mitm_addon.py`'s `L2ActiveHoneypot` logs every request/response
to `network_evidence.json` and does two things beyond passive capture:

- **Exfiltration detection.** A keyword list (`otp`, `pin`, `aadhaar`,
  `mpin`, `cvv`, `upi`, `ifsc`, `imei`, `contacts`, `sms`, …) checked against
  request bodies (and against a best-effort base64-decoded form of the body,
  including double-base64), plus a volume heuristic (a POST ≥1024 bytes to a
  host that isn't a known CDN/telemetry suffix is flagged as possible bulk
  exfiltration).
- **Active response hijacking.** When the malware calls what looks like a
  bank/UPI API (matched by hostname substring against a bank-name list and
  by URL-path regex, e.g. `/api/v\d+/account/balance`), the addon fabricates
  a plausible success response — fake UPI transaction history, account
  balances, a beneficiary list with IFSC codes, a mini statement — as well as
  spoofed responses for Firebase Realtime Database (`firebaseio.com`) and the
  Telegram Bot API, both used by some Indian banking trojans as an HTTP(S) C2
  channel. The design goal is to keep the malware convinced it succeeded so
  it progresses to its next attack stage.

One deliberate limitation the code documents explicitly: FCM push delivery
to a device rides `mtalk.google.com:5228` over a binary MCS/protobuf
protocol that never traverses an HTTP(S) proxy — mitmproxy structurally
cannot see or hijack it, so `proxy_setup.py` blackholes that host at the DNS
layer instead. An earlier version of the project's documentation claimed a
"response hijacking" capability against this channel; that claim was
deleted once the protocol was actually checked (recorded in `CLAUDE.md` §7).

### tcpdump PCAP

`L2/sandbox/pcap_capture.py`'s `PcapCapture` starts `tcpdump -i any -w
/sdcard/capture.pcap` in the background via `adb shell su 0 tcpdump`, and on
stop sends `SIGINT` (tcpdump's clean-flush signal, not a hard kill) before
pulling the file to the sample's artifact directory as `capture.pcap` — a
raw packet capture alongside the higher-level `network_evidence.json`.

### OTP injection

`OTP_INJECTION_SCHEDULE` fires three fake bank-OTP SMS at T+10s (SBI),
T+20s (HDFC), T+30s (ICICI), each generated up front and written to
`latest_injected_otp.txt` (env `DROIDBOT_OTP_FILE`) *before* it is sent, so
DroidBot's patched field-filler (and the GenAI navigator, via
`DummyDataGenerator.otp()`) can type the value that is about to arrive
rather than a disconnected guess. Delivery is via `adb emu sms send`, which
triggers a **real `SMS_RECEIVED` broadcast** — distinct from
`HoneypotSeeder.seed_sms()`, which only inserts a silent content-provider
row and cannot trigger an OTP-listening receiver.

### The honest gap: payload triggering

Everything above — attach, capture, isolation, honeypot, PCAP, OTP delivery
— is now measured as working. What has never been observed is a sample's
**actual malicious payload firing**: on the SBI sample, `frida_hooks.jsonl`
holds only attach diagnostics, and `network_evidence.json` stays at 0
requests across DroidBot runs that reach and genuinely operate the app's one
real screen (a complaint-registration `EditText` + `SUBMIT` button — DroidBot
exhausts the available widget permutations and finds no further screen).
The reliability log's own diagnosis: whatever gates this sample's SMS
interception logic sits behind a specific form-submission flow, a
server-response condition the mitmproxy honeypot's canned shapes may not
match this exact app's endpoints, or passive SMS-broadcast listening the
injected OTP didn't trigger for reasons unrelated to navigation. This is
explicitly **not** a navigation-depth problem any more — it needs
sample-specific reverse engineering of the SUBMIT handler. The GenAI
navigator (§11) is the project's current attempt at that gap, on the theory
that DroidBot's blind exploration can reach a form but cannot *reason*
through it the way a form-filling adversary would.

---

## 8. L3 — ML classifier

L3 is a **generic maliciousness prior**, bounded to ±10 points on the final
0–100 score, and by design it can never produce a verdict on its own
(enforced in `L5/score.py::apply_ml`, pinned by a test). It has gone through
two generations in this project, and the second exists specifically because
measurement caught the first one lying quietly.

### Generation 1: LAMDA, Drebin-style features, and the train/serve skew

`L3/train.py` trains on **LAMDA** (HuggingFace `IQSeC-Lab/LAMDA`, MIT,
1,008,381 rows × 4,561 precomputed binary Drebin-style columns, temporally
partitioned by year so the split is 2013–2022 train / 2023+ held-out-future
rather than a random split that would leak the future into the past). The
bridge from *our* APKs to LAMDA's fixed vocabulary is `L3/features.py`,
which extracts ten Drebin-style token families (`RequestedPermissionList`,
`UsedPermissionsList`, `ActivityList`, `ServiceList`,
`BroadcastReceiverList`, `IntentFilterList`, `HardwareComponentsList`,
`RestrictedApiList`, `SuspiciousApiList`, `URLDomainList`) from the manifest
and the dex, then looks each candidate token up in LAMDA's
`feature_mapping.csv`.

**The measured problem:** LAMDA's own reference density is 2.54% of columns
set per sample. Our extractor reproduced only **0.4–1.8%** — most of LAMDA's
4,561 columns simply never populate from our pipeline, because the tokens
our extractor emits and the tokens LAMDA's original (AndroZoo-derived)
extractor emitted use different spellings and conventions for the same
underlying fact. A model fit on one extractor's tokens and served with
another's is the textbook train/serve skew failure mode: it still returns a
probability for every input, and nothing about a near-empty vector *looks*
broken — it is a constant dressed up as a prediction.

### Generation 2: the unified pipeline-extracted dataset

`decision-0011-l3-unified-dataset.md` documents the fix: stop forcing our
tokens through LAMDA's fixed schema, and instead build the column space
**from the tokens our own extractor emits, across our own corpus** — so
train and serve use exactly one extractor and there is no vocabulary skew.
The token producer is unchanged (`L3.features.extract_from_apk`); what
changed is which of those tokens become columns.

`L3/unified_features.py` adds two deliberate filters on top of the raw
token stream:

- **`meaningful_tokens` relevance filter.** A raw extraction over a modern
  app emits ~100k tokens, ~99% of them androidx/kotlin/Google-Play-Services
  library signatures — an artifact of *which SDKs an app bundles*, not
  behaviour. Since the corpus is F-Droid (benign) vs CICMalDroid (malware),
  keeping those tokens would let the model learn "uses androidx → benign,"
  the ML-form of the same T27/T28 confound already found in the YARA
  scanner. `is_meaningful()` keeps only the cross-app manifest families
  (permissions, intent-filter actions, hardware features, URL domains) plus
  API calls into a curated allow-list of **security-relevant** framework
  classes — telephony/SMS, accessibility, device-admin, dex-loading
  (`dalvik.system`), crypto, reflection, notification/clipboard managers,
  screen capture, WebView. This allow-list names classes, not samples, so it
  is capability selection rather than per-sample tuning.
- **`cap:*` capability (absence) signals.** 13 synthetic aggregate columns
  (`cap:sms`, `cap:accessibility`, `cap:device_admin`, `cap:dynamic_code`,
  `cap:overlay`, …) each fire if *any* of several token spellings for that
  capability is present. This exists directly because the dataset analysis
  (below) found the strongest genuine discriminator is a capability being
  *absent*, not any single brittle token spelling — an individual API token
  is defeated by refactoring, but a capability aggregate is robust to it, and
  computed identically at train and predict time so it carries no skew of
  its own.

Column selection uses a document-frequency floor and ceiling
(`build_vocabulary`, `min_df=5`, `max_df_ratio=0.98`): a token in one app is
a memorised sample id, not a feature; a token in ~every app carries no
discrimination. The frozen vocabulary is persisted and loaded identically
by the dataset builder and the predictor.

### The source confound, measured honestly (T27, ML form)

The corpus is **source-confounded**: every benign sample is F-Droid, every
malware sample is CICMalDroid/GitHub — two disjoint populations, so the
*source* is nearly perfectly correlated with the *label*. `L3/unified_train.py`
and `L3/unified_cv.py` build this honesty in structurally rather than
leaving it to a caveat in prose:

- The split is **group-disjoint** (group = malware family where provenance
  reveals one, else the sample's own sha), so family variants never
  straddle train/test.
- Only **held-out** metrics are ever reported, never in-sample.
- The metrics file explicitly flags a held-out AUROC ≥ 0.99 as *probable
  source-artifact leakage, not detection skill* — a threshold check built
  into the training script itself, not a note a reader has to remember to
  apply.

`tools/analyze_unified_dataset.py` (output: `docs/reports/unified_dataset_analysis.json`)
quantifies the confound directly rather than asserting it:

| Measurement | Value |
|---|---|
| Dataset shape (analysis run) | 3,317 rows × 7,821 columns (2,714 malware / 603 benign) |
| Exact duplicate feature vectors | **59.3%** of rows |
| Rows with a ≥0.95-cosine near-twin | **73.5%** |
| PCA PC2 — separates label | AUROC 0.978 |
| PCA PC2 — separates source (F-Droid vs CICMalDroid) | AUROC 0.903 |
| Strong malware-only separators (columns) | 2 (`TelephonyManager.getLine1Number`) |
| Strong benign-only separators (columns) | 90 — nearly all modern `AccessibilityNodeInfo`/reflection API calls, a build-era artifact of when each corpus was collected |
| SMS-capability present, malware vs benign | **79.9% vs 10.8%** — the one real capability signal |

That PC2 separates *both* label and source at nearly the same AUROC is the
confound made visible in one number: the model's easiest available signal
and the source label are close to the same axis. The 90 benign-only
"separator" columns being modern accessibility-API methods rather than
anything behavioural is exactly the failure mode the relevance filter and
capability aggregates are designed to blunt, not eliminate — F-Droid apps
are simply newer than the 2020–2022 malware corpus, and a model without the
guard would happily learn "modern androidx call → benign."

*(Note: the FACT SHEET states 3,319 rows × 7,834 columns; the analysis file
actually on disk reads 3,317 × 7,821 — a difference of 2 rows / 13 columns,
almost certainly the `plausible`-row filter applied before the analysis
script ran vs the raw build count. Flagged here rather than silently
reconciled; both figures describe the same dataset to within rounding.)*

### Accuracy — and the upper-bound caveat

A single group-disjoint split reported AUROC 0.9958 — suspicious on its
face, and `L3/unified_cv.py` exists specifically to interrogate that number.
CICMalDroid ships near-duplicate/repacked samples, so two rows with an
*identical feature vector* but different sha256 could land on opposite sides
of a group-disjoint split — free AUROC from a train/test intersection that
has nothing to do with the model generalising. `unified_cv.py`
near-deduplicates same-label rows at cosine similarity ≥ 0.97 (down to 1,166
rows) and runs stratified 5-fold cross-validation on the result:

**AUROC 0.9963 ± 0.0017** (5-fold, deduplicated).

This is explicitly labelled — in the code, not only in this document — as an
**upper bound**: dedup removes the *duplicate-leakage* inflation, but it does
not touch the source confound. The model is separating F-Droid from
CICMalDroid, not malware from benign in general, and the metrics file's own
`LEAKAGE_AUROC = 0.99` threshold check fires on this result and says so. L3
therefore stays a bounded ±10 generic prior — never a verdict — and the real
number the project actually needs (a false-positive rate against a benign
*banking* app) requires a benign-banking hard-negative panel that does not
yet exist (see §12).

---

## 9. L4 — GenAI reasoning

L4 explains code that L1 has already flagged as interesting; it never
extracts new facts on its own authority, and — enforced structurally, not by
convention — it **never reaches the score.** `decision-0004` (LLM contributes
zero points) is unchanged by anything in this section; `L4/deobfuscate.py`'s
`promote()` literally sets `"contributes_points": 0` in its spine summary,
and there is no code path from L4's output into `L5/score.py`.

### Scope: six to eight calls, not a full-app summary

Summarising every class of a decompiled Android app costs 30–40 minutes of
model time and mostly describes framework/SDK code no analyst would read.
`interesting_locations()` instead reads the `location` fields off L1's
findings, most-severe first, and caps at `MAX_CLASSES = 8` — L1 has already
done the work of deciding what's worth explaining.

### The knowledge base and the three-agent chain

`L4/knowledge/build_kb.py` builds `kb.json`, a curated set of entries (MITRE
ATT&CK Mobile techniques, YARA rule metadata, India-specific patterns) that
`L4/knowledge/retriever.py` indexes with TF-IDF for retrieval. For each of the
selected classes, `explain_class()` in `deobfuscate.py` runs a four-stage
chain — three LLM calls plus one deterministic function:

1. **Analyst** (LLM call 1) — reads the class source, one line of L0 context
   (brand claim / cert anomaly), one line of L2 package-level context
   (`sms_intercepted`, `overlay_displayed`, C2 endpoint count), the top-3 KB
   matches for this class, and any string/host correlation against captured
   network traffic. Returns structured JSON claims: `purpose`, `renamed`,
   `decoded_strings`, `api_calls`, `iocs`, `behaviours`, `matched_pattern`,
   `confidence`.
2. **Mechanical verify** (`L4/verify.py`, no LLM) — every claim class a
   decoder, parser, or substring search can settle is settled that way (see
   below).
3. **Reasoning trail** (LLM call 2, `L4/reasoning_trail.py`) — sees only what
   *survived* mechanical verification, never the raw class source, and
   builds a cited evidence chain against the KB matches.
4. **Adversarial verifier** (LLM call 3, `L4/verify_verdict.py`) — reads the
   source code and the trail, and is explicitly instructed *"do not be
   agreeable — a trail that holds up under genuine scrutiny is rare, not the
   default outcome."* Its `status` (`confirmed`/`weakened`/`refuted`) can
   only be pushed **down** by a mechanical citation check
   (`_mechanically_check_citations`): every `kb_id` the trail claims to cite
   is looked up in the KB index, never asked of the model itself, and a
   fabricated citation forces `status` toward `weakened`/`refuted` regardless
   of what the LLM's own adversarial pass concluded.

A deterministic `score_class()` (no LLM) then turns kept claims + KB
similarity + verifier status into a 0–10 report-ranking score — this score
feeds `L6`'s ranked report, never `L5`.

### Grounding: RAG vs mechanical verification, and why the split matters

The project draws a hard line between two kinds of claim, and this is the
system's actual anti-hallucination architecture, not a footnote:

- **RAG (retrieval) grounds claims about the threat landscape** — "this
  behaviour matches a known MITRE ATT&CK technique." `L4/knowledge/retriever.py`
  is TF-IDF cosine similarity, and as of this session uses a **hybrid word +
  character n-gram vectorizer** (`FeatureUnion` of a word-level
  `TfidfVectorizer` and a `char_wb` 3–5-gram `TfidfVectorizer`), plus
  camelCase/dotted-identifier expansion (`_expand_identifiers` — API names
  like `sendTextMessage` survive obfuscation where renamed identifiers do
  not, so exposing their word components lets retrieval match KB prose that
  spells the behaviour out even when the class's own identifiers are
  scrambled).
- **Mechanical verification grounds claims about *this specific sample*** —
  and retrieval structurally cannot do this job. `L4/verify.py`'s docstring
  states the reason with the project's own worked example: during model
  selection, a candidate model was given the literal
  `aHR0cDovLzE5Mi4xNjguMS4xMDAvZ2F0ZS5waHA=` and confidently asserted it
  decoded to `.../get.php`. The true decoding is `gate.php` (**T26**). The
  claim was fluent, plausible, and exactly the shape of a real finding — and
  wrong in a way retrieval could never catch, because no amount of retrieved
  threat intelligence tells you what one specific base64 string actually
  decodes to. That has to be settled by calling `base64.b64decode()` and
  comparing.

`verify.py` accordingly re-checks every checkable claim class:

| Claim | Check |
|---|---|
| `decoded_strings` | Re-decode the literal ourselves (base64 std + URL-safe, nested base64, base32, hex, gzip/zlib, plus speculative XOR/ROT13 gated on the result being indicator-shaped) and compare |
| `renamed` | The obfuscated identifier must occur at a word boundary in the code |
| `api_calls` | The API name (in any of its legitimate source forms — `Log.i`, `new Date(`, etc.) must occur in the code |
| `iocs` | Must already be in L1's extracted indicator list — the model may never introduce a new indicator |
| `matched_pattern` | The cited `kb_id` must be one retrieval actually surfaced |

A claim that fails its check is **dropped, not down-weighted**, and the drop
is recorded (`Verdict.drop()`) so a reader can see exactly what the model
said that didn't hold up. Free-text fields with no mechanical check
(`behaviours`, `purpose`) are carried but explicitly labelled `unverified`.

### The three L4 grounding fixes made this session

1. **`retriever.py`: hybrid word + char n-gram TF-IDF + identifier
   expansion**, described above — makes retrieval robust to renaming and
   obfuscation rather than relying on exact word overlap.
2. **`verify.py::_try_decode`: broadened decoders** — added base32, URL-safe
   base64, nested (double) base64, gzip/zlib decompression, and ROT13
   (speculative decoders gated on the result being indicator-shaped, so
   plain ASCII text never yields a spurious "decoding"). This directly
   reduces false *drops* of a correct decoding the analyst got right but the
   old, narrower decoder set couldn't confirm.
3. **`verify.py`: a new `dex_symbols` haystack.** `deobfuscate.py::dex_symbols()`
   reads identifiers, class names, method names, field names, and string
   constants straight from the DEX via androguard, independent of jadx. This
   supplements the jadx-decompiled source for the `renamed`/`api_calls`
   checks, so a true claim about a class jadx failed to decompile (or
   truncated) is no longer falsely dropped — grounding stops being coupled
   to decompiler success.

All 44 L4 tests pass; the full suite is 393 passed / 1 skipped / 1
pre-existing (unrelated) fail. Session work is on branch
`session-2026-08-25-l3l2l4`; the L4 fixes specifically are commit `0dac60c`.

---

## 10. L5 — hybrid scoring

L5 (`L5/score.py`, `L5/gates.py`, `L5/policy.yaml`) turns the spine's
findings into a 0–100 score, and its entire design is built around one
constraint: **every point must trace to a named signal or gate carrying the
evidence id that produced it.** The arithmetic below exists to serve that
constraint, not the other way around.

### Four stages

1. **Accumulate, with per-family redundancy discount.** Three SMS rules
   firing on the same class is close to one fact, not three — naive addition
   would double-count correlated evidence and manufacture false confidence.
   `accumulate()` groups a sample's priced signals by *family* (defined in
   `policy.yaml` — `sms`, `overlay`, `accessibility`, `c2_exfil`, `dropper`,
   `cert`, `brand`, `hygiene`), ranks each family's members by `|weight|`,
   applies a **geometric decay** (family-specific, e.g. `0.5` for `sms`,
   `1.0`/no decay for `brand`) so the second- and third-strongest members of
   a family contribute progressively less, and caps the family's total
   contribution (e.g. `sms` caps at ±4.0). The audit trail attributes any
   clamping to the family's weakest member rather than silently rescaling
   everything.
2. **Map the unbounded log-odds total to 0–100** via a sigmoid with two
   fitted anchors, not a bare linear map or an unbounded raw sigmoid: `s0` is
   the log-odds at which the empirical posterior P(malware | evidence)
   crosses 0.5 (so "score 50" *means* "as likely malicious as benign given
   this evidence," not an arbitrary midpoint), and the temperature `T` is
   solved so the log-odds at which the benign false-positive rate reaches 1%
   lands exactly on score 85 (the Critical threshold). Both anchors are
   re-derivable by `tools/fit_calibration.py`, not hand-picked.
3. **Apply L3 (and, separately, L3b)** as a delta clipped to ±10 points and
   structurally unable to push a score into Critical on its own
   (`apply_ml`'s explicit clamp) — because L3 is trained on a corpus that is
   ~99.6% non-banking (or, for L3b, on an unverified split), and must never
   make a banking-specific claim by itself.
4. **Apply gates as floors** — `max(score, floor)`, never an override. A gate
   can only raise a score, never lower one, and if the additive score already
   exceeds a gate's floor the full underlying reason chain still survives in
   the audit trail rather than being replaced by the gate's own (shorter)
   justification.

### Smoking-gun gates

`L5/gates.py` defines four gate combinations, each requiring **distinct
evidence** on both legs — both legs must cite different finding ids, or the
gate refuses to fire. This closes a specific loophole: without it, a single
rule like `Android_BFSI_SMS_Intercept_And_Forward` (which detects reading
SMS *and* forwarding it inside one rule) would satisfy both halves of the G2
gate by itself, making the "gate" nothing but a rename of one rule's own
large additive weight.

| Gate | Legs | Floor | Status |
|---|---|---|---|
| G1 | Bank impersonation (L0) + credential-harvesting UI (L1) | 85 | ✅ enabled |
| G2 | SMS interception + exfiltration to an external C2 | 85 | ✅ enabled |
| G3 | Accessibility abuse + overlay on a *known bank package* | 85 | ❌ disabled — no evidence source records *which* package a targeting rule matched |
| G4 | Dropper permission + embedded secondary APK | 70 | ❌ disabled — L0 does not yet record either input |

Gates are evaluated **ternary**, not boolean: `fired` / `not_fired` /
`indeterminate`. A leg whose input is missing because coverage genuinely
failed (e.g. L1 never completed) is `indeterminate`, never treated as
`False` — collapsing "we don't know" into "no" would make a failed analysis
read as a clean app, which is precisely the kind of silent miscalibration
the confidence axis (a separate axis, never touching the score) exists to
avoid. G3 and G4 ship disabled rather than enabled-but-always-false, because
"the gate did not fire" reading as evidence of innocence would be worse than
an honest "we can't evaluate this yet."

### Why scores are currently `unsupported`

Weights are **computed, not asserted** — `tools/rule_firing_report.py` (A4)
produces Jeffreys-smoothed log-odds ratios from measured firing rates across
the malware and benign corpora, and `L5` refuses to load a weights file whose
`ruleset_version` doesn't match the current ruleset. But at the benign corpus
sizes measured so far, this arithmetic genuinely breaks: **T24** found that at
`n_benign = 4`, 32 of 45 signals were priced **negative** — as evidence of
being *benign* — including `l0:brand_claim`, the project's own differentiator,
at −1.90. The top-weighted signal in the whole system was
`APK_Valid_Structure_Check` (+2.85), i.e. "is a well-formed ZIP." This is not
imprecision; it is sign-inversion, because the Jeffreys 95% upper bound on
"0 false positives out of 4 samples" is **0.445** — every historical "0/4
benign false positives" claim actually meant "somewhere between 0% and 44%."

The requirement for a weight to have the correct sign is closed-form
(derived in `CLAUDE.md` T24): with a benign base rate `b=0`, `w>0` iff
`B > 0.5·(M−m+0.5)/(m+0.5) − 0.5`, which works out to **B ≥ 213** benign
samples. Until the benign corpus reaches that size (or the specific signals
in question are independently supported), `L5/validate_policy.py` stamps the
score `unsupported`, and no gate is permitted to arm. This is by design, not
a bug the project is embarrassed by: it is the same "measure before
claiming" discipline applied to the scoring layer's own confidence in
itself.

### Why not a naive weighted blend

The project's earlier proposal was `0.45·rules + 0.30·ml + 0.25·llm` — a
fixed linear blend of three heterogeneous signals with weights that were
never fit to anything. `policy.yaml`'s own header states plainly why this was
rejected: it sums incommensurable units (a rule count, a probability, an
LLM's self-reported confidence) with coefficients chosen by feel rather than
measurement, and it has no principled way to express "this evidence is
redundant with that evidence" or "this combination is a smoking gun
regardless of the additive total." The additive log-odds + computed weights +
gates design instead makes every number traceable to a measured rate, makes
redundancy an explicit discount rather than free extra credit, and makes the
strongest claims (gates) require *structurally distinct* corroborating
evidence rather than a high enough weighted sum of possibly-correlated
signals.

---

## 11. GenAI use & app-navigation integration

GenAI is used in exactly two places in this pipeline, and both are
explicitly **grounded, never trusted blindly** — the project's L4 discipline
(§9) extends to L2's newest component as well.

### L4: verified deobfuscation (recap)

Covered in full in §9. The short version: the model explains code and
proposes claims; every claim a decoder, parser, or search can mechanically
settle is settled that way before it is kept, and a claim that fails its
check is dropped and the drop is recorded. The model never votes on the
score (`decision-0004`).

### L2: the GenAI navigator

`L2/sandbox/genai_navigator.py` (`docs/plans/l2_genai_navigator_plan.md`) is
new this session and reverses an earlier decision (`decision-0010`, "no
GenAI in L2") specifically because that earlier call is diagnosed as the
reason payloads don't fire (§7): DroidBot's blind `dfs_greedy` exploration
reaches an app's UI but cannot *reason through* a multi-field login or
SUBMIT flow. `GenAINavigator` is a **perceive → reason → act** loop:

- **Perceive** — `adb shell uiautomator dump`, parsed by
  `parse_ui_elements()` into a compact list of interactable elements
  (`text`, `resource_id`, `class`, `content_desc`, `editable`, `clickable`,
  `password`, `bounds`), capped so the prompt stays small. `screen_hash()`
  fingerprints the current screen (excluding parse-order-derived fields) for
  cycle detection.
- **Reason** — one call to `L4.provider`'s `Provider` interface (OpenRouter,
  reusing L4's existing $0-cost provider abstraction rather than a new one),
  with a system prompt that instructs strict JSON output and — critically —
  that the model **names the kind of field**, never supplies a literal PII
  value itself (`"value": "mobile_number"`, not an actual phone number). The
  response is parsed with a bracket/string-aware scanner
  (`_extract_json_object`, mirroring the same technique used for Frida CLI
  output in §7) and never `eval`'d, since this is adversarial output —
  ultimately reflecting an attacker's own app strings back into the prompt.
- **Indian dummy-data generation** — `DummyDataGenerator` is a seeded,
  deterministic generator (so a re-run fills a re-validated field with the
  same value) producing full names from real Indian first/last name lists,
  10-digit mobile numbers, `name@oksbi`-style UPI ids, 16-digit card numbers,
  MPIN/ATM PIN, PAN, DOB, and Indian city/state/pincode addresses. Field
  matching (`value_for`) uses ordered regex rules so more specific patterns
  (MPIN, CVV, OTP) are checked before generic catch-alls (password → MPIN).
- **The OTP-hint bridge.** `DummyDataGenerator.otp()` reads the same
  `latest_injected_otp.txt` hint file the orchestrator's SMS-injection
  schedule writes (§7) — so a field the model identifies as an OTP field
  gets the value that is actually about to arrive (or just arrived) as a
  real `SMS_RECEIVED` broadcast, not a disconnected random guess. This is
  the same mechanism DroidBot's patched field-filler already used; the
  navigator reuses it rather than inventing a second one.
- **Act** — `input tap`/`input text`/`input keyevent`/`swipe` via adb,
  identical primitives to the rest of L2.
- **Graceful fallback.** `orchestrator.py::_start_genai_navigator()` returns
  `None` — never raises — if the import fails or the provider is
  unavailable/misconfigured, and the caller falls back to DroidBot exactly
  as before. A provider outage can never hard-fail a detonation; this
  contract is load-bearing and stated explicitly in the code.

**Why this is grounded, not blindly trusted:** the navigator only ever sees
UI *state* (element text/resource-id/class/bounds) and only ever generates
*synthetic* Indian dummy data — it never receives, sees, or handles a real
credential or real network content. Its output space is deliberately narrow
(one of six verbs, an element index, a field-kind string), so there is no
path by which a hallucinated claim about "what this app does" could leak
into evidence — the navigator drives UI, it does not report findings. It is
explicitly **navigation, not scoring**: `decision-0004` (LLM contributes
zero score points) is unaffected, and the plan document says so directly.
Every step is logged to `genai_nav.jsonl` for after-the-fact audit. 46 tests
cover perception XML parsing, defensive action parsing (including malformed
input), dummy-data field matching, the OTP-hint path, and the
provider-unavailable fallback; a live emulator smoke test is
skip-guarded. Live use needs `OPENROUTER_API_KEY` set.

---

## 12. Fixes this session, known gaps, and roadmap

### Fixes landed this session

| Area | Fix | Effect |
|---|---|---|
| L3 | Unified pipeline-extracted dataset (`unified_features.py`, corpus-derived vocabulary, `meaningful_tokens` relevance filter, `cap:*` capability aggregates) | Replaces LAMDA's fixed schema (0.4–1.8% density vs its 2.5%) with a self-consistent extractor; kills train/serve skew |
| L3 | Dataset analysis (`analyze_unified_dataset.py`) quantifying the source confound | 59.3% exact-duplicate vectors, 73.5% near-duplicates, PC2 separates label (0.978) and source (0.903) on nearly the same axis |
| L3 | Dedup + stratified 5-fold CV (`unified_cv.py`) | AUROC 0.9963 ± 0.0017 — stated as an upper bound, not a claimed result |
| L4 | Hybrid word + char n-gram retriever + identifier expansion (`retriever.py`) | Retrieval robust to renaming/obfuscation |
| L4 | Broadened `_try_decode` (base32, URL-safe/nested base64, gzip/zlib, gated ROT13) | Fewer false drops of correct decodings |
| L4 | `dex_symbols` haystack (`deobfuscate.py`, wired into `verify.py`) | `renamed`/`api_calls` claims not dropped when jadx fails to decompile a class |
| L2 | GenAI navigator (`genai_navigator.py`) | Perceive→reason→act loop targeting the payload-triggering gap; graceful fallback to DroidBot |

Verification: all 44 L4 tests pass; full suite 393 passed / 1 skipped / 1
pre-existing fail; 46 new L2 GenAI navigator tests. A 15-app pipeline
dry-run this session ran every stage to `rc=0` with zero failures: benign
apps (notely/pennywise/proton) scored 17/20/20 (Informational); duckassist
scored 32 (Low); malware (krep_banking, cicmaldroid samples) scored 73–81
(High) with one Critical at 99; newer F-Droid apks (newpipe, freeproxy,
smsecure) ran clean. One miss: sample `79866c17` (a banking-family sample)
scored only 32 (Low) with 0 malware-category findings and an L3 probability
of 0.17 — flagged, not hidden.

All session work is snapshotted on git branch
`session-2026-08-25-l3l2l4`; the baseline `protoworkingv1` (commit
`0e1500e`) is untouched. The L4 fixes specifically are commit `0dac60c`.

### Known gaps

- **Emulator boot flakiness (T14).** The original `sentinel` AVD
  core-dumped on boot; `sentinel30` replaced it and boots reliably in the
  reliability-log runs, but this session's own detonation attempt hung —
  the underlying flakiness is not fully resolved, only worked around.
- **Source confound needs a benign-banking hard-negative panel.** Both the
  L3 unified dataset and the L1 YARA rule measurements share the same root
  gap (T27): F-Droid has zero commercial banking apps, 5 accessibility apps,
  and 79 SMS-permission apps repo-wide. Every accuracy number computed
  against this benign set — L3's AUROC, YARA rule benign-fire rates, L5's
  weight arithmetic — is an upper bound on real-world performance until a
  dedicated benign-banking panel exists to test against.
- **L3→L5 wiring.** `l3` is not yet batch-populated on corpus spines
  (`tools/corpus_run.py`/`run.py` do not currently call it), and
  `L5/policy.yaml`'s `ml.enabled` stays `false` until that measured step
  happens — the unified model exists and trains cleanly, but is not yet
  live in scoring.
- **One detection miss** in this session's dry run (`79866c17`, above) —
  a banking-family sample the pipeline scored Low.
- **18 dead YARA rules** (of 51) fire on nothing in the current corpus.
  All 18 pass the T25 self-match test, so they are not broken — the
  corpus lacks the co-located vocabulary they look for. The stated fix path
  is to mine real per-class co-occurrence from the corpus and rewrite each
  condition, the same process that produced the 8 rules in
  `apk_bfsi_primitives.yar` that took malware-category detection from 8% to
  37%.
- **B ≥ 213.** Until the benign corpus reaches roughly 213 samples (the
  closed-form requirement derived in T24) — or the specific negative-weight
  signals are independently re-measured — L5 scores stay stamped
  `unsupported` and no gate is permitted to arm above its additive floor.

### Roadmap (in dependency order)

1. Grow the benign corpus past B ≥ 213 (and, separately, build the
   benign-banking hard-negative panel — a different corpus-composition
   problem from just "more F-Droid apps").
2. Re-run A4 (`tools/rule_firing_report.py`) once B is large enough, confirm
   weight signs flip correctly, and let `L5/validate_policy.py` arm gates.
3. Wire `l3` into the corpus runner and flip `ml.enabled` once the benign
   panel gives a trustworthy false-positive measurement.
4. Chase the emulator boot flakiness enough to get a live GenAI-navigator
   run against the SBI sample, and confirm (or refute) that it closes the
   payload-triggering gap — the plan's own stated success metric is a richer
   `frida_hooks.jsonl` / non-empty `network_evidence.json` versus the
   `dfs_greedy` baseline.
5. Revive the 18 dead YARA rules via mined per-class co-occurrence, the same
   process that produced the BFSI primitives rule file.
6. Investigate the one detection miss from this session's dry run.
