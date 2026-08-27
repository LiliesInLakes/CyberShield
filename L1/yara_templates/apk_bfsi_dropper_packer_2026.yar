/*
    Dropper / commercial-packer signatures — authored 2026-08-27 against five
    Bank-of-India-impersonating samples found in testing_apps/unknown/. These
    are STRUCTURAL rules (scope="apk", container/central-directory), not
    behavioural per-class rules: they key on how the payload is *hidden inside
    the package*, which the existing behavioural rules cannot see.

    WHY THIS FILE EXISTS
    --------------------
    The five samples produced findings=1 (just the structure check) on four of
    five — the existing dropper coverage missed them entirely. Root cause,
    measured on the actual files:
      - `APK_Anomalous_Multiple_DEX_Files` only knows the standard multidex
        names (classes2.dex, classes3.dex). These samples hide the second-stage
        dex under assets/ with a random name (`assets/raw/ddb0e2.dex`,
        `assets/ScKit_shield_v1.dex`) — structurally invisible to that rule.
      - `Android_Dropper_Encrypted_Payload_Stage1` caps the file size at ten
        megabytes (these run 2.4–37 MB) and requires a PNG/JPEG-disguised
        header these droppers don't use — their payload sits in dozens of
        random-named .dat/.bin/.cfg blobs instead.
      - There was no rule at all for commercial Android packers/protectors
        (ScKit/SecShell, np_protect, Jiagu, DexHelper, …), which two samples
        use to wrap their payload.

    DISCIPLINE (measured, not asserted — T2/T28)
    --------------------------------------------
    Every rule below was measured against a benign panel BEFORE being written:
      - asset-hidden secondary dex:   0 / 80  benign apps
      - commercial packer signatures: 0 / 80  benign apps
      - >=12 random encrypted blobs:   0 / 120 benign apps (raw-byte count;
        malware samples counted 30 and 40, benign max 0 — wide margin)
    Benign panel = a random sample of the F-Droid corpus plus testing_apps/
    good_apps. These are container-structure signatures with near-zero
    generality, not broad behaviour detectors; any weight derived from them
    stays `unsupported` until the full benign corpus re-run prices them (I14).
*/

rule Android_Dropper_Asset_Hidden_Dex
{
    meta:
        description = "A secondary DEX hidden under assets/ with a non-standard name — a dropper staging its next stage where the standard multidex check (classes2.dex) cannot see it. Measured on 'Bank Of India(1)' (assets/raw/ddb0e2.dex) and 'Bank Of India' (assets/ScKit_shield_v1.dex)."
        severity = "High"
        category = "native_payload"
        scope = "apk"
        author = "Agent-Sentinel"
        date = "2026-08-27"
        reference = "measured: 0/80 benign, fires on 2/5 BOI-impersonator samples"
    strings:
        // A .dex anywhere under assets/, at any nesting depth. Deliberately
        // excludes a root classes*.dex (legit multidex) — the "assets/" anchor
        // is the whole point: legitimate secondary dex lives at the APK root,
        // not buried in assets under a random name.
        $asset_dex = /assets\/[A-Za-z0-9_\/.-]{0,60}\.dex/ ascii
    condition:
        uint32be(0) == 0x504B0304
        and $asset_dex
}

rule Android_Commercial_Packer_Protector
{
    meta:
        description = "Commercial Android packer/protector artifacts (ScKit/SecShell, np_protect, Jiagu, DexHelper, mobisec, Bangcle) — a legitimate bank ships an unpacked app; a packer wrapping an app that impersonates a bank is a strong repackaging/evasion signal. Measured on 'Bank Of India' (ScKit_shield_v1 + libnp_protect_res)."
        severity = "High"
        category = "packing_obfuscation"
        scope = "apk"
        author = "Agent-Sentinel"
        date = "2026-08-27"
        reference = "measured: 0/80 benign, fires on the ScKit-packed BOI-impersonator"
    strings:
        // ScKit / SecShell (the packer in the sample)
        $sckit1 = "ScKit_shield" ascii
        $sckit2 = "libScKitShieldV1" ascii
        $np     = "np_protect" ascii
        // Other well-documented commercial Android protectors (real product
        // library names; included in the 0/80-benign measurement)
        $jiagu   = "libjiagu" ascii            // Qihoo 360 Jiagu
        $dexhelp = "libDexHelper" ascii         // 360 DexHelper
        $mobisec = "libmobisec" ascii           // Ali/mobisec
        $secexe  = "libsecexe" ascii            // Bangcle
        $secshell = "libSecShell" ascii         // Bangcle SecShell
    condition:
        uint32be(0) == 0x504B0304
        and any of them
}

rule Android_Dropper_Bulk_Encrypted_Assets
{
    meta:
        description = "Many random-named opaque asset blobs (.dat/.bin/.cfg) — the encrypted-payload staging pattern of an assets-based dropper, where the real second stage is split across dozens of generated-name files. Measured on 'Bank of india' (com.apkshield.installer, 40 blobs) and 'Bank Of India(1)' (30 blobs)."
        severity = "High"
        category = "native_payload"
        scope = "apk"
        author = "Agent-Sentinel"
        date = "2026-08-27"
        reference = "measured raw-byte count: malware 30-40, benign max 0 (n=120); threshold 12 leaves wide margin"
    strings:
        // assets file whose stem contains at least one digit (i.e. generated,
        // not a human-named resource) and an opaque binary extension.
        $blob = /assets\/[a-z0-9]{0,14}[0-9][a-z0-9]{0,14}\.(dat|bin|cfg)/ ascii
    condition:
        uint32be(0) == 0x504B0304
        and #blob >= 12
}
