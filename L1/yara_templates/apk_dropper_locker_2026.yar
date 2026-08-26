/*
    Dropper + screen-locker signatures — authored 2026-08-26 against the XBot
    banking trojan, whose behaviour was observed both statically (this file) and
    dynamically (an L2 detonation captured its on-launch C2 beacon
    `POST /request.php {"action":"get_script"}` fetching a second stage).

    WHY THIS FILE EXISTS
    --------------------
    `apk_ransomware.yar` fires on 0/649 known malware (B29) on a corpus that
    contains screen-lockers. XBot is a concrete miss. The root cause, measured
    here: XBot is **modular** — it splits one behaviour across classes. Its
    device-admin control, remote script fetch and C2 endpoints live in three
    separate classes (RunService, packets/GetScript, Consts) under each embedded
    package. A behavioural rule that requires the primitives to co-locate
    in one class (the T2/T21 discipline that keeps false positives down) therefore
    cannot fire — `lockNow` is not even present; XBot locks via the admin policy a
    different way. So these two rules are deliberately **family signatures** keyed
    on strings that DO co-locate in one class, not behavioural-primitive rules.

    DISCIPLINE
    ----------
    - Strings are substrings of both the dex representation and jadx output. (T22)
    - Conditions require co-location in ONE class buffer (verified against the
      scanner's own `_dex_class_buffers`): `RunService` carries
      DevicePolicyManager + bootScript + request.php together; `Consts` carries
      locker.php + http://. (T2/T21)
    - Two strings minimum, never one. (T23)

    🔴 HONESTY: validated to FIRE on XBot (4 repackaged variants: com.xbot,
    org.luckybird, org.merry, org.verywell) and to MISS a benign F-Droid batch at
    authoring time. NOT yet measured against the full benign corpus — any weight
    derived from these stays unsupported until that runs (I14). These are precise
    family signatures (low generality, low false-positive), not broad behaviour
    detectors; the general lesson (modular malware defeats per-class conjunction)
    belongs in the log, not in a looser rule that would reintroduce T2.
*/

rule Android_BFSI_XBot_Dropper_Service
{
    meta:
        description = "Background service class co-locating device-admin control, a remote script fetch, and an HTTP C2 endpoint — the XBot-family banking dropper/locker service"
        severity = "Critical"
        category = "native_payload"
        scope = "both"
        reference = "measured: */core/RunService co-locates DevicePolicyManager + bootScript + request.php"
    strings:
        $admin = "DevicePolicyManager"
        $script1 = "bootScript"
        $script2 = "get_script"
        $c2_1 = "request.php"
        $c2_2 = "locker.php"
    condition:
        $admin and 1 of ($script*) and 1 of ($c2*)
}

rule Android_BFSI_XBot_Locker_Endpoint
{
    meta:
        description = "Class builds an HTTP request to a `locker.php` C2 endpoint — the XBot-family remote screen-locker (ransom-lock) control channel"
        severity = "High"
        category = "ransomware"
        scope = "both"
        reference = "measured: */core/Consts co-locates locker.php + http://"
    strings:
        $locker = "locker.php"
        $url = "http://"
    condition:
        all of them
}
