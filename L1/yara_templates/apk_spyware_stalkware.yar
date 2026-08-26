// =============================================================================
// APK Spyware & Stalkware YARA Rules
// Description: Detects surveillance, stalking, and espionage Android malware
// Author: Agent-Sentinel
// Date: 2026-07-19
// =============================================================================

rule Android_Spyware_Generic_GPS_Surveillance {
    meta:
        category = "data_exfiltration"
        scope = "both"
        description = "Detects generic Android spyware with GPS tracking and location surveillance"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Location APIs
        $loc1 = "LocationManager" ascii wide
        $loc2 = "requestLocationUpdates" ascii wide
        $loc3 = "GPS_PROVIDER" ascii wide
        $loc4 = "NETWORK_PROVIDER" ascii wide
        $loc5 = "FusedLocationProviderClient" ascii wide

        // Background service persistence
        $svc1 = "startForeground" ascii wide
        $svc2 = "FOREGROUND_SERVICE" ascii wide
        $svc3 = "JobScheduler" ascii wide
        $svc4 = "AlarmManager" ascii wide

        // Data exfiltration
        $exfil1 = "HttpURLConnection" ascii wide
        $exfil2 = "OutputStreamWriter" ascii wide
        $exfil3 = "multipart/form-data" ascii wide

        // Stealth indicators
        $stealth1 = "hideAppIcon" ascii wide
        $stealth2 = "setComponentEnabledSetting" ascii wide
        $stealth3 = "COMPONENT_ENABLED_STATE_DISABLED" ascii wide

    // Was: 3 of ($loc*) AND 2 of ($svc*) AND 2 of ($exfil*) AND 1 of ($stealth*)
    // — eight co-located tokens, 0/640 malware (B29). Reduced to two groups:
    // location capture plus persistence/egress, AND the stealth marker, which is
    // the token benign location apps do not carry (an app that hides its own
    // launcher icon is making a claim about intent).
    condition:
        filesize < 12MB
        and uint32be(0) == 0x504B0304
        and (2 of ($loc*, $svc*, $exfil*))
        and (1 of ($stealth*))
}


rule Android_Spyware_SMS_Call_Log_Harvester {
    meta:
        category = "sms_intercept"
        scope = "both"
        description = "Detects spyware harvesting SMS, call logs, and contact data"
        author = "Agent-Sentinel"
        severity = "High"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // SMS harvesting
        $sms1 = "content://sms/" ascii wide
        $sms2 = "content://sms/inbox" ascii wide
        $sms3 = "content://sms/sent" ascii wide

        // Call log harvesting
        $call1 = "content://call_log/calls" ascii wide
        $call2 = "CallLog.Calls" ascii wide
        // $call3 = "NUMBER" and $call4 = "DURATION" removed — bare provider
        // column names, present in any dialer or call-log UI class.

        // Contact harvesting
        $contact1 = "content://contacts/people" ascii wide
        $contact2 = "ContactsContract.Contacts" ascii wide
        // $contact3 = "DISPLAY_NAME" removed for the same reason.

        // Exfiltration patterns
        $exfil1 = "JSONObject" ascii wide
        $exfil2 = "JSONArray" ascii wide
        $exfil3 = "Base64.encodeToString" ascii wide

        // Hex: content provider URI patterns

    // Was: 2 of ($sms*) AND 2 of ($call*) AND 2 of ($contact*) AND 2 of ($exfil*)
    // — eight co-located tokens across four groups, 0/640 malware (B29). A real
    // harvester puts one provider URI and a serializer in the same class and
    // splits the rest across helpers. Reduced to two groups: any content-provider
    // read of personal data, plus a serialization/exfil marker. The bare column
    // names ("NUMBER", "DURATION", "DISPLAY_NAME") are kept out of the first
    // group — they are ordinary in any contacts or dialer UI class.
    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (2 of ($sms*, $call1, $call2, $contact1, $contact2))
        and (1 of ($exfil*))
}


rule Android_Spyware_Microphone_Camera_Access {
    meta:
        category = "data_exfiltration"
        scope = "both"
        description = "Detects spyware accessing microphone and camera for surveillance"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Camera access
        $cam1 = "CameraManager" ascii wide
        $cam2 = "CameraDevice" ascii wide
        $cam3 = "CaptureRequest" ascii wide
        $cam4 = "ImageReader" ascii wide
        $cam5 = "MediaRecorder" ascii wide

        // Microphone access
        $mic1 = "MediaRecorder.AudioSource.MIC" ascii wide
        $mic2 = "AudioRecord" ascii wide
        $mic3 = "RECORD_AUDIO" ascii wide

        // Screenshot / screen recording
        $screen1 = "MediaProjection" ascii wide
        $screen2 = "createVirtualDisplay" ascii wide
        $screen3 = "MediaProjectionManager" ascii wide

        // File storage of captured media
        $store1 = ".mp4" ascii wide
        $store2 = ".3gp" ascii wide
        $store3 = "Environment.DIRECTORY_PICTURES" ascii wide

        // Hex: MP4 file header (ftyp)

    condition:
        filesize < 20MB
        and uint32be(0) == 0x504B0304
        and (
            (2 of ($cam*) and 2 of ($mic*))
            or (2 of ($screen*) and 1 of ($store*))
        )
}


rule Android_Spyware_Keylogger_Credential_Theft {
    meta:
        category = "data_exfiltration"
        scope = "both"
        description = "Detects keylogger functionality and credential theft in Android apps"
        author = "Agent-Sentinel"
        severity = "Critical"
        platform = "Android"
        date = "2026-07-19"

    strings:
        // Accessibility-based keylogging
        $kl1 = "AccessibilityEvent" ascii wide
        $kl2 = "TYPE_VIEW_TEXT_CHANGED" ascii wide
        $kl3 = "getBeforeText" ascii wide
        $kl4 = "getSource" ascii wide

        // Input method monitoring

        // Clipboard monitoring
        $clip1 = "ClipboardManager" ascii wide
        $clip2 = "addPrimaryClipChangedListener" ascii wide
        $clip3 = "getPrimaryClip" ascii wide

        // Credential targeting
        $cred1 = "password" ascii wide
        $cred2 = "username" ascii wide
        $cred3 = "login" ascii wide
        $cred4 = "PIN" ascii wide

        // Hex: AccessibilityNodeInfo pattern

    condition:
        filesize < 10MB
        and uint32be(0) == 0x504B0304
        and (3 of ($kl*))
        and (2 of ($clip*))
        and (2 of ($cred*))
}
