# APK Sentinel — Setup Guide

## Prerequisites

- Windows 10/11 (the pipeline uses Windows batch scripts)
- 8 GB+ RAM (16 GB recommended for Ghidra)
- 4 GB free disk for tools + dependencies

## 1. Python Environment

```powershell
python -m venv env
.\env\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 2. JDK

Two JDKs needed:

| JDK | Version | Used by | Install |
|-----|---------|---------|---------|
| JDK 17 | 17.0.19+ | jadx | `scoop install temurin17-jdk` or manual download |
| JDK 21 | 21.0.11+ | Ghidra | `scoop install temurin21-jdk` or manual download |

Manual alternative — extract to `tools/`:
```powershell
# JDK 17 → tools/jdk17/jdk-17.0.19+10/
# JDK 21 → scoop or C:\Users\<user>\scoop\apps\temurin21-jdk\current\
```

## 3. jadx (Headless)

```powershell
mkdir -Force tools/jadx
# Download jadx-1.5.6-all.jar from https://github.com/skylot/jadx/releases
# Place jar at: tools/jadx/lib/jadx-1.5.6-all.jar
```

On Windows, invoke the CLI class directly (NOT `-jar` — that opens GUI):
```powershell
java -cp tools/jadx/lib/jadx-1.5.6-all.jar jadx.cli.JadxCLI -j 4 -d out_dir app.apk
```

## 4. Ghidra (Headless)

```powershell
mkdir -Force tools/ghidra
# Download ghidra_12.1.2_PUBLIC from https://github.com/NationalSecurityAgency/ghidra/releases
# Extract to: tools/ghidra/ghidra_12.1.2_PUBLIC/
```

Set `JAVA_HOME` to JDK 21 before using Ghidra:
```powershell
$env:JAVA_HOME = "C:\Users\$env:USERNAME\scoop\apps\temurin21-jdk\current"
```

## 5. Verify Installation

```powershell
# Python + YARA
.\env\Scripts\python.exe -c "import yara; print('YARA OK')"

# jadx
java -cp tools/jadx/lib/jadx-1.5.6-all.jar jadx.cli.JadxCLI --version

# Ghidra
$env:JAVA_HOME = "C:\Users\$env:USERNAME\scoop\apps\temurin21-jdk\current"
tools\ghidra\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat -help
```

## 6. Run Pipeline

```powershell
# L0 — triage
.\env\Scripts\python.exe L0/ingest.py testing_apps/vuln/pivaa.apk

# L1 — static analysis (auto-routes engine by track)
.\env\Scripts\python.exe L1/l1.py testing_apps/vuln/pivaa.apk

# Full L0 + L1 with evidence update
.\env\Scripts\python.exe L0/ingest.py testing_apps/vuln/pivaa.apk
.\env\Scripts\python.exe L1/l1.py testing_apps/vuln/pivaa.apk
# Then update evidence.json l1.status = "complete" (manual or script)
```

## Directory Layout

```
BOI/
├── .gitignore
├── requirements.txt
├── setup.md
├── env/                  # Python venv (ignored)
├── tools/                # JDK, jadx, Ghidra (mostly ignored)
├── testing_apps/         # Test APKs (ignored)
├── L0/
│   ├── ingest.py         # L0 triage pipeline
│   └── artifacts/        # L0 evidence (ignored)
├── L1/
│   ├── l1.py             # L1 dispatcher
│   ├── schema.py         # Shared types
│   ├── engines/          # jadx, ghidra, combo, yara
│   ├── yara_templates/   # YARA rule files
│   └── artifacts/        # L1 analysis (ignored)
└── docs/                 # Session docs
```

## Known Quirks

- **jadx on Windows**: Must use `jadx.cli.JadxCLI` class, not `-jar`, or GUI pops up
- **Ghidra**: Requires JDK 21+. Set `JAVA_HOME` before calling analyzeHeadless.bat
- **First Ghidra run**: Slow (~30s startup + analysis time per .so file). Subsequent runs cached.
- **YARA on 24k+ file APK**: Batch size 500, sequential by default. Use `max_workers=4` for parallel.
