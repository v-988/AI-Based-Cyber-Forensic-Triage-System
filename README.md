# 🛡️ Cyber Forensic Triage System — IsoScan

> **An isolated sandbox engine that scans uploaded files through a 6-layer malware detection pipeline. Malicious files are quarantined inside the sandbox. Clean files are safely returned to the user. Your system is never touched.**

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-red?style=flat-square&logo=streamlit)
![ClamAV](https://img.shields.io/badge/ClamAV-Integrated-green?style=flat-square)
![YARA](https://img.shields.io/badge/YARA-Rules--Engine-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 📌 What Is This?

**IsoScan** is a cyber forensic triage tool built entirely in Python and Streamlit. When a user uploads any file, it is intercepted and analyzed inside an isolated directory sandbox before it ever reaches the real filesystem. The system runs the file through **6 independent detection layers**, aggregates a threat score, and delivers a verdict:

| Verdict | Score Range | Action |
|---|---|---|
| ✅ CLEAN | 0 – 39 | Moved to `sandbox_safe/` — user can download |
| ⚠️ SUSPICIOUS | 40 – 79 | Moved to `sandbox_quarantine/` — review required |
| ☣️ MALICIOUS | 80 – 100 | Moved to `sandbox_quarantine/` — permanently locked |

The file **never executes**. It is only read byte-by-byte and pattern-matched. Even the most destructive ransomware or trojan is completely inert inside the sandbox.

---

🏗️ System Architecture 
<p align="center">
<img src="https://github.com/user-attachments/assets/910567aa-74c8-4f1b-a7af-41d86cbf6cae" width="400">
</p>

> The full end-to-end pipeline from file ingestion to verdict output.

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│   User Upload │ REST API (/scan) │ CLI Scanner │ Batch Watch    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │    File Ingestion       │
              │  UUID rename · size     │
              │  check · temp save      │
              └────────────┬────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│              ISOLATED SANDBOX — 6-LAYER ANALYSIS                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Layer 1 · File Validation                               │    │
│  │ Extension check · MIME type · size · polyglot detection │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │ Layer 2 · Entropy Analysis                              │    │
│  │ Shannon entropy · chunk scan · obfuscation detection    │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │ Layer 3 · YARA Rules Scan                               │    │
│  │ Ransomware · trojans · shellcode · macros · miners      │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │ Layer 4 · PE / EXE Analysis                             │    │
│  │ Packer detect · section entropy · Win32 API imports     │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │ Layer 5 · String Heuristics                             │    │
│  │ Ransom text · shell commands · C2 IPs · cred theft      │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │ Layer 6 · ClamAV Antivirus                              │    │
│  │ 2M+ virus signatures · daemon + CLI fallback            │    │
│  └──────────────────────────┬──────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │      Verdict Engine          │
              │  Aggregate score · thresholds│
              │  JSON report generated       │
              └──────┬───────────┬───────────┘
                     │           │           │
           ┌─────────▼─┐   ┌────▼────┐  ┌──▼──────┐
           │ MALICIOUS  │   │SUSPICIOUS│  │  CLEAN  │
           │quarantine/ │   │quarantine│  │  safe/  │
           │  locked    │   │  review  │  │download │
           └────────────┘   └──────────┘  └─────────┘
```

---

## 🔬 Detection Layers — Deep Dive

### Layer 1 — File Validation
Performs surface-level inspection before reading any file content.

- Checks file extension against a known-dangerous list (`.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.vbs`, `.ps1`)
- Reads the file's **magic bytes** (first 4–8 bytes) and compares against declared extension
- Detects **polyglot file attacks** — e.g., a `.jpg` file whose first bytes say `MZ` (Windows executable)
- Flags oversized files and empty files

**Score contribution:** +25 (suspicious ext) to +50 (dangerous ext) / +45 (MIME mismatch)

---

### Layer 2 — Entropy Analysis
Uses **Shannon Entropy** — a mathematical measure of randomness in the file's byte distribution.

- A normal text file has entropy ~3.5 (predictable, low randomness)
- A ZIP archive has entropy ~7.5 (compressed, high randomness)
- A **packed or encrypted malware** has entropy ~7.8–8.0 (near-maximum randomness)
- Performs chunk-level entropy scanning to detect hidden encrypted payloads within otherwise normal-looking files

**Score contribution:** +12 (elevated) to +40 (very high entropy >7.0)

---

### Layer 3 — YARA Rules
YARA is the industry standard for malware pattern matching, used by threat intelligence teams at major security firms. IsoScan ships with **10 rule categories**:

| Rule | Detects |
|------|---------|
| `Ransomware_Generic` | Payment demands, encryption messages, WannaCry, CryptoLocker |
| `Suspicious_PowerShell` | Encoded commands, `Invoke-Expression`, `DownloadString` |
| `Shellcode_Pattern` | NOP sleds, common exploit prologues, Metasploit signatures |
| `Trojan_Backdoor` | Reverse shells, registry persistence, remote thread injection |
| `Suspicious_Script_Execution` | `eval(base64)`, `WScript.Shell`, `CreateObject` |
| `PDF_Exploit` | JavaScript in PDFs, `/Launch` + `/EmbeddedFile` |
| `Suspicious_Macro` | `AutoOpen`, `Document_Open`, shell execution macros |
| `Keylogger_Pattern` | `SetWindowsHookEx`, `GetAsyncKeyState`, keyboard hooks |
| `Crypto_Miner` | `stratum+tcp://`, XMRig, NiceHash strings |
| `Suspicious_Network_Activity` | Tor `.onion` refs, Pastebin C2, encoded downloads |

**Score contribution:** +15 (LOW) → +55 (HIGH) → +80 (CRITICAL)

---

### Layer 4 — PE / EXE Analysis
Windows Portable Executable (PE) files are dissected using the `pefile` library.

- Detects **packers**: UPX, ASPack, Petite — tools malware uses to hide itself from antivirus
- Scans PE **sections** for anomalous entropy (encrypted payloads embedded inside executables)
- Checks **Win32 API imports** for dangerous combinations:
  - `WriteProcessMemory` + `CreateRemoteThread` → Process injection (rootkit behavior)
  - `GetAsyncKeyState` → Keylogger
  - `URLDownloadToFile` → Downloads secondary payload
  - `RegSetValueEx` → Registry persistence

**Score contribution:** +20 (PE detected) to +70 (packer + dangerous APIs)

---

### Layer 5 — String Heuristics
Every printable string is extracted from the file and cross-referenced against threat patterns.

- **Ransomware phrases**: "your files have been encrypted", "vssadmin delete shadows", `bcdedit /set recoveryenabled no`
- **Shell execution**: reverse shell patterns, firewall disabling commands, hidden user creation
- **Credential theft**: `mimikatz`, `hashdump`, `/etc/shadow`, `id_rsa`
- **C2 infrastructure**: clusters of external IP addresses, `.onion` references, Pastebin URLs
- **Destruction commands**: `rm -rf /`, `format c:`, `wbadmin delete catalog`

**Score contribution:** +10–20 per keyword cluster found

---

### Layer 6 — ClamAV Antivirus
ClamAV's signature database contains **2 million+ known malware definitions**, updated daily.

- Attempts **clamd daemon** connection first (fastest)
- Falls back to **`clamscan` CLI** if daemon is unavailable
- Gracefully degrades: if ClamAV is not installed, the other 5 layers still provide strong coverage
- Detects known viruses, trojans, worms, and PUAs by exact binary fingerprint

**Score contribution:** +100 on any detection (auto-flags as MALICIOUS)

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip
- (Optional) ClamAV for Layer 6

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/v-988/isoscan.git
cd isoscan

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Copy YARA rules to the rules folder
mkdir rules
copy yara_rules.yar rules\    # Windows
cp yara_rules.yar rules/      # macOS / Linux

# 4. Run the app
streamlit run app.py
```

Open your browser at **http://localhost:8501**

### Install ClamAV (Windows)
```
1. Download from https://www.clamav.net/downloads
2. Run the .msi installer
3. Open Command Prompt as Administrator:
   cd "C:\Program Files\ClamAV"
   freshclam.exe
```

### Install ClamAV (Linux)
```bash
sudo apt install clamav clamav-daemon -y
sudo freshclam
sudo systemctl start clamav-daemon
```

---

## 📁 Project Structure

```
isoscan/
│
├── app.py                  ← Streamlit UI + all 6 scan layers (single file)
├── yara_rules.yar          ← YARA malware detection rules
├── requirements.txt        ← Python dependencies
│
├── rules/
│   └── yara_rules.yar      ← YARA rules loaded from here at runtime
│
└── (auto-created at runtime)
    ├── sandbox_uploads/    ← Files land here temporarily during scan
    ├── sandbox_quarantine/ ← MALICIOUS + SUSPICIOUS files locked here
    ├── sandbox_safe/       ← CLEAN files stored here (downloadable)
    └── sandbox_reports/    ← JSON report saved for every scan
```

---

## 🖥️ Dashboard Features

| Feature | Description |
|---|---|
| Live scan progress | 6-layer animated progress bar shows which layer is running |
| Verdict banner | Color-coded CLEAN / SUSPICIOUS / MALICIOUS result |
| Threat score meter | 0–100 visual score bar |
| Layer breakdown | Per-layer score, PASS/WARN/FAIL badge, findings list |
| YARA match viewer | Expandable list of triggered rules with severity |
| File hashes | MD5, SHA1, SHA256 for threat intelligence cross-referencing |
| Safe download | Download button appears only for CLEAN files |
| Scan history | Last 20 scans with verdict, score, and timestamp |
| Sidebar stats | Live counters: total scanned, clean, threats, suspicious |

---
<h2 align="center">📊 Dashboard Preview</h2>
<p align="center">
  <img width="700" alt="ISOSCAN Dashboard" src="https://github.com/user-attachments/assets/4bdfcc16-3fa6-46b9-a02f-981ad4fcf567" />
</p>
---

## 📊 Scoring Reference

```
┌─────────────────────────────────────────────────────┐
│ SCORE     VERDICT      ACTION                        │
├─────────────────────────────────────────────────────┤
│  0 – 39   CLEAN        → sandbox_safe/  (download)  │
│ 40 – 79   SUSPICIOUS   → sandbox_quarantine/         │
│ 80 – 100  MALICIOUS    → sandbox_quarantine/         │
└─────────────────────────────────────────────────────┘

Score accumulates per layer:
  Layer 1 (File Validation)    max +50
  Layer 2 (Entropy)            max +40
  Layer 3 (YARA)               max +80
  Layer 4 (PE Analysis)        max +70
  Layer 5 (String Heuristics)  max +60
  Layer 6 (ClamAV)             max +100
```

---

## 🔒 Security Design Principles

**1. Files never execute.** The sandbox only reads raw bytes — no process spawning, no script interpretation, no dynamic analysis.

**2. Quarantine is one-way.** Files moved to `sandbox_quarantine/` cannot be served via any endpoint.

**3. Download is gated on verdict.** The download API checks the JSON report verdict before serving any file — a tampered report will not bypass this.

**4. UUID prefixing.** Every uploaded file is renamed with a UUID prefix before saving — no two files can overwrite each other, and original filenames cannot be used to path-traverse.

**5. Graceful degradation.** If ClamAV is not installed, the system still runs 5 layers. If YARA is missing, fallback keyword scanning activates. No single dependency failure breaks the system.

---

## 🧰 Tech Stack

| Component | Technology |
|---|---|
| Frontend / UI | Streamlit |
| Malware pattern engine | YARA (`yara-python`) |
| PE / EXE analysis | `pefile` |
| Antivirus engine | ClamAV (`clamd` / `clamscan`) |
| File type detection | Magic bytes + `python-magic` |
| Entropy calculation | Shannon formula (pure Python) |
| String analysis | `re` module + keyword matching |
| Report storage | JSON (local filesystem) |
| Language | Python 3.10+ |

---

## 🗺️ Roadmap

- [ ] VirusTotal API integration (Layer 7 — cross-check 70+ AV engines online)
- [ ] Behavioral sandbox (run file in isolated VM, watch what it does)
- [ ] Email attachment scanner integration
- [ ] MITRE ATT&CK framework tagging for detected techniques
- [ ] REST API mode with authentication
- [ ] Docker deployment with full container isolation
- [ ] PDF report generation per scan

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/new-layer`)
3. Commit your changes (`git commit -m 'Add Layer 7: VirusTotal integration'`)
4. Push to the branch (`git push origin feature/new-layer`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Vishal P**
- GitHub: [@v-988](https://github.com/v-988)
- LinkedIn: [Vishal Purushothaman](https://www.linkedin.com/in/vishal-purushothaman-51a66628b/)

---

> *"A file that never runs can never harm you."*
> Built with Python · Streamlit · YARA · ClamAV
