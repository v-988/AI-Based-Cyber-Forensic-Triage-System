# sandbox_analyze.py
import sys
import os

# ── Suspicious string patterns ──────────────────────────────────────
MALWARE_SIGNATURES = [
    (b"eval(",           "MALICIOUS: eval() injection detected"),
    (b"exec(",           "MALICIOUS: exec() injection detected"),
    (b"<script",         "MALICIOUS: Embedded script tag found"),
    (b"document.cookie", "MALICIOUS: Cookie stealing pattern"),
]

SUSPICIOUS_SIGNATURES = [
    (b"base64",          "SUSPICIOUS: Base64 encoding (possible obfuscation)"),
    (b"powershell",      "SUSPICIOUS: PowerShell command found"),
    (b"cmd.exe",         "SUSPICIOUS: CMD shell reference found"),
    (b"wget ",           "SUSPICIOUS: Network download command (wget)"),
    (b"curl ",           "SUSPICIOUS: Network download command (curl)"),
    (b"nc -e",           "SUSPICIOUS: Netcat reverse shell pattern"),
    (b"/etc/passwd",     "SUSPICIOUS: Unix credential file reference"),
    (b"DROP TABLE",      "SUSPICIOUS: SQL Injection pattern"),
    (b"UNION SELECT",    "SUSPICIOUS: SQL Injection pattern"),
    (b"os.system(",      "SUSPICIOUS: OS command execution"),
    (b"subprocess",      "SUSPICIOUS: Subprocess execution pattern"),
    (b"CreateRemoteThread", "SUSPICIOUS: Windows process injection API"),
    (b"VirtualAlloc",    "SUSPICIOUS: Memory allocation (shellcode pattern)"),
]

# ── PE Header check (detects Windows EXE/DLL) ────────────────────────
def check_pe_header(content: bytes) -> str | None:
    if content[:2] == b"MZ":
        return "SUSPICIOUS: Windows PE Executable header detected (MZ magic bytes)"
    return None

# ── ELF Header check (detects Linux binary) ─────────────────────────
def check_elf_header(content: bytes) -> str | None:
    if content[:4] == b"\x7fELF":
        return "SUSPICIOUS: Linux ELF binary detected"
    return None

# ── Entropy check (high entropy = possibly encrypted/packed) ─────────
def check_entropy(content: bytes) -> str | None:
    if len(content) == 0:
        return None
    import math
    freq = [0] * 256
    for byte in content:
        freq[byte] += 1
    entropy = -sum(
        (f / len(content)) * math.log2(f / len(content))
        for f in freq if f > 0
    )
    if entropy > 7.2:
        return f"SUSPICIOUS: High entropy ({entropy:.2f}/8.0) — possibly packed or encrypted"
    return None

def analyze(file_path: str) -> str:
    findings = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # 1. PE / ELF binary headers
        pe  = check_pe_header(content)
        elf = check_elf_header(content)
        if pe:  findings.append(pe)
        if elf: findings.append(elf)

        # 2. Entropy check
        ent = check_entropy(content)
        if ent: findings.append(ent)

        # 3. Malware signatures (critical)
        content_lower = content.lower()
        for pattern, message in MALWARE_SIGNATURES:
            if pattern.lower() in content_lower:
                findings.append(message)

        # 4. Suspicious signatures (warnings)
        for pattern, message in SUSPICIOUS_SIGNATURES:
            if pattern.lower() in content_lower:
                findings.append(message)

        if findings:
            return " | ".join(findings)
        return "NORMAL"

    except PermissionError:
        return "ANALYSIS_FAILED: Permission denied"
    except Exception as e:
        return f"ANALYSIS_FAILED: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("ANALYSIS_FAILED: No file path provided")
    else:
        print(analyze(sys.argv[1]))
