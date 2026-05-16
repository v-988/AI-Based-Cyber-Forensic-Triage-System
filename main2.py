'''import os
import re
import hashlib
import stat
import json
import csv
import io
import platform
import datetime
import tempfile
import zipfile
import streamlit as st
import pandas as pd
from pathlib import Path

# ─────────────────────────────────────────────
#  CONSTANTS & CONFIG
# ─────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    "executables":   [".exe", ".bat", ".cmd", ".com", ".scr", ".pif"],
    "scripts":       [".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta"],
    "malware_like":  [".dll", ".sys", ".drv", ".ocx"],
    "archives":      [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"],
    "documents":     [".doc", ".docm", ".xlsm", ".pptm"],
    "misc":          [".torrent", ".onion", ".lnk", ".reg"],
}

ALL_SUSPICIOUS_EXTS = {
    ext for exts in SUSPICIOUS_EXTENSIONS.values() for ext in exts
}

KEYWORDS = {
    "credentials":   ["password", "passwd", "pwd", "username", "login", "credential", "secret", "token", "api_key", "apikey"],
    "financial":     ["bank", "credit card", "debit", "account number", "iban", "routing", "bitcoin", "ethereum", "crypto", "wallet", "transaction"],
    "illegal":       ["exploit", "malware", "ransomware", "phishing", "hack", "crack", "keygen", "bypass", "payload", "shellcode", "rootkit"],
    "personal":      ["ssn", "social security", "passport", "aadhaar", "pan card", "dob", "date of birth", "phone number"],
}

ALL_KEYWORDS = {kw for kws in KEYWORDS.values() for kw in kws}

READABLE_EXTENSIONS = {
    ".txt", ".csv", ".log", ".xml", ".json", ".html",
    ".htm", ".ini", ".cfg", ".conf", ".yaml", ".yml",
    ".py", ".js", ".ts", ".sh", ".bat", ".ps1",
    ".md", ".rst", ".env", ".sql",
}

LARGE_FILE_THRESHOLD_MB = 100   # files > 100 MB flagged as large
MAX_KEYWORD_READ_BYTES   = 1_000_000  # read first 1 MB for keyword scan

# ─────────────────────────────────────────────
#  CORE ANALYSIS ENGINE
# ─────────────────────────────────────────────

def compute_sha256(filepath: str) -> str:
    """Generate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return "HASH_ERROR"


def is_hidden(filepath: str) -> bool:
    """Detect hidden files (cross-platform)."""
    name = os.path.basename(filepath)
    if name.startswith("."):
        return True
    if platform.system() == "Windows":
        try:
            attrs = os.stat(filepath).st_file_attributes
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass
    return False


def keyword_scan(filepath: str) -> dict:
    """Scan text content of a file for sensitive keywords."""
    ext = Path(filepath).suffix.lower()
    if ext not in READABLE_EXTENSIONS:
        return {}

    found = {}
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read(MAX_KEYWORD_READ_BYTES).lower()

        for category, keywords in KEYWORDS.items():
            hits = [kw for kw in keywords if kw in content]
            if hits:
                found[category] = hits
    except (PermissionError, OSError, UnicodeDecodeError):
        pass

    return found


def get_metadata(filepath: str) -> dict:
    """Extract file metadata (size, timestamps)."""
    try:
        stat_info = os.stat(filepath)
        size_bytes = stat_info.st_size
        created    = datetime.datetime.fromtimestamp(stat_info.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        modified   = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        accessed   = datetime.datetime.fromtimestamp(stat_info.st_atime).strftime("%Y-%m-%d %H:%M:%S")
        return {
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 3),
            "created":  created,
            "modified": modified,
            "accessed": accessed,
        }
    except (PermissionError, OSError):
        return {"size_bytes": 0, "size_mb": 0, "created": "N/A", "modified": "N/A", "accessed": "N/A"}


def risk_score(record: dict) -> int:
    """Calculate a risk score (0-100) for a file record."""
    score = 0
    if record["is_suspicious_ext"]:
        score += 35
    if record["is_hidden"]:
        score += 20
    if record["keyword_hits"]:
        score += min(len(record["keyword_hits"]) * 10, 30)
    if record["size_mb"] > LARGE_FILE_THRESHOLD_MB:
        score += 10
    if record["hash"] == "HASH_ERROR":
        score += 5
    return min(score, 100)


def risk_label(score: int) -> str:
    if score >= 70:  return "🔴 CRITICAL"
    if score >= 40:  return "🟠 HIGH"
    if score >= 20:  return "🟡 MEDIUM"
    return "🟢 LOW"


def analyze_path(root_path: str, progress_cb=None) -> list[dict]:
    """Walk a directory tree and analyse every file."""
    results = []
    all_files = []

    for dirpath, _, filenames in os.walk(root_path):
        for fname in filenames:
            all_files.append(os.path.join(dirpath, fname))

    total = len(all_files)

    for idx, filepath in enumerate(all_files):
        if progress_cb:
            progress_cb(idx + 1, total)

        ext      = Path(filepath).suffix.lower()
        metadata = get_metadata(filepath)
        kw_hits  = keyword_scan(filepath)
        hidden   = is_hidden(filepath)
        susp_ext = ext in ALL_SUSPICIOUS_EXTS
        sha256   = compute_sha256(filepath)

        record = {
            "filepath":          filepath,
            "filename":          os.path.basename(filepath),
            "extension":         ext,
            "is_suspicious_ext": susp_ext,
            "is_hidden":         hidden,
            "keyword_hits":      kw_hits,
            "hash":              sha256,
            **metadata,
        }
        record["risk_score"] = risk_score(record)
        record["risk_label"] = risk_label(record["risk_score"])
        results.append(record)

    return results


# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────

def generate_csv(results: list[dict]) -> bytes:
    """Generate CSV report as bytes."""
    output = io.StringIO()
    fieldnames = [
        "filepath", "filename", "extension",
        "is_suspicious_ext", "is_hidden", "keyword_hits",
        "hash", "size_mb", "created", "modified", "accessed",
        "risk_score", "risk_label",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        row = dict(r)
        row["keyword_hits"] = json.dumps(r["keyword_hits"])
        writer.writerow(row)
    return output.getvalue().encode("utf-8")


def generate_txt_report(results: list[dict], scan_path: str) -> str:
    """Generate a plain-text forensic investigation report."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flagged  = [r for r in results if r["risk_score"] >= 20]
    critical = [r for r in results if r["risk_score"] >= 70]
    high     = [r for r in results if 40 <= r["risk_score"] < 70]

    lines = [
        "=" * 70,
        "   CYBER FORENSIC TRIAGE REPORT",
        "   R.M.K. Engineering College – ECE (Advanced Communication & Technology)",
        "=" * 70,
        f"  Scan Date/Time  : {now}",
        f"  Scanned Path    : {scan_path}",
        f"  Total Files     : {len(results)}",
        f"  Flagged Files   : {len(flagged)}",
        f"  Critical        : {len(critical)}",
        f"  High Risk       : {len(high)}",
        "=" * 70,
        "",
    ]

    if critical:
        lines.append("▌ CRITICAL RISK FILES")
        lines.append("-" * 70)
        for r in critical:
            lines += _file_block(r)

    if high:
        lines.append("▌ HIGH RISK FILES")
        lines.append("-" * 70)
        for r in high:
            lines += _file_block(r)

    lines += [
        "",
        "=" * 70,
        "  END OF REPORT",
        "=" * 70,
    ]
    return "\n".join(lines)


def _file_block(r: dict) -> list[str]:
    block = [
        f"  File      : {r['filepath']}",
        f"  Risk      : {r['risk_label']} (Score: {r['risk_score']}/100)",
        f"  Extension : {r['extension']}  |  Size: {r['size_mb']} MB",
        f"  Hidden    : {r['is_hidden']}",
        f"  SHA-256   : {r['hash']}",
        f"  Modified  : {r['modified']}",
    ]
    if r["keyword_hits"]:
        for cat, kws in r["keyword_hits"].items():
            block.append(f"  Keywords [{cat}]: {', '.join(kws)}")
    block.append("")
    return block


def generate_zip(results: list[dict], scan_path: str) -> bytes:
    """Bundle CSV + TXT report into a ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("forensic_report.csv", generate_csv(results))
        zf.writestr("forensic_report.txt", generate_txt_report(results, scan_path))
    return buf.getvalue()


# ─────────────────────────────────────────────
#  STREAMLIT UI
# ─────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="Cyber Forensic Triage",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ── Custom CSS ──────────────────────────────────────────────────────
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Exo 2', sans-serif;
        background: #0a0e1a;
        color: #c8d8e8;
    }

    .stApp { background: #0a0e1a; }

    /* Header */
    .hero {
        background: linear-gradient(135deg, #0d1b2a 0%, #112240 50%, #0d1b2a 100%);
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 28px 36px;
        margin-bottom: 28px;
        position: relative;
        overflow: hidden;
    }
    .hero::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 3px;
        background: linear-gradient(90deg, #00d4ff, #0080ff, #00d4ff);
    }
    .hero h1 {
        font-family: 'Share Tech Mono', monospace;
        color: #00d4ff;
        font-size: 1.8rem;
        letter-spacing: 2px;
        margin: 0;
    }
    .hero p { color: #7a9bb5; margin: 4px 0 0 0; font-size: 0.88rem; }

    /* Stat cards */
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 20px 0; }
    .stat-card {
        background: #0d1b2a;
        border: 1px solid #1e3a5f;
        border-radius: 6px;
        padding: 18px 20px;
        text-align: center;
    }
    .stat-card .num { font-family: 'Share Tech Mono', monospace; font-size: 2rem; color: #00d4ff; }
    .stat-card .lbl { font-size: 0.76rem; color: #7a9bb5; text-transform: uppercase; letter-spacing: 1px; }
    .stat-card.red   .num { color: #ff4444; }
    .stat-card.orange .num { color: #ff8c00; }
    .stat-card.yellow .num { color: #ffd700; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: #0d1b2a !important;
        border-right: 1px solid #1e3a5f;
    }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0066cc, #0044aa);
        color: #fff;
        border: 1px solid #0080ff;
        border-radius: 4px;
        font-family: 'Share Tech Mono', monospace;
        letter-spacing: 1px;
        padding: 8px 24px;
        width: 100%;
        transition: all .2s;
    }
    .stButton > button:hover { background: linear-gradient(135deg, #0080ff, #0055cc); }

    /* DataFrames */
    .stDataFrame { border: 1px solid #1e3a5f; border-radius: 6px; }

    /* Progress */
    .stProgress > div > div { background: #00d4ff; }

    /* Tabs */
    .stTabs [data-baseweb="tab"] { color: #7a9bb5; font-family: 'Share Tech Mono', monospace; }
    .stTabs [aria-selected="true"] { color: #00d4ff; border-bottom-color: #00d4ff; }

    /* Hide default streamlit menu */
    #MainMenu, footer { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)

    # ── Hero Header ────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero">
        <h1>🔍 CYBER FORENSIC TRIAGE SYSTEM</h1>
        <p>R.M.K. Engineering College &nbsp;|&nbsp; ECE – Advanced Communication & Technology &nbsp;|&nbsp; Hackathon 2025</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Sidebar ────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### ⚙️ Scan Configuration")
        st.markdown("---")

        scan_mode = st.radio(
            "Input Mode",
            ["📁 Scan Folder Path", "📤 Upload Files (Demo)"],
        )

        folder_path = ""
        uploaded_files = []

        if scan_mode == "📁 Scan Folder Path":
            folder_path = st.text_input(
                "Enter folder/device path:",
                placeholder="e.g. /home/user/Documents or D:\\Evidence",
            )
        else:
            uploaded_files = st.file_uploader(
                "Upload files to analyse",
                accept_multiple_files=True,
            )

        st.markdown("---")
        st.markdown("### 🎛️ Filter Options")
        show_all   = st.checkbox("Show all files", value=False)
        min_risk   = st.slider("Minimum risk score", 0, 100, 20, 5)

        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
        **Team Members**
        - Lavanya D
        - Meghana N
        - Sethu Madhavan S.B
        - Vishal P

        **Problem Statement 3:**
        Cyber Forensic Triage Software
        """)

    # ── Main Content ───────────────────────────────────────────────────
    start_scan = st.button("🚀 START FORENSIC SCAN", use_container_width=True)

    if start_scan:
        results = []

        # ── Upload mode: write to temp dir ────────────────────────────
        if scan_mode == "📤 Upload Files (Demo)" and uploaded_files:
            with tempfile.TemporaryDirectory() as tmpdir:
                for uf in uploaded_files:
                    dest = os.path.join(tmpdir, uf.name)
                    with open(dest, "wb") as f:
                        f.write(uf.read())

                with st.spinner("🔬 Scanning uploaded files…"):
                    prog = st.progress(0)
                    def cb(done, total):
                        prog.progress(done / total)
                    results = analyze_path(tmpdir, progress_cb=cb)
                    prog.empty()
            scan_target = "Uploaded Files"

        # ── Folder mode ───────────────────────────────────────────────
        elif scan_mode == "📁 Scan Folder Path" and folder_path:
            if not os.path.isdir(folder_path):
                st.error("❌ Path not found or not a directory.")
                st.stop()
            with st.spinner(f"🔬 Scanning `{folder_path}` …"):
                prog = st.progress(0)
                def cb(done, total):
                    prog.progress(done / total)
                results = analyze_path(folder_path, progress_cb=cb)
                prog.empty()
            scan_target = folder_path

        else:
            st.warning("⚠️ Please enter a folder path or upload files first.")
            st.stop()

        if not results:
            st.info("No files found in the selected path.")
            st.stop()

        # ── Store in session state ────────────────────────────────────
        st.session_state["results"]     = results
        st.session_state["scan_target"] = scan_target

    # ── Results section ────────────────────────────────────────────────
    if "results" in st.session_state:
        results     = st.session_state["results"]
        scan_target = st.session_state["scan_target"]

        total    = len(results)
        critical = sum(1 for r in results if r["risk_score"] >= 70)
        high     = sum(1 for r in results if 40 <= r["risk_score"] < 70)
        flagged  = sum(1 for r in results if r["risk_score"] >= 20)

        # ── Stats ─────────────────────────────────────────────────────
        st.markdown(f"""
        <div class="stat-grid">
            <div class="stat-card"><div class="num">{total}</div><div class="lbl">Total Files</div></div>
            <div class="stat-card red"><div class="num">{critical}</div><div class="lbl">Critical Risk</div></div>
            <div class="stat-card orange"><div class="num">{high}</div><div class="lbl">High Risk</div></div>
            <div class="stat-card yellow"><div class="num">{flagged}</div><div class="lbl">Flagged</div></div>
        </div>
        """, unsafe_allow_html=True)

        # ── Tabs ──────────────────────────────────────────────────────
        tab1, tab2, tab3, tab4 = st.tabs(
            ["📋 File Results", "🔑 Keyword Hits", "🔒 Hash Values", "📊 Risk Overview"]
        )

        # Filter
        display = results if show_all else [r for r in results if r["risk_score"] >= min_risk]
        display_sorted = sorted(display, key=lambda x: x["risk_score"], reverse=True)

        with tab1:
            st.markdown(f"**Showing {len(display_sorted)} of {total} files**")
            rows = []
            for r in display_sorted:
                rows.append({
                    "Risk":      r["risk_label"],
                    "Score":     r["risk_score"],
                    "Filename":  r["filename"],
                    "Ext":       r["extension"],
                    "Hidden":    "✓" if r["is_hidden"] else "",
                    "Susp Ext":  "✓" if r["is_suspicious_ext"] else "",
                    "Keywords":  "✓" if r["keyword_hits"] else "",
                    "Size (MB)": r["size_mb"],
                    "Modified":  r["modified"],
                    "Path":      r["filepath"],
                })
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)

        with tab2:
            kw_files = [r for r in results if r["keyword_hits"]]
            if kw_files:
                for r in sorted(kw_files, key=lambda x: x["risk_score"], reverse=True):
                    with st.expander(f"{r['risk_label']}  {r['filename']}", expanded=False):
                        st.code(r["filepath"])
                        for cat, kws in r["keyword_hits"].items():
                            st.markdown(f"**{cat.upper()}**: `{', '.join(kws)}`")
                        st.markdown(f"SHA-256: `{r['hash']}`")
            else:
                st.success("No keyword matches found.")

        with tab3:
            hash_rows = [
                {"Filename": r["filename"], "SHA-256": r["hash"], "Risk": r["risk_label"]}
                for r in display_sorted
            ]
            st.dataframe(pd.DataFrame(hash_rows), use_container_width=True, hide_index=True)

        with tab4:
            ext_counts = {}
            for r in results:
                ext = r["extension"] or "(no ext)"
                ext_counts[ext] = ext_counts.get(ext, 0) + 1

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Extension Distribution**")
                st.bar_chart(pd.Series(ext_counts).sort_values(ascending=False).head(15))
            with col2:
                st.markdown("**Risk Level Breakdown**")
                risk_counts = {
                    "Critical (≥70)":    critical,
                    "High (40-69)":      high,
                    "Medium (20-39)":    sum(1 for r in results if 20 <= r["risk_score"] < 40),
                    "Low (<20)":         sum(1 for r in results if r["risk_score"] < 20),
                }
                st.bar_chart(pd.Series(risk_counts))

        # ── Download ──────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📥 Download Reports")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.download_button(
                "⬇️ Download CSV Report",
                data=generate_csv(results),
                file_name="forensic_report.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with col2:
            st.download_button(
                "⬇️ Download TXT Report",
                data=generate_txt_report(results, scan_target),
                file_name="forensic_report.txt",
                mime="text/plain",
                use_container_width=True,
            )
        with col3:
            st.download_button(
                "⬇️ Download ZIP (All)",
                data=generate_zip(results, scan_target),
                file_name="forensic_bundle.zip",
                mime="application/zip",
                use_container_width=True,
            )

    else:
        # Welcome screen
        st.markdown("""
        <div style="text-align:center; padding: 60px 20px; color: #7a9bb5;">
            <div style="font-size:4rem;">🕵️</div>
            <h3 style="color:#00d4ff; font-family:'Share Tech Mono',monospace;">READY FOR INVESTIGATION</h3>
            <p>Select a folder path or upload files in the sidebar, then click <strong>START FORENSIC SCAN</strong>.</p>
            <br/>
            <p style="font-size:0.82rem;">
                Detects: Suspicious Extensions &nbsp;•&nbsp; Hidden Files &nbsp;•&nbsp;
                Keyword Patterns &nbsp;•&nbsp; SHA-256 Hashes &nbsp;•&nbsp; Metadata &amp; Timestamps
            </p>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()'''

import streamlit as st
import hashlib

# 🔒 Paste your generated hash here
STORED_HASH = "fd59b97d0cbc8cc25578927a0788ef1e6cb365cbd5a313aec03044e6179ee79a"

def check_password(input_password):
    hashed_input = hashlib.sha256(input_password.encode()).hexdigest()
    return hashed_input == STORED_HASH

# Initialize auth state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

def login_screen():
    st.set_page_config(page_title="Secure Access", page_icon="🔐")

    st.markdown("<h1 style='text-align:center;'>🔐 Authorized Access Only</h1>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        password = st.text_input("Enter Investigator Password", type="password")

        if st.button("LOGIN", use_container_width=True):
            if check_password(password):
                st.session_state.authenticated = True
                st.success("Access Granted ✅")
                st.rerun()
            else:
                st.error("Unauthorized Access ❌")


import os
import re
import hashlib
import stat
import json
import csv
import io
import platform
import datetime
from datetime import datetime
import tempfile
import zipfile
import streamlit as st
import pandas as pd
from pathlib import Path
import shutil
import subprocess
import sys
import firebase_admin
from firebase_admin import credentials, db


# FIREBASE INITIALIZATION
if not firebase_admin._apps:

    cred = credentials.Certificate("firebase_key.json")

    firebase_admin.initialize_app(cred, {
        "databaseURL": "https://forensic-triage-default-rtdb.asia-southeast1.firebasedatabase.app/"
    })

# ─────────────────────────────────────────────
#  CONSTANTS & CONFIG
# ─────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    "executables":   [".exe", ".bat", ".cmd", ".com", ".scr", ".pif"],
    "scripts":       [".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta"],
    "malware_like":  [".dll", ".sys", ".drv", ".ocx"],
    "archives":      [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso"],
    "documents":     [".doc", ".docm", ".xlsm", ".pptm"],
    "misc":          [".torrent", ".onion", ".lnk", ".reg"],
}

ALL_SUSPICIOUS_EXTS = {ext for exts in SUSPICIOUS_EXTENSIONS.values() for ext in exts}

KEYWORDS = {
    "credentials": ["password","passwd","pwd","username","login","credential","secret","token","api_key","apikey"],
    "financial":   ["bank","credit card","debit","account number","iban","routing","bitcoin","ethereum","crypto","wallet","transaction"],
    "illegal":     ["exploit","malware","ransomware","phishing","hack","crack","keygen","bypass","payload","shellcode","rootkit"],
    "personal":    ["ssn","social security","passport","aadhaar","pan card","dob","date of birth","phone number"],
}

ALL_KEYWORDS = {kw for kws in KEYWORDS.values() for kw in kws}

READABLE_EXTENSIONS = {
    ".txt",".csv",".log",".xml",".json",".html",".htm",".ini",".cfg",
    ".conf",".yaml",".yml",".py",".js",".ts",".sh",".bat",".ps1",
    ".md",".rst",".env",".sql",
}

LARGE_FILE_THRESHOLD_MB = 100
MAX_KEYWORD_READ_BYTES  = 1_000_000

# ─────────────────────────────────────────────
#  SPLASH SCREEN
# ─────────────────────────────────────────────

SPLASH_HTML = """
<!DOCTYPE html>
<html>
<head>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{margin:0;padding:0;box-sizing:border-box}
  :root{--cyan:#00FFFF;--green:#00FF41;--bg:#020810}
  body{width:100%;height:100vh;background:var(--bg);overflow:hidden;font-family:'Share Tech Mono',monospace;display:flex;flex-direction:column;align-items:center;justify-content:center}
  canvas#m{position:fixed;inset:0;opacity:0.18;z-index:0}
  body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,0.012) 2px,rgba(0,255,65,0.012) 4px);pointer-events:none;z-index:999}
  .corner{position:fixed;width:50px;height:50px;z-index:5;opacity:0.35}
  .corner::before,.corner::after{content:'';position:absolute;background:var(--cyan)}
  .corner::before{width:2px;height:100%}.corner::after{width:100%;height:2px}
  .tl{top:14px;left:14px}.tr{top:14px;right:14px;transform:scaleX(-1)}
  .bl{bottom:14px;left:14px;transform:scaleY(-1)}.br{bottom:14px;right:14px;transform:scale(-1)}
  .wrap{position:relative;z-index:10;display:flex;flex-direction:column;align-items:center;opacity:0;animation:fadeIn .5s ease .2s forwards}
  @keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  .hex{position:relative;width:130px;height:130px;margin-bottom:1.8rem;animation:float 4s ease-in-out infinite}
  @keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}
  .ring{position:absolute;inset:0;border:2px solid var(--cyan);clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);animation:hpulse 2s ease-in-out infinite}
  .ring:nth-child(2){inset:10px;border-color:rgba(0,255,255,.35);animation-delay:.3s}
  .ring:nth-child(3){inset:20px;border-color:rgba(0,255,255,.12);animation-delay:.6s}
  @keyframes hpulse{0%,100%{box-shadow:inset 0 0 0 rgba(0,255,255,0)}50%{box-shadow:inset 0 0 25px rgba(0,255,255,.07),0 0 35px rgba(0,255,255,.12)}}
  .orbit{position:absolute;inset:-18px;border:1px dashed rgba(0,255,255,.18);clip-path:polygon(50% 0%,95% 25%,95% 75%,50% 100%,5% 75%,5% 25%);animation:spin 12s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  .icon{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:2.8rem;animation:iglow 2s ease-in-out infinite alternate}
  @keyframes iglow{from{filter:drop-shadow(0 0 8px var(--cyan))}to{filter:drop-shadow(0 0 22px var(--cyan)) drop-shadow(0 0 44px rgba(0,255,255,.4))}}
  .tag{font-size:.58rem;letter-spacing:.4em;color:var(--green);text-transform:uppercase;margin-bottom:.4rem}
  .title{font-family:'Orbitron',sans-serif;font-weight:900;font-size:clamp(1.5rem,5vw,2.4rem);letter-spacing:.08em;text-transform:uppercase;color:#fff;text-align:center;text-shadow:0 0 30px rgba(0,255,255,.5),0 0 70px rgba(0,255,255,.18);line-height:1.15}
  .title span{color:var(--cyan)}
  .sub{font-family:'Orbitron',sans-serif;font-size:.7rem;letter-spacing:.28em;color:rgba(0,255,255,.45);margin-top:.35rem;text-transform:uppercase}
  .log{width:min(460px,88vw);background:rgba(0,255,65,.025);border:1px solid rgba(0,255,65,.18);border-radius:4px;padding:.85rem 1rem;margin:1.4rem 0 .9rem}
  .ll{font-size:.66rem;line-height:1.95;color:var(--green);opacity:0;transition:opacity .3s}
  .ll.ok::after{content:' [OK]';color:var(--cyan)}.ll.warn::after{content:' [WARN]';color:#FFD700}
  .pbar{width:min(460px,88vw)}
  .ph{display:flex;justify-content:space-between;font-size:.58rem;letter-spacing:.14em;color:rgba(0,255,255,.45);margin-bottom:.35rem}
  .track{height:3px;background:rgba(0,255,255,.1);border-radius:2px;overflow:hidden}
  .fill{height:100%;width:0%;background:linear-gradient(90deg,var(--cyan),var(--green));box-shadow:0 0 10px var(--cyan);transition:width .08s linear}
  #enterBtn{display:none;margin-top:1.8rem;font-family:'Orbitron',sans-serif;font-weight:700;font-size:.78rem;letter-spacing:.28em;text-transform:uppercase;color:#020810;background:var(--cyan);border:none;padding:.8em 2.6em;cursor:pointer;clip-path:polygon(10px 0%,100% 0%,calc(100% - 10px) 100%,0% 100%);box-shadow:0 0 30px rgba(0,255,255,.4);animation:bpulse 1.5s ease-in-out infinite;transition:transform .15s}
  #enterBtn:hover{transform:scale(1.05)}
  @keyframes bpulse{0%,100%{box-shadow:0 0 28px rgba(0,255,255,.4)}50%{box-shadow:0 0 55px rgba(0,255,255,.7)}}
  .statusbar{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:1rem;font-size:.52rem;letter-spacing:.12em;color:rgba(255,255,255,.2);z-index:20}
  .dot{width:5px;height:5px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:dblink 1.2s step-end infinite}
  .dot:nth-child(3){animation-delay:.4s}.dot:nth-child(5){animation-delay:.8s}
  @keyframes dblink{0%,100%{opacity:1}50%{opacity:.1}}
</style>
</head>
<body>
<canvas id="m"></canvas>
<div class="corner tl"></div><div class="corner tr"></div>
<div class="corner bl"></div><div class="corner br"></div>
<div class="wrap">
  <div class="hex">
    <div class="orbit"></div>
    <div class="ring"></div><div class="ring"></div><div class="ring"></div>
    <div class="icon">🔍</div>
  </div>
  <div style="text-align:center;margin-bottom:.2rem">
    <div class="tag">// classified — authorized access only</div>
    <div class="title">CYBER <span>FORENSIC</span><br>TRIAGE <span>TOOL</span></div>
    <div class="sub">Digital Evidence Analysis Platform</div>
  </div>
  <div class="log">
    <div class="ll ok" id="l0">› Initializing threat detection engine</div>
    <div class="ll ok" id="l1">› Loading signature database [v8.3.2]</div>
    <div class="ll ok" id="l2">› Mounting forensic analysis modules</div>
    <div class="ll warn" id="l3">› Scanning environment variables</div>
    <div class="ll ok" id="l4">› Establishing secure sandbox</div>
    <div class="ll ok" id="l5">› All systems nominal — ready</div>
  </div>
  <div class="pbar">
    <div class="ph"><span>SYSTEM BOOT</span><span id="pct">0%</span></div>
    <div class="track"><div class="fill" id="fill"></div></div>
  </div>
  <button id="enterBtn" onclick="enter()">▶ ENTER SYSTEM</button>
</div>
<div class="statusbar">
  <span>SYS</span><div class="dot"></div>
  <span>NET</span><div class="dot"></div>
  <span>SEC</span><div class="dot"></div>
  <span>v2.4.1</span>
</div>
<script>
  const cv=document.getElementById('m'),cx=cv.getContext('2d');
  cv.width=window.innerWidth;cv.height=window.innerHeight;
  const cols=Math.floor(cv.width/15),drops=Array(cols).fill(1);
  const chars='ｱｲｳｴｵｶｷｸｹｺABCDEFGHIJKLM0123456789@#$%^<>/\\';
  function drawMatrix(){
    cx.fillStyle='rgba(2,8,16,0.05)';cx.fillRect(0,0,cv.width,cv.height);
    cx.font='12px Share Tech Mono,monospace';
    drops.forEach((y,i)=>{
      const c=chars[Math.floor(Math.random()*chars.length)];
      const x=i*15,b=Math.random();
      cx.fillStyle=b>.95?'#ffffff':b>.7?'#00FFFF':'#00FF41';
      cx.fillText(c,x,y*15);
      if(y*15>cv.height&&Math.random()>.975)drops[i]=0;
      drops[i]++;
    });
  }
  setInterval(drawMatrix,42);
  const logDelays=[900,1700,2500,3200,4000,4800],pctStops=[14,30,50,65,82,100];
  let curPct=0;
  const fillEl=document.getElementById('fill'),pctEl=document.getElementById('pct');
  function animateTo(target){
    const step=()=>{if(curPct<target){curPct++;fillEl.style.width=curPct+'%';pctEl.textContent=curPct+'%';requestAnimationFrame(step);}};
    requestAnimationFrame(step);
  }
  document.querySelectorAll('.ll').forEach((el,i)=>{
    setTimeout(()=>{
      el.style.opacity='1';animateTo(pctStops[i]);
      if(i===5)setTimeout(()=>{document.getElementById('enterBtn').style.display='block';},600);
    },logDelays[i]);
  });
  function enter(){window.parent.postMessage({type:'streamlit:setComponentValue',value:true},'*');}
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────
#  ADVANCED APP CSS  (File 1 + File 2 merged)
# ─────────────────────────────────────────────

APP_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&family=Exo+2:wght@300;400;600;700&display=swap');

:root {
  --cyan:        #00FFFF;
  --cyan-dim:    #00bcd4;
  --cyan-glow:   rgba(0,255,255,0.15);
  --green:       #00FF41;
  --red:         #FF2244;
  --orange:      #FF8C00;
  --yellow:      #FFD700;
  --bg:          #080B12;
  --surface:     #0D1220;
  --raised:      #111827;
  --card:        #0F1825;
  --border:      rgba(0,255,255,0.20);
  --border-hi:   rgba(0,255,255,0.45);
  --text:        #C8D8E8;
  --text-hi:     #E8F4F8;
  --muted:       #4A6070;
}

html, body,
[data-testid="stAppViewContainer"],
[data-testid="stMain"], .main {
  background-color: var(--bg) !important;
  font-family: 'Exo 2', 'Share Tech Mono', monospace !important;
  color: var(--text) !important;
}

/* Animated grid + radial glow background */
[data-testid="stAppViewContainer"]::before {
  content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background:
    radial-gradient(ellipse 90% 50% at 50% -10%, rgba(0,255,255,0.07), transparent 70%),
    radial-gradient(ellipse 40% 30% at 90% 80%,  rgba(0,100,200,0.04), transparent 60%),
    repeating-linear-gradient(0deg,  transparent, transparent 39px, rgba(0,255,255,0.022) 40px),
    repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,255,0.022) 40px);
}

/* CRT Scanlines overlay */
[data-testid="stAppViewContainer"]::after {
  content: ''; position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: repeating-linear-gradient(0deg,
    transparent, transparent 2px,
    rgba(0,0,0,0.04) 2px, rgba(0,0,0,0.04) 4px);
}

[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer { visibility: hidden !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"]::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan), transparent);
}
[data-testid="stSidebar"] .stMarkdown p,
[data-testid="stSidebar"] .stMarkdown li {
  font-size: 0.78rem !important;
  color: rgba(0,255,255,0.55) !important;
  font-family: 'Share Tech Mono', monospace !important;
}

/* ── Typography ── */
h1 {
  font-family: 'Orbitron', sans-serif !important;
  font-weight: 900 !important; font-size: 1.85rem !important;
  letter-spacing: 0.12em !important; text-transform: uppercase;
  color: var(--cyan) !important; text-align: center;
  text-shadow: 0 0 20px rgba(0,255,255,0.7), 0 0 60px rgba(0,255,255,0.25), 0 0 120px rgba(0,255,255,0.1);
}
h2, h3 {
  font-family: 'Orbitron', sans-serif !important;
  font-weight: 700 !important; color: var(--cyan-dim) !important;
  letter-spacing: 0.07em !important;
}

/* ── Hero Banner ── */
.hero {
  position: relative;
  background: linear-gradient(135deg, #0a1628 0%, #0d1e38 50%, #0a1628 100%);
  border: 1px solid rgba(0,255,255,0.18); border-radius: 6px;
  padding: 30px 40px; margin-bottom: 24px; overflow: hidden;
}
.hero::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, var(--cyan), var(--green), var(--cyan), transparent);
  animation: topbar 3s ease-in-out infinite;
}
.hero::after {
  content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(0,255,255,0.3), transparent);
}
@keyframes topbar { 0%,100%{opacity:0.5} 50%{opacity:1;box-shadow:0 0 20px var(--cyan)} }
.hero h1 {
  font-family: 'Orbitron', sans-serif !important; color: var(--cyan) !important;
  font-size: 1.7rem !important; letter-spacing: 3px; margin: 0 !important;
  text-shadow: 0 0 25px rgba(0,255,255,0.6);
}
.hero p { color: rgba(0,255,255,0.45); margin: 5px 0 0; font-size: 0.8rem; letter-spacing: 0.15em; }
.hero .ctl, .hero .cbr { position: absolute; width: 20px; height: 20px; opacity: 0.45; }
.hero .ctl { top: 10px; left: 10px; border-top: 2px solid var(--cyan); border-left: 2px solid var(--cyan); }
.hero .cbr { bottom: 10px; right: 10px; border-bottom: 2px solid var(--cyan); border-right: 2px solid var(--cyan); }

/* ── Stat Cards ── */
.stat-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin: 20px 0; }
.stat-card {
  position: relative; background: var(--card);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 20px 16px; text-align: center; overflow: hidden;
  transition: border-color .3s, box-shadow .3s;
}
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: var(--cyan); opacity: 0.4;
}
.stat-card:hover {
  border-color: var(--cyan);
  box-shadow: 0 0 20px rgba(0,255,255,0.08), inset 0 0 20px rgba(0,255,255,0.02);
}
.stat-card.red::before   { background: var(--red); }
.stat-card.orange::before{ background: var(--orange); }
.stat-card.yellow::before{ background: var(--yellow); }
.stat-card .num {
  font-family: 'Orbitron', sans-serif; font-size: 2.2rem; font-weight: 900;
  color: var(--cyan); text-shadow: 0 0 20px rgba(0,255,255,0.5); line-height: 1;
}
.stat-card.red    .num { color: var(--red);    text-shadow: 0 0 20px rgba(255,34,68,0.5); }
.stat-card.orange .num { color: var(--orange); text-shadow: 0 0 20px rgba(255,140,0,0.5); }
.stat-card.yellow .num { color: var(--yellow); text-shadow: 0 0 20px rgba(255,215,0,0.5); }
.stat-card .lbl {
  font-size: 0.6rem; color: var(--muted); text-transform: uppercase;
  letter-spacing: 0.15em; margin-top: 6px;
  font-family: 'Share Tech Mono', monospace;
}

/* ── Buttons ── */
.stButton > button {
  background: linear-gradient(135deg, rgba(0,255,255,0.06), rgba(0,140,200,0.10)) !important;
  color: var(--cyan) !important;
  font-family: 'Orbitron', sans-serif !important;
  font-weight: 700 !important; font-size: 0.72rem !important;
  letter-spacing: 0.22em !important; text-transform: uppercase;
  border: 1px solid rgba(0,255,255,0.5) !important;
  border-radius: 4px !important; height: 3.2em; width: 100%;
  position: relative; overflow: hidden;
  transition: all 0.25s ease !important;
  box-shadow: 0 0 14px rgba(0,255,255,0.08) !important;
}
.stButton > button::before {
  content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0,255,255,0.08), transparent);
  transition: left 0.4s ease;
}
.stButton > button:hover {
  background: linear-gradient(135deg, rgba(0,255,255,0.14), rgba(0,188,212,0.20)) !important;
  color: #fff !important; border-color: var(--cyan) !important;
  box-shadow: 0 0 35px rgba(0,255,255,0.3), 0 0 70px rgba(0,255,255,0.08), inset 0 0 20px rgba(0,255,255,0.04) !important;
  transform: translateY(-1px) !important;
}
.stButton > button:hover::before { left: 100%; }
.stButton > button:active { transform: translateY(0) !important; }

/* ── Inputs ── */
.stTextInput > label {
  font-size: 0.6rem !important; letter-spacing: 0.22em !important;
  text-transform: uppercase; color: rgba(0,255,255,0.5) !important;
  font-family: 'Share Tech Mono', monospace !important;
}
.stTextInput > div > div > input {
  background: var(--raised) !important; color: var(--text-hi) !important;
  border: 1px solid var(--border) !important; border-radius: 4px !important;
  font-family: 'Share Tech Mono', monospace !important; font-size: 0.85rem !important;
  transition: border-color .2s, box-shadow .2s !important;
}
.stTextInput > div > div > input:focus {
  border-color: var(--cyan) !important;
  box-shadow: 0 0 0 2px var(--cyan-glow), 0 0 20px rgba(0,255,255,0.08) !important;
}
.stTextInput > div > div > input::placeholder { color: var(--muted) !important; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
  background: var(--surface) !important;
  border-bottom: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
  font-family: 'Orbitron', sans-serif !important;
  font-size: 0.62rem !important; letter-spacing: 0.14em !important;
  text-transform: uppercase; color: var(--muted) !important;
  background: transparent !important; border: none !important;
  transition: color .2s !important;
}
.stTabs [data-baseweb="tab"]:hover { color: rgba(0,255,255,0.7) !important; }
.stTabs [aria-selected="true"] {
  color: var(--cyan) !important;
  background: rgba(0,255,255,0.05) !important;
  border-bottom: 2px solid var(--cyan) !important;
  text-shadow: 0 0 12px rgba(0,255,255,0.5);
}

/* ── DataFrames ── */
.stDataFrame { border: 1px solid var(--border) !important; border-radius: 6px !important; }
.stDataFrame thead th {
  background: var(--raised) !important; color: var(--cyan) !important;
  font-family: 'Share Tech Mono', monospace !important;
  font-size: 0.7rem !important; letter-spacing: 0.1em; text-transform: uppercase;
  border-bottom: 1px solid var(--border) !important;
}
.stDataFrame tbody tr:hover { background: rgba(0,255,255,0.03) !important; }
.stDataFrame tbody td {
  font-family: 'Share Tech Mono', monospace !important; font-size: 0.78rem !important;
  color: var(--text) !important; border-bottom: 1px solid rgba(0,255,255,0.05) !important;
}

/* ── Progress ── */
.stProgress > div > div > div {
  background: linear-gradient(90deg, var(--cyan), var(--green)) !important;
  box-shadow: 0 0 10px var(--cyan) !important;
}
.stProgress > div > div { background: rgba(0,255,255,0.08) !important; border-radius: 2px !important; }

/* ── Alerts ── */
[data-testid="stSuccess"] { border-left: 3px solid var(--green) !important; background: rgba(0,255,65,0.05) !important; }
[data-testid="stError"]   { border-left: 3px solid var(--red) !important;   background: rgba(255,34,68,0.05) !important; }
[data-testid="stWarning"] { border-left: 3px solid var(--yellow) !important; background: rgba(255,215,0,0.05) !important; }
[data-testid="stInfo"]    { border-left: 3px solid var(--cyan) !important;   background: rgba(0,255,255,0.04) !important; }

/* ── Expanders ── */
.streamlit-expanderHeader {
  background: var(--card) !important; border: 1px solid var(--border) !important;
  border-radius: 4px !important; font-family: 'Share Tech Mono', monospace !important;
  font-size: 0.8rem !important; color: var(--text) !important;
  transition: border-color .2s, background .2s !important;
}
.streamlit-expanderHeader:hover { border-color: var(--cyan) !important; background: rgba(0,255,255,0.04) !important; }
.streamlit-expanderContent {
  border: 1px solid var(--border) !important; border-top: none !important;
  background: rgba(0,255,255,0.02) !important;
}

/* ── File Uploader ── */
[data-testid="stFileUploader"] {
  border: 1px dashed rgba(0,255,255,0.3) !important; border-radius: 6px !important;
  background: rgba(0,255,255,0.02) !important; transition: border-color .2s !important;
}
[data-testid="stFileUploader"]:hover { border-color: var(--cyan) !important; background: rgba(0,255,255,0.04) !important; }

/* ── Download Buttons ── */
.stDownloadButton > button {
  background: linear-gradient(135deg, rgba(0,255,255,0.05), rgba(0,100,200,0.08)) !important;
  color: var(--cyan-dim) !important; font-family: 'Share Tech Mono', monospace !important;
  font-size: 0.72rem !important; letter-spacing: 0.1em !important;
  border: 1px solid rgba(0,255,255,0.3) !important; border-radius: 4px !important;
  transition: all .2s !important; width: 100%;
}
.stDownloadButton > button:hover {
  border-color: var(--cyan) !important;
  background: linear-gradient(135deg, rgba(0,255,255,0.10), rgba(0,140,212,0.15)) !important;
  color: #fff !important; box-shadow: 0 0 20px rgba(0,255,255,0.2) !important;
}

/* ── Code blocks ── */
code, pre {
  background: var(--raised) !important; border: 1px solid var(--border) !important;
  color: var(--green) !important; font-family: 'Share Tech Mono', monospace !important;
  font-size: 0.78rem !important; border-radius: 3px !important;
}

/* ── Slider ── */
.stSlider > label { font-size: 0.6rem !important; letter-spacing: 0.18em !important; color: rgba(0,255,255,0.5) !important; text-transform: uppercase !important; }
[data-testid="stSlider"] [data-baseweb="slider"] [role="slider"] { background: var(--cyan) !important; box-shadow: 0 0 10px var(--cyan) !important; }

/* ── Dividers & Scrollbar ── */
hr { border: none !important; border-top: 1px solid var(--border) !important; margin: 1.4rem 0 !important; }
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: rgba(0,255,255,0.2); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0,255,255,0.45); }

/* ── Section Headers ── */
.sec-hdr {
  font-family: 'Share Tech Mono', monospace; font-size: 0.68rem;
  letter-spacing: 0.2em; text-transform: uppercase;
  color: rgba(0,255,255,0.45); margin-bottom: 8px;
}

/* ── Welcome Screen ── */
.welcome {
  text-align: center; padding: 60px 20px;
}
.welcome .wi { font-size: 4rem; animation: wfloat 4s ease-in-out infinite; display: block; }
@keyframes wfloat { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }
.welcome h3 {
  font-family: 'Orbitron', sans-serif !important; color: var(--cyan) !important;
  letter-spacing: 0.12em; text-shadow: 0 0 20px rgba(0,255,255,0.4); margin-top: 12px;
}
.welcome p { font-size: 0.82rem; color: rgba(0,255,255,0.35); margin-top: 8px; }
.feat-wrap { display: flex; flex-wrap: wrap; gap: 8px; justify-content: center; margin-top: 18px; }
.feat {
  font-size: 0.62rem; letter-spacing: 0.12em; color: rgba(0,255,255,0.4);
  border: 1px solid rgba(0,255,255,0.15); border-radius: 3px; padding: 4px 12px;
  font-family: 'Share Tech Mono', monospace; text-transform: uppercase;
  transition: all .2s;
}
.feat:hover { border-color: var(--cyan); color: var(--cyan); background: rgba(0,255,255,0.04); }
</style>
"""

# ─────────────────────────────────────────────
#  CORE ANALYSIS ENGINE
# ─────────────────────────────────────────────
def compute_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        return "HASH_ERROR"

def is_hidden(filepath: str) -> bool:
    name = os.path.basename(filepath)
    if name.startswith("."):
        return True
    if platform.system() == "Windows":
        try:
            attrs = os.stat(filepath).st_file_attributes
            return bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            pass
    return False

def keyword_scan(filepath: str) -> dict:
    ext = Path(filepath).suffix.lower()
    if ext not in READABLE_EXTENSIONS:
        return {}
    found = {}
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read(MAX_KEYWORD_READ_BYTES).lower()
        for category, keywords in KEYWORDS.items():
            hits = [kw for kw in keywords if kw in content]
            if hits:
                found[category] = hits
    except (PermissionError, OSError, UnicodeDecodeError):
        pass
    return found

def get_metadata(filepath: str) -> dict:
    try:
        s = Path(filepath).stat()
        return {
            "size_bytes": s.st_size,
            "size_mb":    round(s.st_size / (1024 * 1024), 3),
            #"created":    datetime.datetime.fromtimestamp(s.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            #"modified":   datetime.datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            #"accessed":   datetime.datetime.fromtimestamp(s.st_atime).strftime("%Y-%m-%d %H:%M:%S"), 
            "created":    datetime.fromtimestamp(s.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "modified":   datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "accessed":   datetime.fromtimestamp(s.st_atime).strftime("%Y-%m-%d %H:%M:%S"),

        }
    except (PermissionError, OSError):
        return {"size_bytes": 0, "size_mb": 0, "created": "N/A", "modified": "N/A", "accessed": "N/A"}

def risk_score(record: dict) -> int:
    score = 0
    if record["is_suspicious_ext"]: score += 35
    if record["is_hidden"]:         score += 20
    if record["keyword_hits"]:      score += min(len(record["keyword_hits"]) * 10, 30)
    if record["size_mb"] > LARGE_FILE_THRESHOLD_MB: score += 10
    if record["hash"] == "HASH_ERROR": score += 5
    return min(score, 100)

def risk_label(score: int) -> str:
    if score >= 70: return "🔴 CRITICAL"
    if score >= 40: return "🟠 HIGH"
    if score >= 20: return "🟡 MEDIUM"
    return "🟢 LOW"

def get_file_times(filepath):
    try:
        stat = os.stat(filepath)

        created_time = datetime.datetime.fromtimestamp(stat.st_ctime)
        modified_time = datetime.datetime.fromtimestamp(stat.st_mtime)
        accessed_time = datetime.datetime.fromtimestamp(stat.st_atime)

        return created_time, modified_time, accessed_time

    except Exception:
        return "N/A", "N/A", "N/A"

def analyze_path(root_path: str, progress_cb=None) -> list[dict]:
    results, all_files = [], []
    for dirpath, _, filenames in os.walk(root_path):
        for fname in filenames:
            all_files.append(os.path.join(dirpath, fname))
    total = len(all_files)
    for idx, filepath in enumerate(all_files):
        if progress_cb:
            progress_cb(idx + 1, total)
        ext      = Path(filepath).suffix.lower()
        metadata = get_metadata(filepath)
        created, modified, accessed = get_file_times(filepath)
        kw_hits  = keyword_scan(filepath)
        hidden   = is_hidden(filepath)
        susp_ext = ext in ALL_SUSPICIOUS_EXTS
        sha256   = compute_sha256(filepath)
        record = {
            "filepath": filepath, "filename": os.path.basename(filepath),
            "extension": ext, "is_suspicious_ext": susp_ext,
            "is_hidden": hidden, "keyword_hits": kw_hits, "hash": sha256, 
            **metadata,
        }
        record["risk_score"] = risk_score(record)
        record["risk_label"] = risk_label(record["risk_score"])
        results.append(record)
    return results


# ─────────────────────────────────────────────
#  NATIVE SANDBOX / QUARANTINE ENGINE
# ─────────────────────────────────────────────
def run_native_sandbox(filepath: str) -> str:
    """Copy suspicious file to quarantine and run sandbox_analyze.py on it."""
    quarantine_dir = os.path.join(os.getcwd(), "quarantine_zone")
    os.makedirs(quarantine_dir, exist_ok=True)

    filename  = os.path.basename(filepath)
    safe_path = os.path.join(quarantine_dir, filename + ".analysis")

    try:
        shutil.copy2(filepath, safe_path)
    except Exception as e:
        return f"QUARANTINE_FAILED: {e}"

    try:
        result = subprocess.run(
            [sys.executable, "sandbox_analyze.py", safe_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip() or "NORMAL"
    except subprocess.TimeoutExpired:
        return "ERROR: Analysis timed out (Possible infinite loop / Malware)"
    except FileNotFoundError:
        return "ERROR: sandbox_analyze.py not found"
    except Exception as e:
        return f"ERROR: {str(e)}"
# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────

def generate_csv(results: list[dict]) -> bytes:
    output = io.StringIO()
    fieldnames = ["filepath","filename","extension","is_suspicious_ext","is_hidden",
                  "keyword_hits","hash","size_mb","created","modified","accessed","risk_score","risk_label"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        row = dict(r); row["keyword_hits"] = json.dumps(r["keyword_hits"])
        writer.writerow(row)
    return output.getvalue().encode("utf-8")

def generate_txt_report(results: list[dict], scan_path: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    flagged  = [r for r in results if r["risk_score"] >= 20]
    critical = [r for r in results if r["risk_score"] >= 70]
    high     = [r for r in results if 40 <= r["risk_score"] < 70]
    lines = [
        "=" * 70, "   CYBER FORENSIC TRIAGE REPORT",
        "   R.M.K. Engineering College – ECE (Advanced Communication & Technology)",
        "=" * 70,
        f"  Scan Date/Time  : {now}", f"  Scanned Path    : {scan_path}",
        f"  Total Files     : {len(results)}", f"  Flagged Files   : {len(flagged)}",
        f"  Critical        : {len(critical)}", f"  High Risk       : {len(high)}",
        "=" * 70, "",
    ]
    if critical:
        lines += ["▌ CRITICAL RISK FILES", "-" * 70]
        for r in critical: lines += _file_block(r)
    if high:
        lines += ["▌ HIGH RISK FILES", "-" * 70]
        for r in high: lines += _file_block(r)
    lines += ["", "=" * 70, "  END OF REPORT", "=" * 70]
    return "\n".join(lines)

def _file_block(r: dict) -> list[str]:
    block = [
        f"  File      : {r['filepath']}",
        f"  Risk      : {r['risk_label']} (Score: {r['risk_score']}/100)",
        f"  Extension : {r['extension']}  |  Size: {r['size_mb']} MB",
        f"  Hidden    : {r['is_hidden']}", f"  SHA-256   : {r['hash']}",
        f"  Modified  : {r['modified']}",
    ]
    if r["keyword_hits"]:
        for cat, kws in r["keyword_hits"].items():
            block.append(f"  Keywords [{cat}]: {', '.join(kws)}")
    block.append("")
    return block

def generate_zip(results: list[dict], scan_path: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("forensic_report.csv", generate_csv(results))
        zf.writestr("forensic_report.txt", generate_txt_report(results, scan_path))
    return buf.getvalue()

def upload_results_to_firebase(results, scan_target):

    ref = db.reference("forensic_scans")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for r in results:

        created  = r.get("created", "N/A")
        modified = r.get("modified", "N/A")
        accessed = r.get("accessed", "N/A")

        data = {
            "filename": r.get("filename"),
            "filepath": r.get("filepath"),
            "sha256": r.get("hash"),
            "created_time": created,
            "modified_time": modified,
            "accessed_time": accessed,
            "risk": r.get("risk_label"),
            "risk_score": r.get("risk_score"),
            "size_mb": r.get("size_mb"),
            "scan_location": scan_target,
            "scan_time": scan_time
        }

        ref.push(data)
# ─────────────────────────────────────────────
#  STREAMLIT UI
# ─────────────────────────────────────────────

def main():
    st.set_page_config(
        page_title="Cyber Forensic Triage",
        page_icon="🔍", layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(APP_CSS, unsafe_allow_html=True)

    # ── Splash gate ───────────────────────────────────────────────────
    if "splash_done" not in st.session_state:
        st.session_state["splash_done"] = False

    if not st.session_state["splash_done"]:
        clicked = st.components.v1.html(SPLASH_HTML, height=620, scrolling=False)
        if clicked:
            st.session_state["splash_done"] = True
            st.rerun()
        _, mid, _ = st.columns([3, 1, 3])
        with mid:
            if st.button("▶ SKIP INTRO"):
                st.session_state["splash_done"] = True
                st.rerun()
        st.stop()

    # ── Hero ──────────────────────────────────────────────────────────
    st.markdown("""
    <div class="hero">
      <div class="ctl"></div>
      <div class="cbr"></div>
      <h1>🔍 CYBER FORENSIC TRIAGE SYSTEM</h1>
      <p>       R.M.K. Engineering College - &nbsp  ECA Department &nbsp; - &nbsp; Mini Project Competition 2K26</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Sidebar ───────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### ⚙️ Scan Configuration")
        st.markdown("---")
        scan_mode = st.radio("Input Mode", ["📁 Scan Folder Path", "📤 Upload Files (Demo)"])
        folder_path, uploaded_files = "", []

        if scan_mode == "📁 Scan Folder Path":
            folder_path = st.text_input("Enter folder/device path:", placeholder="e.g. /home/user/Documents or D:\\Evidence")
        else:
            uploaded_files = st.file_uploader("Upload files to analyse", accept_multiple_files=True)

        st.markdown("---")
        st.markdown("### 🎛️ Filter Options")
        show_all = st.checkbox("Show all files", value=False)
        min_risk = st.slider("Minimum risk score", 0, 100, 20, 5)
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.markdown("""
**Team Members**
- Sethu Madhavan S.B  
- Vishal P

**Problem Statement 3:** Cyber Forensic Triage Software
        """)
        if st.button("🔓 Logout"):
            st.session_state.authenticated = False
            st.rerun()

    # ── Scan Button ───────────────────────────────────────────────────
    if st.button("🚀 START FORENSIC SCAN", use_container_width=True):
        results = []
        if scan_mode == "📤 Upload Files (Demo)" and uploaded_files:
            with tempfile.TemporaryDirectory() as tmpdir:
                for uf in uploaded_files:
                    dest = os.path.join(tmpdir, uf.name)
                    with open(dest, "wb") as f: f.write(uf.read())
                with st.spinner("🔬 Scanning uploaded files…"):
                    prog = st.progress(0)
                    def cb(done, total): prog.progress(done / total)
                    results = analyze_path(tmpdir, progress_cb=cb)
                    prog.empty()
            scan_target = "Uploaded Files"

        elif scan_mode == "📁 Scan Folder Path" and folder_path:
            if not os.path.isdir(folder_path):
                st.error("❌ Path not found or not a directory."); st.stop()
            with st.spinner(f"🔬 Scanning `{folder_path}` …"):
                prog = st.progress(0)
                def cb(done, total): prog.progress(done / total)
                results = analyze_path(folder_path, progress_cb=cb)
                prog.empty()
            scan_target = folder_path
        else:
            st.warning("⚠️ Please enter a folder path or upload files first."); st.stop()

        if not results:
            st.info("No files found in the selected path."); st.stop()

        st.session_state["results"]     = results
        st.session_state["scan_target"] = scan_target
        upload_results_to_firebase(results, scan_target)


    # ── Results ───────────────────────────────────────────────────────
    if "results" in st.session_state:
        results     = st.session_state["results"]
        scan_target = st.session_state["scan_target"]

        total    = len(results)
        critical = sum(1 for r in results if r["risk_score"] >= 70)
        high     = sum(1 for r in results if 40 <= r["risk_score"] < 70)
        flagged  = sum(1 for r in results if r["risk_score"] >= 20)

        st.markdown(f"""
        <div class="stat-grid">
          <div class="stat-card"><div class="num">{total}</div><div class="lbl">Total Files</div></div>
          <div class="stat-card red"><div class="num">{critical}</div><div class="lbl">Critical Risk</div></div>
          <div class="stat-card orange"><div class="num">{high}</div><div class="lbl">High Risk</div></div>
          <div class="stat-card yellow"><div class="num">{flagged}</div><div class="lbl">Flagged</div></div>
        </div>
        """, unsafe_allow_html=True)

        tab1, tab2, tab3, tab4 = st.tabs(["📋 File Results", "🔑 Keyword Hits", "🔒 Hash Values", "📊 Risk Overview"])
        display        = results if show_all else [r for r in results if r["risk_score"] >= min_risk]
        display_sorted = sorted(display, key=lambda x: x["risk_score"], reverse=True)

        with tab1:
            st.markdown(f'<div class="sec-hdr">Showing {len(display_sorted)} of {total} files</div>', unsafe_allow_html=True)
            rows = [{"Risk": r["risk_label"], "Score": r["risk_score"], "Filename": r["filename"],
                     "Ext": r["extension"], "Hidden": "✓" if r["is_hidden"] else "",
                     "Susp Ext": "✓" if r["is_suspicious_ext"] else "",
                     "Keywords": "✓" if r["keyword_hits"] else "",
                     "Size (MB)": r["size_mb"], "Modified": r["modified"], "Path": r["filepath"]}
                    for r in display_sorted]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            # ── Sandbox Deep-Scan for High Risk Files ──────────────────────
            st.markdown("---")
            st.markdown("#### 🧪 Deep Sandbox Analysis")

            # Filter files with risk_score > 50
            high_risk_files = [r for r in display_sorted if r["risk_score"] > 50]

            if not high_risk_files:
                st.success("✅ No files exceed the sandbox threshold (score > 50).")
            else:
                st.warning(f"⚠️ {len(high_risk_files)} file(s) flagged for deep analysis.")

                if st.button("🔬 Run Sandbox on High-Risk Files", use_container_width=True):
                    sandbox_results = []

                    for record in high_risk_files:
                        filepath = record["filepath"]

                        # Only analyze if file actually exists (handles upload temp paths)
                        if not os.path.exists(filepath):
                            sandbox_results.append({
                                "filename": record["filename"],
                                "risk_score": record["risk_score"],
                                "verdict": "SKIPPED: File no longer accessible (temp upload)"
                            })
                            continue

                        with st.spinner(f"🔍 Analysing `{record['filename']}`..."):
                            verdict = run_native_sandbox(filepath)

                        sandbox_results.append({
                            "filename":   record["filename"],
                            "risk_score": record["risk_score"],
                            "verdict":    verdict
                        })

                        # Show per-file result immediately
                        if "NORMAL" in verdict:
                            st.success(f"✅ `{record['filename']}` — Passed: `{verdict}`")
                        elif "SKIPPED" in verdict:
                            st.info(f"⏭️ `{record['filename']}` — {verdict}")
                        elif "ERROR" in verdict or "FAILED" in verdict:
                            st.warning(f"⚙️ `{record['filename']}` — `{verdict}`")
                        else:
                            st.error(f"🚨 `{record['filename']}` — THREAT: `{verdict}`")

                    # Summary table
                    if sandbox_results:
                        st.markdown("##### 📋 Sandbox Summary")
                        st.dataframe(
                            pd.DataFrame(sandbox_results),
                            use_container_width=True,
                            hide_index=True
                        )

                        # Push sandbox verdicts back to Firebase
                        try:
                            ref = db.reference("forensic_scans")
                            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            for sr in sandbox_results:
                                ref.push({
                                    "filename":        sr["filename"],
                                    "risk_score":      sr["risk_score"],
                                    "sandbox_verdict": sr["verdict"],
                                    "scan_time":       scan_time,
                                    "type":            "sandbox_analysis"
                                })
                            st.success("✅ Sandbox results saved to Firebase.")
                        except Exception as e:
                            st.warning(f"⚠️ Firebase push failed: {e}")

        with tab2:
            kw_files = [r for r in results if r["keyword_hits"]]
            if kw_files:
                for r in sorted(kw_files, key=lambda x: x["risk_score"], reverse=True):
                    with st.expander(f"{r['risk_label']}  {r['filename']}", expanded=False):
                        st.code(r["filepath"])
                        for cat, kws in r["keyword_hits"].items():
                            st.markdown(f"**{cat.upper()}**: `{', '.join(kws)}`")
                        st.markdown(f"SHA-256: `{r['hash']}`")
            else:
                st.success("✔ No keyword matches found.")

        with tab3:
            st.dataframe(
                pd.DataFrame([
                    {
                        "Filename": r["filename"],
                        "SHA-256": r["hash"],
                        "Created Time": r["created"],
                        "Modified Time": r["modified"],
                        "Accessed Time": r["accessed"],
                        "Risk": r["risk_label"]
                    }
                    for r in display_sorted
                ]),
                use_container_width=True,
                hide_index=True
            )

        with tab4:
            ext_counts = {}
            for r in results:
                ext = r["extension"] or "(no ext)"
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
            col1, col2 = st.columns(2)
            with col1:
                st.markdown('<div class="sec-hdr">Extension Distribution</div>', unsafe_allow_html=True)
                st.bar_chart(pd.Series(ext_counts).sort_values(ascending=False).head(15))
            with col2:
                st.markdown('<div class="sec-hdr">Risk Level Breakdown</div>', unsafe_allow_html=True)
                st.bar_chart(pd.Series({
                    "Critical (≥70)": critical, "High (40-69)": high,
                    "Medium (20-39)": sum(1 for r in results if 20 <= r["risk_score"] < 40),
                    "Low (<20)":      sum(1 for r in results if r["risk_score"] < 20),
                }))

       
        
        DB_VIEWER_PASSWORD = 'forensic2026'
        st.markdown("---")
        st.markdown("### 🔐 Investigation Reports & Database")

        # ── Password Gate ─────────────────────────────────────────────
        if "db_authenticated" not in st.session_state:
            st.session_state["db_authenticated"] = False

        if not st.session_state["db_authenticated"]:
            st.markdown("🔒 **Enter password to access reports and database**")
            col1, col2 = st.columns([2, 1])
            with col1:
                pwd = st.text_input("🔐 Password", type="password", key="db_pwd_input")
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔓 Unlock", use_container_width=True):
                    if pwd == DB_VIEWER_PASSWORD:
                        st.session_state["db_authenticated"] = True
                        st.rerun()
                    else:
                        st.error("❌ Incorrect password.")

        # ── Unlocked Section ──────────────────────────────────────────
        if st.session_state["db_authenticated"]:

            st.success("✅ Access granted — Reports & Database unlocked")

            col_lock, _ = st.columns([1, 3])
            with col_lock:
                if st.button("🔒 Lock Section", use_container_width=True):
                    st.session_state["db_authenticated"] = False
                    st.rerun()

            # ── Download Reports ──────────────────────────────────────
            st.markdown("#### 📥 Download Reports")
            c1, c2, c3 = st.columns(3)
            with c1:
                st.download_button("⬇️ Download CSV", data=generate_csv(results),
                                   file_name="forensic_report.csv", mime="text/csv", use_container_width=True)
            with c2:
                st.download_button("⬇️ Download TXT", data=generate_txt_report(results, scan_target),
                                   file_name="forensic_report.txt", mime="text/plain", use_container_width=True)
            with c3:
                st.download_button("⬇️ Download ZIP", data=generate_zip(results, scan_target),
                                   file_name="forensic_bundle.zip", mime="application/zip", use_container_width=True)
            # ── Database Viewer ───────────────────────────────────────
            st.markdown("---")
            st.markdown("#### 🗄️ Firebase Database Viewer")

            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                if st.button("🔄 Refresh Data", use_container_width=True):
                    st.rerun()
            with col2:
                if st.button("🗑️ Clear View", use_container_width=True):
                    st.rerun()
            with col3:
                if st.button("☠️ Clear Database", use_container_width=True):
                    st.session_state["confirm_delete"] = True

            # ── Confirm Delete ────────────────────────────────────────
            if st.session_state.get("confirm_delete", False):
                st.warning("⚠️ Are you sure? This will **permanently delete ALL records** from Firebase.")
                yes_col, no_col = st.columns([1, 1])
                with yes_col:
                    if st.button("✅ Yes, Delete Everything", use_container_width=True):
                        try:
                            db.reference("forensic_scans").delete()
                            st.session_state["confirm_delete"] = False
                            st.success("🗑️ Database cleared successfully.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Failed to delete: {e}")
                with no_col:
                    if st.button("❌ Cancel", use_container_width=True):
                        st.session_state["confirm_delete"] = False
                        st.rerun()

            try:
                ref = db.reference("forensic_scans")
                data = ref.get()

                if not data:
                    st.info("📭 No scan records found in database.")
                else:
                    records = []
                    for key, val in data.items():
                        val["_firebase_id"] = key
                        records.append(val)

                    st.markdown(f"**Total records in database: {len(records)}**")

                    df = pd.DataFrame(records)

                    priority_cols = ["filename", "risk", "risk_score", "sha256",
                                     "scan_location", "scan_time", "size_mb",
                                     "created_time", "modified_time",
                                     "accessed_time", "filepath", "_firebase_id"]
                    cols = [c for c in priority_cols if c in df.columns]
                    other_cols = [c for c in df.columns if c not in cols]
                    df = df[cols + other_cols]

                    st.dataframe(df, use_container_width=True, hide_index=True)

                    csv_export = df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "⬇️ Download Full Database as CSV",
                        data=csv_export,
                        file_name="firebase_database_export.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

            except Exception as e:
                st.error(f"❌ Failed to fetch database: {e}")
                               
        if st.button("END FORENSIC SCANNING"):
            for key in st.session_state.keys():
                del st.session_state[key]
            st.rerun()
    else:
        st.markdown("""
        <div class="welcome">
          <span class="wi">🕵️</span>
          <h3>READY FOR INVESTIGATION</h3>
          <p>Select a folder path or upload files in the sidebar,<br>
             then click <strong style="color:#00FFFF;">START FORENSIC SCAN</strong>.</p>
          <div class="feat-wrap">
            <span class="feat">Suspicious Extensions</span>
            <span class="feat">Hidden Files</span>
            <span class="feat">Keyword Patterns</span>
            <span class="feat">SHA-256 Hashes</span>
            <span class="feat">Metadata &amp; Timestamps</span>
            <span class="feat">Risk Scoring</span>
          </div>
        </div>
        """, unsafe_allow_html=True)


if __name__ == "__main__":
    if not st.session_state.authenticated:
        login_screen()
        st.stop()
    else:
        main()
