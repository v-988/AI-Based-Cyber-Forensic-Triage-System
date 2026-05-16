'''import streamlit as st

#st.title("This the Best Project")
st.write("Hello World")
import streamlit as st
import os

# Custom CSS
st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');

/* ── Root Variables ── */
:root {
    --cyan: #00FFFF;
    --cyan-dim: #00bcd4;
    --cyan-glow: rgba(0, 255, 255, 0.15);
    --bg-deep: #080B12;
    --bg-surface: #0F1320;
    --bg-raised: #161B2E;
    --border: rgba(0, 255, 255, 0.25);
    --text-primary: #E0F7FA;
    --text-muted: #607D8B;
}

/* ── Global ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: var(--bg-deep) !important;
    font-family: 'Rajdhani', sans-serif;
    color: var(--text-primary);
}

[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed;
    inset: 0;
    background:
        radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0, 255, 255, 0.07), transparent),
        repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,255,255,0.03) 40px),
        repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,255,0.03) 40px);
    pointer-events: none;
    z-index: 0;
}

[data-testid="stSidebar"] {
    background-color: var(--bg-surface) !important;
    border-right: 1px solid var(--border);
}

/* ── Headings ── */
h1 {
    font-family: 'Rajdhani', sans-serif;
    font-weight: 700;
    font-size: 2.8rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--cyan) !important;
    text-align: center;
    text-shadow:
        0 0 20px rgba(0, 255, 255, 0.6),
        0 0 60px rgba(0, 255, 255, 0.2);
    margin-bottom: 0.2em;
}

h2, h3 {
    font-family: 'Rajdhani', sans-serif;
    font-weight: 600;
    letter-spacing: 0.06em;
    color: var(--cyan-dim) !important;
}

/* ── Text Input ── */
.stTextInput > label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--cyan-dim) !important;
}

.stTextInput > div > div > input {
    background-color: var(--bg-raised) !important;
    color: var(--text-primary) !important;
    border-radius: 6px !important;
    border: 1px solid var(--border) !important;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.95rem;
    padding: 0.6em 1em;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.stTextInput > div > div > input:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 3px var(--cyan-glow), inset 0 0 20px rgba(0,255,255,0.04) !important;
    outline: none !important;
}

.stTextInput > div > div > input::placeholder {
    color: var(--text-muted);
}

/* ── Button ── */
.stButton > button {
    background: linear-gradient(135deg, rgba(0,255,255,0.1) 0%, rgba(0,188,212,0.15) 100%) !important;
    color: var(--cyan) !important;
    font-family: 'Rajdhani', sans-serif;
    font-weight: 700;
    font-size: 1rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    border-radius: 6px !important;
    border: 1px solid var(--cyan) !important;
    height: 3em;
    width: 100%;
    position: relative;
    overflow: hidden;
    transition: all 0.25s ease;
    box-shadow: 0 0 15px rgba(0,255,255,0.1), inset 0 1px 0 rgba(255,255,255,0.05);
}

.stButton > button::before {
    content: '';
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0,255,255,0.15), transparent);
    transition: left 0.4s ease;
}

.stButton > button:hover {
    background: linear-gradient(135deg, rgba(0,255,255,0.2) 0%, rgba(0,188,212,0.25) 100%) !important;
    color: white !important;
    box-shadow: 0 0 25px rgba(0,255,255,0.35), 0 0 60px rgba(0,255,255,0.1) !important;
    transform: translateY(-1px);
}

.stButton > button:hover::before {
    left: 100%;
}

.stButton > button:active {
    transform: translateY(0px);
    box-shadow: 0 0 10px rgba(0,255,255,0.2) !important;
}

/* ── Selectbox / Dropdowns ── */
.stSelectbox > div > div {
    background-color: var(--bg-raised) !important;
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
}

/* ── Metrics & Cards ── */
[data-testid="metric-container"] {
    background-color: var(--bg-raised);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem 1.2rem;
    box-shadow: 0 0 20px rgba(0,255,255,0.05);
}

/* ── Dataframe / Tables ── */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 8px;
    overflow: hidden;
}

/* ── Divider ── */
hr {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.5rem 0;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: rgba(0, 255, 255, 0.25); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(0, 255, 255, 0.5); }

</style>
""", unsafe_allow_html=True)


st.title("Cyber Forensic Triage Tool")

folder_path = st.text_input("Enter Folder Path")

if st.button("Start Scan"):

    if os.path.exists(folder_path):

        suspicious_files = []

        for root, dirs, files in os.walk(folder_path):
            for file in files:

                file_path = os.path.join(root, file)

                if file.endswith((".exe", ".bat", ".vbs", ".ps1")):
                    suspicious_files.append(file_path)

        if suspicious_files:
            st.write("Suspicious Files Found:")

            for f in suspicious_files:
                st.write(f)

        else:
            st.write("No suspicious files found.")

    else:
        st.error("Folder path does not exist!")'''

import streamlit as st
import os
import time
import streamlit.components.v1 as components

# ── Page Config ──
st.set_page_config(
    page_title="Cyber Forensic Triage Tool",
    page_icon="🔍",
    layout="centered"
)

# ── Session State ──
if "splashed" not in st.session_state:
    st.session_state.splashed = False

# ══════════════════════════════════════════════════════
#  SPLASH SCREEN HTML (Animation runs inside Streamlit)
# ══════════════════════════════════════════════════════
SPLASH_HTML = """
<!DOCTYPE html>
<html>
<head>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
  :root { --cyan:#00FFFF; --green:#00FF41; --bg:#020810; }

  body {
    width:100%; height:100vh;
    background:var(--bg);
    overflow:hidden;
    font-family:'Share Tech Mono',monospace;
    display:flex; flex-direction:column;
    align-items:center; justify-content:center;
  }

  /* Matrix canvas */
  canvas#m { position:fixed; inset:0; opacity:0.18; z-index:0; }

  /* Scanline overlay */
  body::after {
    content:''; position:fixed; inset:0;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,0.012) 2px,rgba(0,255,65,0.012) 4px);
    pointer-events:none; z-index:999;
  }

  /* Corner brackets */
  .corner { position:fixed; width:50px; height:50px; z-index:5; opacity:0.35; }
  .corner::before,.corner::after { content:''; position:absolute; background:var(--cyan); }
  .corner::before { width:2px; height:100%; }
  .corner::after  { width:100%; height:2px; }
  .tl{top:14px;left:14px}
  .tr{top:14px;right:14px;transform:scaleX(-1)}
  .bl{bottom:14px;left:14px;transform:scaleY(-1)}
  .br{bottom:14px;right:14px;transform:scale(-1)}

  /* Main wrapper */
  .wrap {
    position:relative; z-index:10;
    display:flex; flex-direction:column; align-items:center;
    opacity:0; animation:fadeIn 0.5s ease 0.2s forwards;
  }
  @keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }

  /* Hexagon logo */
  .hex { position:relative; width:130px; height:130px; margin-bottom:1.8rem; animation:float 4s ease-in-out infinite; }
  @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }

  .ring {
    position:absolute; inset:0;
    border:2px solid var(--cyan);
    clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);
    animation:hpulse 2s ease-in-out infinite;
  }
  .ring:nth-child(2){inset:10px;border-color:rgba(0,255,255,.35);animation-delay:.3s}
  .ring:nth-child(3){inset:20px;border-color:rgba(0,255,255,.12);animation-delay:.6s}
  @keyframes hpulse {
    0%,100%{box-shadow:inset 0 0 0 rgba(0,255,255,0)}
    50%{box-shadow:inset 0 0 25px rgba(0,255,255,.07),0 0 35px rgba(0,255,255,.12)}
  }

  .orbit {
    position:absolute; inset:-18px;
    border:1px dashed rgba(0,255,255,.18);
    clip-path:polygon(50% 0%,95% 25%,95% 75%,50% 100%,5% 75%,5% 25%);
    animation:spin 12s linear infinite;
  }
  @keyframes spin { to{transform:rotate(360deg)} }

  .icon {
    position:absolute; inset:0;
    display:flex; align-items:center; justify-content:center;
    font-size:2.8rem;
    animation:iglow 2s ease-in-out infinite alternate;
  }
  @keyframes iglow {
    from{filter:drop-shadow(0 0 8px var(--cyan))}
    to{filter:drop-shadow(0 0 22px var(--cyan)) drop-shadow(0 0 44px rgba(0,255,255,.4))}
  }

  /* Title */
  .tag   { font-size:.58rem; letter-spacing:.4em; color:var(--green); text-transform:uppercase; margin-bottom:.4rem; }
  .title {
    font-family:'Orbitron',sans-serif; font-weight:900;
    font-size:clamp(1.5rem,5vw,2.4rem); letter-spacing:.08em;
    text-transform:uppercase; color:#fff; text-align:center;
    text-shadow:0 0 30px rgba(0,255,255,.5),0 0 70px rgba(0,255,255,.18);
    line-height:1.15;
  }
  .title span { color:var(--cyan); }
  .sub {
    font-family:'Orbitron',sans-serif; font-size:.7rem;
    letter-spacing:.28em; color:rgba(0,255,255,.45);
    margin-top:.35rem; text-transform:uppercase;
  }

  /* Boot log box */
  .log {
    width:min(460px,88vw);
    background:rgba(0,255,65,.025);
    border:1px solid rgba(0,255,65,.18);
    border-radius:4px;
    padding:.85rem 1rem;
    margin:1.4rem 0 .9rem;
  }
  .ll { font-size:.66rem; line-height:1.95; color:var(--green); opacity:0; transition:opacity .3s; }
  .ll.ok::after   { content:' [OK]';   color:var(--cyan); }
  .ll.warn::after { content:' [WARN]'; color:#FFD700; }

  /* Progress bar */
  .pbar { width:min(460px,88vw); }
  .ph   { display:flex; justify-content:space-between; font-size:.58rem; letter-spacing:.14em; color:rgba(0,255,255,.45); margin-bottom:.35rem; }
  .track { height:3px; background:rgba(0,255,255,.1); border-radius:2px; overflow:hidden; }
  .fill  { height:100%; width:0%; background:linear-gradient(90deg,var(--cyan),var(--green)); box-shadow:0 0 10px var(--cyan); transition:width .08s linear; }

  /* Enter button */
  #enterBtn {
    display:none; margin-top:1.8rem;
    font-family:'Orbitron',sans-serif; font-weight:700; font-size:.78rem;
    letter-spacing:.28em; text-transform:uppercase;
    color:#020810; background:var(--cyan);
    border:none; padding:.8em 2.6em; cursor:pointer;
    clip-path:polygon(10px 0%,100% 0%,calc(100% - 10px) 100%,0% 100%);
    box-shadow:0 0 30px rgba(0,255,255,.4);
    animation:bpulse 1.5s ease-in-out infinite;
    transition:transform .15s;
  }
  #enterBtn:hover { transform:scale(1.05); }
  @keyframes bpulse {
    0%,100%{box-shadow:0 0 28px rgba(0,255,255,.4)}
    50%{box-shadow:0 0 55px rgba(0,255,255,.7)}
  }

  /* Status bar */
  .statusbar {
    position:fixed; bottom:16px; left:50%; transform:translateX(-50%);
    display:flex; align-items:center; gap:1rem;
    font-size:.52rem; letter-spacing:.12em; color:rgba(255,255,255,.2); z-index:20;
  }
  .dot { width:5px; height:5px; border-radius:50%; background:var(--green); box-shadow:0 0 6px var(--green); animation:dblink 1.2s step-end infinite; }
  .dot:nth-child(3){animation-delay:.4s} .dot:nth-child(5){animation-delay:.8s}
  @keyframes dblink { 0%,100%{opacity:1} 50%{opacity:.1} }
</style>
</head>
<body>

<canvas id="m"></canvas>
<div class="corner tl"></div>
<div class="corner tr"></div>
<div class="corner bl"></div>
<div class="corner br"></div>

<div class="wrap">

  <!-- Hex Logo -->
  <div class="hex">
    <div class="orbit"></div>
    <div class="ring"></div>
    <div class="ring"></div>
    <div class="ring"></div>
    <div class="icon">🔍</div>
  </div>

  <!-- Title -->
  <div style="text-align:center; margin-bottom:.2rem;">
    <div class="tag">// classified — authorized access only</div>
    <div class="title">CYBER <span>FORENSIC</span><br>TRIAGE <span>TOOL</span></div>
    <div class="sub">Digital Evidence Analysis Platform</div>
  </div>

  <!-- Boot Log -->
  <div class="log">
    <div class="ll ok"   id="l0">› Initializing threat detection engine</div>
    <div class="ll ok"   id="l1">› Loading signature database [v8.3.2]</div>
    <div class="ll ok"   id="l2">› Mounting forensic analysis modules</div>
    <div class="ll warn" id="l3">› Scanning environment variables</div>
    <div class="ll ok"   id="l4">› Establishing secure sandbox</div>
    <div class="ll ok"   id="l5">› All systems nominal — ready</div>
  </div>

  <!-- Progress Bar -->
  <div class="pbar">
    <div class="ph"><span>SYSTEM BOOT</span><span id="pct">0%</span></div>
    <div class="track"><div class="fill" id="fill"></div></div>
  </div>

  <!-- Enter Button -->
  <button id="enterBtn" onclick="enter()">▶ ENTER SYSTEM</button>

</div>

<!-- Status Bar -->
<div class="statusbar">
  <span>SYS</span><div class="dot"></div>
  <span>NET</span><div class="dot"></div>
  <span>SEC</span><div class="dot"></div>
  <span>v2.4.1</span>
</div>

<script>
  /* ── Matrix Rain ── */
  const cv = document.getElementById('m');
  const cx = cv.getContext('2d');
  cv.width = window.innerWidth;
  cv.height = window.innerHeight;

  const cols = Math.floor(cv.width / 15);
  const drops = Array(cols).fill(1);
  const chars = 'ｱｲｳｴｵｶｷｸｹｺABCDEFGHIJKLM0123456789@#$%^<>/\\';

  function drawMatrix() {
    cx.fillStyle = 'rgba(2,8,16,0.05)';
    cx.fillRect(0, 0, cv.width, cv.height);
    cx.font = '12px Share Tech Mono, monospace';
    drops.forEach((y, i) => {
      const c = chars[Math.floor(Math.random() * chars.length)];
      const x = i * 15;
      const b = Math.random();
      cx.fillStyle = b > 0.95 ? '#ffffff' : b > 0.7 ? '#00FFFF' : '#00FF41';
      cx.fillText(c, x, y * 15);
      if (y * 15 > cv.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    });
  }
  setInterval(drawMatrix, 42);

  /* ── Boot Sequence ── */
  const logDelays = [900, 1700, 2500, 3200, 4000, 4800];
  const pctStops  = [14,  30,   50,   65,   82,   100];
  let curPct = 0;

  const fillEl = document.getElementById('fill');
  const pctEl  = document.getElementById('pct');

  function animateTo(target) {
    const step = () => {
      if (curPct < target) {
        curPct++;
        fillEl.style.width = curPct + '%';
        pctEl.textContent  = curPct + '%';
        requestAnimationFrame(step);
      }
    };
    requestAnimationFrame(step);
  }

  document.querySelectorAll('.ll').forEach((el, i) => {
    setTimeout(() => {
      el.style.opacity = '1';
      animateTo(pctStops[i]);
      if (i === 5) {
        setTimeout(() => {
          document.getElementById('enterBtn').style.display = 'block';
        }, 600);
      }
    }, logDelays[i]);
  });

  /* ── Enter: notify Streamlit ── */
  function enter() {
    window.parent.postMessage({ type: 'streamlit:setComponentValue', value: true }, '*');
  }
</script>
</body>
</html>
"""

# ══════════════════════════════════════════
#  MAIN APP CSS
# ══════════════════════════════════════════
APP_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');

:root {
  --cyan: #00FFFF;
  --cyan-dim: #00bcd4;
  --cyan-glow: rgba(0,255,255,0.15);
  --green: #00FF41;
  --bg: #080B12;
  --surface: #0F1320;
  --raised: #161B2E;
  --border: rgba(0,255,255,0.25);
  --text: #E0F7FA;
  --muted: #607D8B;
}

html, body, [data-testid="stAppViewContainer"] {
  background-color: var(--bg) !important;
  font-family: 'Share Tech Mono', monospace !important;
  color: var(--text);
}

/* Subtle grid + glow background */
[data-testid="stAppViewContainer"]::before {
  content:''; position:fixed; inset:0;
  background:
    radial-gradient(ellipse 80% 40% at 50% -5%, rgba(0,255,255,0.06), transparent),
    repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,255,255,0.025) 40px),
    repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,255,255,0.025) 40px);
  pointer-events:none; z-index:0;
}

[data-testid="stHeader"] { background:transparent !important; }
[data-testid="stSidebar"] { background:var(--surface) !important; border-right:1px solid var(--border); }

/* Title */
h1 {
  font-family:'Orbitron',sans-serif !important;
  font-weight:900 !important;
  font-size:2rem !important;
  letter-spacing:0.1em;
  text-transform:uppercase;
  color:var(--cyan) !important;
  text-align:center;
  text-shadow: 0 0 25px rgba(0,255,255,0.6), 0 0 70px rgba(0,255,255,0.2);
}

h2, h3 {
  font-family:'Orbitron',sans-serif !important;
  font-weight:700;
  color:var(--cyan-dim) !important;
  letter-spacing:0.06em;
}

.subtitle {
  text-align:center;
  font-size:0.62rem;
  letter-spacing:0.35em;
  color:rgba(0,255,255,0.4);
  text-transform:uppercase;
  margin-bottom:1.5rem;
}

hr { border:none; border-top:1px solid var(--border); margin:1.5rem 0; }

/* Text Input */
.stTextInput > label {
  font-size:0.62rem !important;
  letter-spacing:0.2em !important;
  text-transform:uppercase;
  color:rgba(0,255,255,0.6) !important;
}
.stTextInput > div > div > input {
  background:var(--raised) !important;
  color:var(--text) !important;
  border:1px solid var(--border) !important;
  border-radius:4px !important;
  font-family:'Share Tech Mono', monospace;
  font-size:0.88rem;
  transition: border-color .2s, box-shadow .2s;
}
.stTextInput > div > div > input:focus {
  border-color:var(--cyan) !important;
  box-shadow:0 0 0 3px var(--cyan-glow) !important;
}
.stTextInput > div > div > input::placeholder { color:var(--muted); }

/* Buttons */
.stButton > button {
  background:linear-gradient(135deg, rgba(0,255,255,0.08), rgba(0,188,212,0.12)) !important;
  color:var(--cyan) !important;
  font-family:'Orbitron', sans-serif !important;
  font-weight:700 !important;
  font-size:0.78rem !important;
  letter-spacing:0.22em !important;
  text-transform:uppercase;
  border:1px solid var(--cyan) !important;
  border-radius:4px !important;
  height:3em; width:100%;
  transition:all .2s;
  box-shadow:0 0 12px rgba(0,255,255,0.08);
}
.stButton > button:hover {
  background:linear-gradient(135deg, rgba(0,255,255,0.18), rgba(0,188,212,0.24)) !important;
  color:#fff !important;
  box-shadow:0 0 30px rgba(0,255,255,0.35), 0 0 70px rgba(0,255,255,0.1) !important;
  transform:translateY(-1px);
}
.stButton > button:active { transform:translateY(0); }

/* Alerts */
.stAlert { border-radius:4px !important; font-family:'Share Tech Mono',monospace !important; }
[data-testid="stSuccess"] { border-left:3px solid var(--green) !important; background:rgba(0,255,65,0.05) !important; }
[data-testid="stError"]   { border-left:3px solid #FF0044 !important; background:rgba(255,0,68,0.05) !important; }
[data-testid="stWarning"] { border-left:3px solid #FFD700 !important; background:rgba(255,215,0,0.05) !important; }

/* Text */
[data-testid="stMarkdownContainer"] p { font-family:'Share Tech Mono',monospace !important; font-size:0.82rem !important; }

/* Result lines */
.result-file { color:#FFD700; font-size:0.78rem; padding:0.2rem 0; font-family:'Share Tech Mono',monospace; }

/* Scrollbar */
::-webkit-scrollbar { width:5px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:rgba(0,255,255,0.2); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:rgba(0,255,255,0.45); }
</style>
"""


# ══════════════════════════════════════════
#  APP LOGIC
# ══════════════════════════════════════════

if not st.session_state.splashed:
    # ── Hide Streamlit default chrome ──
    st.markdown("""
    <style>
      [data-testid="stAppViewContainer"] { padding:0 !important; }
      [data-testid="stHeader"] { display:none; }
      footer { display:none; }
      .block-container { padding:0 !important; max-width:100% !important; }
    </style>
    """, unsafe_allow_html=True)

    # ── Show animated splash inside Streamlit ──
    components.html(SPLASH_HTML, height=680, scrolling=False)

    # ── Streamlit button below the animation ──
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("▶  ENTER SYSTEM", key="enter_btn"):
            st.session_state.splashed = True
            st.rerun()

    st.markdown(
        "<p style='text-align:center;font-size:0.6rem;letter-spacing:0.2em;"
        "color:rgba(0,255,255,0.25);font-family:Share Tech Mono,monospace;'>"
        "WAIT FOR BOOT SEQUENCE · THEN CLICK ENTER</p>",
        unsafe_allow_html=True
    )

else:
    # ── Main App ──
    st.markdown(APP_CSS, unsafe_allow_html=True)

    st.title("CYBER FORENSIC TRIAGE TOOL")
    st.markdown('<p class="subtitle">Digital Evidence Analysis Platform</p>', unsafe_allow_html=True)
    st.markdown("<hr>", unsafe_allow_html=True)

    folder_path = st.text_input(
        "Target Directory Path",
        placeholder="/path/to/scan/directory"
    )

    col1, col2 = st.columns([3, 1])
    with col1:
        scan_clicked = st.button("⬡  INITIATE SCAN")
    with col2:
        if st.button("↩  RESET"):
            st.session_state.splashed = False
            st.rerun()

    if scan_clicked:
        if not folder_path:
            st.error("› ERROR: No target path specified.")
        elif not os.path.exists(folder_path):
            st.error("› ERROR: Path does not exist. Verify target directory.")
        else:
            suspicious_files = []
            suspicious_ext = (".exe", ".bat", ".vbs", ".ps1", ".cmd", ".scr", ".jar", ".dll")

            with st.spinner("› Scanning directory tree..."):
                time.sleep(0.6)
                for root, dirs, files in os.walk(folder_path):
                    for file in files:
                        if file.lower().endswith(suspicious_ext):
                            suspicious_files.append(os.path.join(root, file))

            st.markdown("<hr>", unsafe_allow_html=True)
            st.markdown("**› SCAN RESULTS**", unsafe_allow_html=True)

            if suspicious_files:
                st.warning(f"⚠  {len(suspicious_files)} suspicious file(s) detected:")
                for f in suspicious_files:
                    st.markdown(f'<div class="result-file">⬡ {f}</div>', unsafe_allow_html=True)
            else:
                st.success("✓  No suspicious files found. Directory is clean.")
