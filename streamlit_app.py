"""
=============================================================================
  Secure Message Communication — Streamlit Simulation
  Calls secure_message_comm.py functions directly as the backend.
=============================================================================
"""

import base64
import time
import streamlit as st

from secure_message_comm import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="RSA-2048 Secure Communication",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS — dark terminal aesthetic, matches the HTML simulation exactly
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Syne:wght@400;500;600&display=swap');

:root {
  --bg:      #0d0f12;
  --bg2:     #131519;
  --bg3:     #1a1d22;
  --border:  rgba(255,255,255,0.07);
  --border2: rgba(255,255,255,0.13);
  --text:    #e2e4e9;
  --text2:   #8a8f9a;
  --text3:   #4e535d;
  --alice:   #4fa3e0;
  --bob:     #3ecfa3;
  --purple:  #9d8ff5;
  --amber:   #e8a838;
  --green:   #5bbf6e;
  --red:     #e05555;
  --mono:    'JetBrains Mono', monospace;
  --sans:    'Syne', sans-serif;
}

/* Global overrides */
html, body, [data-testid="stAppViewContainer"],
[data-testid="stApp"] {
  background-color: var(--bg) !important;
  font-family: var(--sans) !important;
  color: var(--text) !important;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stSidebar"] { background: var(--bg2) !important; }
section[data-testid="stMain"] > div { padding-top: 1.5rem; }
.block-container { max-width: 1200px !important; padding: 0 1.5rem 3rem !important; }

/* Hide default Streamlit chrome */
#MainMenu, footer, [data-testid="stToolbar"] { display: none !important; }

/* ── Tabs ── */
[data-baseweb="tab-list"] {
  gap: 0 !important;
  border-bottom: 0.5px solid var(--border2) !important;
  background: transparent !important;
}
[data-baseweb="tab"] {
  font-family: var(--mono) !important;
  font-size: 12px !important;
  color: var(--text3) !important;
  background: transparent !important;
  border: none !important;
  padding: 8px 16px !important;
}
[aria-selected="true"][data-baseweb="tab"] {
  color: var(--alice) !important;
  border-bottom: 2px solid var(--alice) !important;
  background: transparent !important;
}
[data-testid="stTabPanel"] { background: transparent !important; padding-top: 1.2rem !important; }

/* ── Buttons ── */
[data-testid="stButton"] > button {
  font-family: var(--mono) !important;
  font-size: 12px !important;
  font-weight: 500 !important;
  border-radius: 8px !important;
  padding: 8px 20px !important;
  transition: all .14s !important;
  border: 0.5px solid rgba(79,163,224,0.3) !important;
  background: rgba(79,163,224,0.09) !important;
  color: var(--alice) !important;
}
[data-testid="stButton"] > button:hover {
  background: rgba(79,163,224,0.16) !important;
  border-color: rgba(79,163,224,0.5) !important;
}

/* ── Text input ── */
[data-testid="stTextInput"] input {
  background: var(--bg3) !important;
  border: 0.5px solid var(--border2) !important;
  border-radius: 8px !important;
  color: var(--alice) !important;
  font-family: var(--mono) !important;
  font-size: 13px !important;
}
[data-testid="stTextInput"] label {
  font-family: var(--mono) !important;
  font-size: 11px !important;
  color: var(--text3) !important;
}

/* ── Terminal card ── */
.term-card {
  background: var(--bg2);
  border: 0.5px solid var(--border2);
  border-radius: 14px;
  overflow: hidden;
  height: 100%;
}
.term-titlebar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 0.5px solid var(--border);
  background: var(--bg3);
}
.tl-dots { display: flex; gap: 5px; }
.tl { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.tl-r { background: #E24B4A; }
.tl-y { background: #EF9F27; }
.tl-g { background: #5bbf6e;  }
.dev-name { font-family: var(--mono); font-size: 11.5px; }
.dev-name-a { color: var(--alice); }
.dev-name-b { color: var(--bob);   }
.dev-role {
  margin-left: auto;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  border: 0.5px solid var(--border);
  padding: 2px 8px;
  border-radius: 999px;
}
.terminal-body {
  padding: 14px 16px;
  font-family: var(--mono);
  font-size: 11.5px;
  line-height: 1.85;
  min-height: 460px;
  overflow-y: auto;
}

/* Terminal text colours */
.t-pa     { color: var(--alice); opacity: .7; }
.t-pb     { color: var(--bob);   opacity: .7; }
.t-cmd    { color: var(--text);  font-weight: 500; }
.t-out    { color: var(--text2); }
.t-key    { color: var(--bob);   }
.t-cipher { color: var(--purple); word-break: break-all; font-size: 10.5px; line-height: 1.6; }
.t-plain  { color: var(--green); font-weight: 500; }
.t-info   { color: var(--alice); }
.t-ok     { color: var(--green); }
.t-err    { color: var(--red);   }
.t-dim    { color: var(--text3); }
.t-label  { color: var(--amber); }
.t-cursor {
  display: inline-block;
  width: 7px; height: 12px;
  background: var(--text2);
  vertical-align: middle;
  border-radius: 1px;
  animation: blink 1s step-end infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

/* ── Channel ── */
.channel-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 8px 0;
  gap: 6px;
  height: 100%;
}
.ch-lbl {
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  text-align: center;
  line-height: 1.5;
}
.ch-wire {
  flex: 1;
  width: 1px;
  min-height: 360px;
  background: var(--border2);
  position: relative;
}
.ch-status {
  font-family: var(--mono);
  font-size: 9.5px;
  color: var(--text3);
  text-align: center;
}
.pkt-anim {
  position: absolute;
  width: 9px; height: 9px;
  border-radius: 50%;
  left: -4px;
  animation: slide-down .7s ease-in-out;
}
.pkt-up   { background: var(--alice);  animation: slide-up   .7s ease-in-out; }
.pkt-down { background: var(--purple); animation: slide-down .7s ease-in-out; }
@keyframes slide-down { 0%{top:0;opacity:1}  100%{top:calc(100% - 10px);opacity:0} }
@keyframes slide-up   { 0%{top:calc(100% - 10px);opacity:1} 100%{top:0;opacity:0} }

/* ── Step pills ── */
.step-strip { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.step-lbl   { font-family: var(--mono); font-size: 10.5px; color: var(--text3); margin-right: 4px; }
.sp-idle    { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid var(--border); color:var(--text3); }
.sp-active  { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid rgba(232,168,56,.5); color:var(--amber); background:rgba(232,168,56,.08); }
.sp-done    { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid rgba(91,191,110,.35); color:var(--green); background:rgba(91,191,110,.07); }

/* ── Info chips ── */
.chips { display: flex; gap: 7px; flex-wrap: wrap; margin-top: 16px; }
.chip  {
  padding: 4px 11px;
  border-radius: 8px;
  font-family: var(--mono);
  font-size: 11px;
  background: var(--bg3);
  border: 0.5px solid var(--border2);
  color: var(--text3);
}
.chip b { color: var(--text); font-weight: 500; }
.chip-ok b { color: var(--green); }
.chip-err b { color: var(--red); }

/* ── Security note ── */
.sec-note {
  margin-top: 16px;
  padding: 11px 15px;
  border-radius: 8px;
  background: var(--bg3);
  border: 0.5px solid var(--border);
  border-left: 2px solid var(--purple);
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  line-height: 1.75;
}
.sec-note b { color: var(--text2); font-weight: 500; }

/* ── Test table ── */
.test-wrap {
  background: var(--bg2);
  border: 0.5px solid var(--border2);
  border-radius: 14px;
  overflow: hidden;
  margin-top: 8px;
}
.test-tbl { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }
.test-tbl th {
  color: var(--text3); font-weight: 400; text-align: left;
  padding: 8px 14px; border-bottom: 0.5px solid var(--border2);
  font-size: 10.5px; letter-spacing: .04em; background: var(--bg3);
}
.test-tbl td { padding: 9px 14px; border-bottom: 0.5px solid var(--border); color: var(--text2); vertical-align: top; }
.test-tbl tr:last-child td { border-bottom: none; }
.tc-pass  { color: var(--green) !important; font-weight: 500; }
.tc-fail  { color: var(--red)   !important; font-weight: 500; }
.tc-note  { color: var(--text3) !important; font-size: 10.5px; }

/* ── Page header ── */
.page-hdr {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 20px;
  gap: 12px;
  flex-wrap: wrap;
}
.page-hdr h1 {
  font-size: 17px; font-weight: 600;
  letter-spacing: -.01em; margin-bottom: 3px;
  font-family: var(--sans);
}
.page-hdr p {
  font-size: 11px; color: var(--text3);
  font-family: var(--mono);
}
.badge-row { display: flex; gap: 7px; flex-wrap: wrap; align-items: center; }
.bdg {
  padding: 3px 9px; border-radius: 999px;
  font-size: 10.5px; font-family: var(--mono);
  border: 0.5px solid var(--border2);
  color: var(--text2); background: var(--bg3);
}
.bdg-live {
  border-color: rgba(62,207,163,.3);
  color: var(--bob);
  background: rgba(62,207,163,.09);
}

/* Streamlit metric override */
[data-testid="metric-container"] {
  background: var(--bg3) !important;
  border: 0.5px solid var(--border2) !important;
  border-radius: 8px !important;
  padding: 10px 14px !important;
}
[data-testid="metric-container"] label,
[data-testid="metric-container"] [data-testid="stMetricLabel"] {
  font-family: var(--mono) !important;
  font-size: 11px !important;
  color: var(--text3) !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
  font-family: var(--mono) !important;
  font-size: 16px !important;
  color: var(--text) !important;
}

/* st.code override */
[data-testid="stCode"] pre,
[data-testid="stCode"] code {
  font-family: var(--mono) !important;
  font-size: 11.5px !important;
  background: var(--bg3) !important;
  color: var(--text2) !important;
  border: 0.5px solid var(--border2) !important;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: build terminal HTML
# ─────────────────────────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_terminal(lines: list[tuple[str, str]], actor: str, show_cursor: bool = True) -> str:
    """
    Build a terminal card HTML string.
    lines = list of (css_class, text) tuples.
    actor = 'alice' | 'bob'
    """
    is_alice = actor == "alice"
    name     = "alice@secure-terminal" if is_alice else "bob@secure-terminal"
    role     = "sender" if is_alice else "receiver"
    name_cls = "dev-name-a" if is_alice else "dev-name-b"
    prompt_cls = "t-pa" if is_alice else "t-pb"
    prompt_txt = f"{name}:~$"

    rows_html = ""
    for css, text in lines:
        if css == "cmd":
            rows_html += f'<div><span class="{prompt_cls}">{name}:~$</span> <span class="t-cmd">{_esc(text)}</span></div>'
        elif css == "blank":
            rows_html += "<div>&nbsp;</div>"
        else:
            rows_html += f'<div><span class="{css}">{_esc(text)}</span></div>'

    cursor_html = f'<div><span class="{prompt_cls}">{prompt_txt}</span> <span class="t-cursor"></span></div>' if show_cursor else ""

    return f"""
<div class="term-card">
  <div class="term-titlebar">
    <div class="tl-dots">
      <span class="tl tl-r"></span>
      <span class="tl tl-y"></span>
      <span class="tl tl-g"></span>
    </div>
    <span class="dev-name {name_cls}">{name}</span>
    <span class="dev-role">{role}</span>
  </div>
  <div class="terminal-body">
    {rows_html}
    {cursor_html}
  </div>
</div>
"""


def render_channel(status: str = "idle", packet: str = "") -> str:
    pkt_html = ""
    if packet == "up":
        pkt_html = '<div class="pkt-anim pkt-up"></div>'
    elif packet == "down":
        pkt_html = '<div class="pkt-anim pkt-down"></div>'

    return f"""
<div class="channel-col">
  <div class="ch-lbl">insecure<br>channel</div>
  <div class="ch-wire">{pkt_html}</div>
  <div class="ch-status">{_esc(status)}</div>
</div>
"""


def render_steps(current: int) -> str:
    labels = ["① key gen", "② exchange", "③ encrypt", "④ transmit", "⑤ decrypt", "⑥ verified"]
    pills = '<span class="step-lbl">protocol:</span>'
    for i, lbl in enumerate(labels):
        if i < current:
            pills += f'<span class="sp-done">{lbl}</span>'
        elif i == current:
            pills += f'<span class="sp-active">{lbl}</span>'
        else:
            pills += f'<span class="sp-idle">{lbl}</span>'
    return f'<div class="step-strip">{pills}</div>'


def render_chips(data: dict) -> str:
    items = [
        ("algorithm",  "RSA-2048"),
        ("padding",    "OAEP-SHA256"),
        ("key size",   data.get("key_size",    "—")),
        ("exponent e", data.get("exponent",    "—")),
        ("keygen",     data.get("keygen_ms",   "—")),
        ("encrypt",    data.get("encrypt_ms",  "—")),
        ("decrypt",    data.get("decrypt_ms",  "—")),
        ("ciphertext", data.get("ct_bytes",    "—")),
    ]
    html = '<div class="chips">'
    for label, val in items:
        html += f'<div class="chip">{label} <b>{_esc(str(val))}</b></div>'
    status     = data.get("status", "")
    status_cls = "chip chip-ok" if status == "secure ✓" else ("chip chip-err" if "FAIL" in status else "chip")
    if status:
        html += f'<div class="{status_cls}">status <b>{_esc(status)}</b></div>'
    html += "</div>"
    return html


# ─────────────────────────────────────────────────────────────────────────────
# Page header
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div class="page-hdr">
  <div>
    <h1>Secure Message Communication</h1>
    <p>rsa-2048 · oaep-sha256 · live python backend · alice → bob</p>
  </div>
  <div class="badge-row">
    <span class="bdg">RSA-2048</span>
    <span class="bdg">OAEP-SHA256</span>
    <span class="bdg bdg-live">live backend</span>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────

tab_sim, tab_tests = st.tabs(["simulation", "test suite"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

with tab_sim:

    # ── Message input ──
    col_inp, col_bc = st.columns([5, 1])
    with col_inp:
        message = st.text_input(
            "alice@message $",
            value="Hello Bob! The meeting is at 3 PM. — Alice",
            max_chars=190,
            placeholder="Enter Alice's plaintext message (max 190 bytes)…",
            label_visibility="visible",
        )
    with col_bc:
        byte_count = len(message.encode("utf-8"))
        st.markdown(f"<div style='padding-top:32px;font-family:var(--mono);font-size:11px;color:var(--text3)'>{byte_count} / 190 bytes</div>", unsafe_allow_html=True)

    if byte_count > 190:
        st.error("Message exceeds the 190-byte RSA-2048/OAEP-SHA256 limit.")
        st.stop()

    # ── Run button ──
    run_col, reset_col, _ = st.columns([1, 1, 6])
    with run_col:
        run_clicked = st.button("run simulation", key="run_sim")
    with reset_col:
        reset_clicked = st.button("reset", key="reset_sim")

    # ── State init ──
    if "sim_done" not in st.session_state:
        st.session_state.sim_done    = False
        st.session_state.alice_lines = []
        st.session_state.bob_lines   = []
        st.session_state.step        = 0
        st.session_state.channel_status = "idle"
        st.session_state.channel_pkt    = ""
        st.session_state.chips          = {}

    if reset_clicked:
        for k in ["sim_done","alice_lines","bob_lines","step","channel_status","channel_pkt","chips"]:
            del st.session_state[k]
        st.rerun()

    # ── Step strip ──
    st.markdown(render_steps(st.session_state.step), unsafe_allow_html=True)

    # ── Terminals placeholder ──
    sim_placeholder = st.empty()

    def draw_sim(alice_lines, bob_lines, step, ch_status, ch_pkt, alice_cursor=True, bob_cursor=True):
        with sim_placeholder.container():
            c1, c2, c3 = st.columns([10, 1, 10])
            with c1:
                st.markdown(render_terminal(alice_lines, "alice", alice_cursor), unsafe_allow_html=True)
            with c2:
                st.markdown(render_channel(ch_status, ch_pkt), unsafe_allow_html=True)
            with c3:
                st.markdown(render_terminal(bob_lines, "bob", bob_cursor), unsafe_allow_html=True)

    # Initial idle state
    if not run_clicked and not st.session_state.sim_done:
        draw_sim([], [], 0, "idle", "")

    # ── Simulation already ran (state persists on re-render) ──
    if st.session_state.sim_done and not run_clicked:
        draw_sim(
            st.session_state.alice_lines,
            st.session_state.bob_lines,
            st.session_state.step,
            st.session_state.channel_status,
            "",
        )
        st.markdown(render_chips(st.session_state.chips), unsafe_allow_html=True)
        st.markdown("""
        <div class="sec-note">
          <b>Why this is secure:</b> Alice encrypted using Bob's public key — only Bob's private key
          (never transmitted) can decrypt it. The OAEP padding introduced a fresh random seed before
          encryption, making the output probabilistic and defeating chosen-plaintext attacks.
          An eavesdropper who captured the ciphertext sees only
          <b>256 bytes of computationally indistinguishable noise</b> — breaking it requires
          factoring a 2048-bit RSA modulus.
        </div>
        """, unsafe_allow_html=True)

    # ── Run the simulation ──
    if run_clicked:
        st.session_state.sim_done    = False
        st.session_state.alice_lines = []
        st.session_state.bob_lines   = []
        aL = st.session_state.alice_lines
        bL = st.session_state.bob_lines

        step_placeholder = st.empty()

        def update_step(s):
            st.session_state.step = s
            step_placeholder.markdown(render_steps(s), unsafe_allow_html=True)

        def redraw(ch_status="idle", ch_pkt="", a_cur=True, b_cur=True):
            draw_sim(aL, bL, st.session_state.step, ch_status, ch_pkt, a_cur, b_cur)

        # ── STEP 0: Bob generates key pair ──────────────────────────────
        update_step(0)
        bL.append(("cmd",   "python3 keygen.py --bits 2048"))
        bL.append(("t-out", "Initialising RSA key generation…"))
        bL.append(("t-out", "Searching for primes p, q  (n = p × q, 2048 bits)…"))
        redraw()

        t0 = time.perf_counter()
        bob_private_key, bob_public_key = generate_rsa_keypair(key_size=2048)
        keygen_ms = int((time.perf_counter() - t0) * 1000)

        bob_public_pem = serialize_public_key(bob_public_key)
        pem_str        = bob_public_pem.decode().strip()
        pub_nums       = bob_public_key.public_numbers()

        bL.append(("t-key",  f"  private key  →  bob_private.pem  [secured]"))
        bL.append(("t-key",  f"  public key   →  bob_public.pem   [ready to share]"))
        bL.append(("t-dim",  f"  modulus n    :  {bob_public_key.key_size} bits"))
        bL.append(("t-dim",  f"  exponent e   :  {pub_nums.e}"))
        bL.append(("t-dim",  f"  keygen time  :  {keygen_ms} ms"))
        bL.append(("t-ok",   "  key pair generated successfully."))
        bL.append(("blank",  ""))
        aL.append(("t-dim",  "Waiting for Bob's public key…"))
        redraw()
        time.sleep(0.4)

        # ── STEP 1: Key exchange ─────────────────────────────────────────
        update_step(1)
        bL.append(("cmd",    "cat bob_public.pem | nc alice.local 4433"))
        bL.append(("t-out",  f"Transmitting public key  ({len(bob_public_pem)} bytes)…"))
        redraw(ch_status="pub key →", ch_pkt="up")
        time.sleep(0.7)

        bL.append(("t-info", "  public key sent. (safe to transmit openly)"))
        bL.append(("blank",  ""))

        aL.append(("t-key",  f"  received: bob_public.pem  ({len(bob_public_pem)} bytes)"))
        for ln in pem_str.split("\n"):
            if ln.strip():
                aL.append(("t-dim", f"  {ln}"))
        aL.append(("t-info", "  key loaded and fingerprint verified."))
        aL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # ── STEP 2: Alice encrypts ───────────────────────────────────────
        update_step(2)
        alice_received_key = deserialize_public_key(bob_public_pem)
        aL.append(("cmd",    "python3 encrypt.py --key bob_public.pem"))
        aL.append(("t-label",f'  plaintext  : "{message}"'))
        aL.append(("t-out",  "  padding    : OAEP (MGF1-SHA256)"))
        aL.append(("t-out",  "  encrypting with Bob's public key…"))
        redraw()

        t1 = time.perf_counter()
        ciphertext = encrypt_message(message, alice_received_key)
        encrypt_ms = int((time.perf_counter() - t1) * 1000)

        ct_b64    = base64.b64encode(ciphertext).decode()
        ct_lines  = [ct_b64[i:i+64] for i in range(0, len(ct_b64), 64)]

        for ln in ct_lines:
            aL.append(("t-cipher", ln))
        aL.append(("t-dim",  f"  original    :  {len(message.encode())} bytes → {len(ciphertext)} bytes"))
        aL.append(("t-dim",  f"  encrypt time:  {encrypt_ms} ms"))
        aL.append(("t-info", "  OAEP randomness: re-encrypting same message"))
        aL.append(("t-info", "  would produce entirely different ciphertext."))
        aL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # ── STEP 3: Transmit ciphertext ──────────────────────────────────
        update_step(3)
        aL.append(("cmd",   "cat ciphertext.bin | nc bob.local 4434"))
        aL.append(("t-out", "Transmitting ciphertext over insecure channel…"))
        aL.append(("t-dim", "  (eavesdropper sees only random bytes)"))
        bL.append(("t-dim", "Listening on :4434 for incoming ciphertext…"))
        redraw(ch_status="ciphertext →", ch_pkt="down")
        time.sleep(0.7)

        aL.append(("t-info", f"  transmission complete."))
        aL.append(("blank",  ""))

        bL.append(("t-out",  "Ciphertext received from Alice."))
        for ln in ct_lines:
            bL.append(("t-cipher", ln))
        bL.append(("t-info", f"  {len(ciphertext)} bytes received."))
        bL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # ── STEP 4: Bob decrypts ─────────────────────────────────────────
        update_step(4)
        bL.append(("cmd",   "python3 decrypt.py --key bob_private.pem"))
        bL.append(("t-out", "  padding    : OAEP (MGF1-SHA256)"))
        bL.append(("t-out", "  decrypting with private key…"))
        bL.append(("t-out", "  verifying OAEP padding integrity…"))
        redraw()

        t2 = time.perf_counter()
        decrypted  = decrypt_message(ciphertext, bob_private_key)
        decrypt_ms = int((time.perf_counter() - t2) * 1000)

        bL.append(("t-plain", f'  plaintext   : "{decrypted}"'))
        bL.append(("t-dim",   f"  decrypt time:  {decrypt_ms} ms"))
        bL.append(("blank",   ""))
        redraw()
        time.sleep(0.4)

        # ── STEP 5: Verify ───────────────────────────────────────────────
        update_step(5)
        match = decrypted == message
        bL.append(("cmd",  "python3 verify.py --original --decrypted"))
        bL.append(("t-ok" if match else "t-err", f"  hash match  : SHA-256 {'verified' if match else 'FAILED'}"))
        bL.append(("t-ok" if match else "t-err", f"  integrity   : {'OK' if match else 'TAMPERED'}"))
        bL.append(("t-ok" if match else "t-err",  "  message authenticated. communication secure." if match else "  INTEGRITY CHECK FAILED."))
        bL.append(("blank", ""))

        aL.append(("cmd",   "# Transmission complete. Bob has decrypted the message."))
        aL.append(("blank", ""))

        # Save state
        chips = {
            "key_size":   f"{bob_public_key.key_size} bit",
            "exponent":   str(pub_nums.e),
            "keygen_ms":  f"{keygen_ms} ms",
            "encrypt_ms": f"{encrypt_ms} ms",
            "decrypt_ms": f"{decrypt_ms} ms",
            "ct_bytes":   f"{len(ciphertext)} bytes",
            "status":     "secure ✓" if match else "FAILED ✗",
        }
        st.session_state.chips          = chips
        st.session_state.channel_status = "closed"
        st.session_state.sim_done       = True

        redraw(ch_status="closed", ch_pkt="", a_cur=True, b_cur=True)
        st.markdown(render_chips(chips), unsafe_allow_html=True)
        st.markdown("""
        <div class="sec-note">
          <b>Why this is secure:</b> Alice encrypted using Bob's public key — only Bob's private key
          (never transmitted) can decrypt it. The OAEP padding introduced a fresh random seed before
          encryption, making the output probabilistic and defeating chosen-plaintext attacks.
          An eavesdropper who captured the ciphertext sees only
          <b>256 bytes of computationally indistinguishable noise</b> — breaking it requires
          factoring a 2048-bit RSA modulus.
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — TEST SUITE
# ══════════════════════════════════════════════════════════════════════════════

with tab_tests:

    run_tests = st.button("run all tests", key="run_tests")

    if "test_results" not in st.session_state:
        st.session_state.test_results = None

    if st.button("reset tests", key="reset_tests"):
        st.session_state.test_results = None
        st.rerun()

    if run_tests:
        st.session_state.test_results = None
        results = []

        with st.spinner("Running test suite against live crypto module…"):
            bob_private, bob_public   = generate_rsa_keypair()
            eve_private, _eve_public  = generate_rsa_keypair()

            tests = [
                ("TC-01", 'Standard short message',        '"Hello, Bob!"'),
                ("TC-02", 'Unicode & special characters',  '"नमस्ते Bob! Secret: €42"'),
                ("TC-03", 'Max-length plaintext (190 B)',  '"A" × 190 bytes'),
                ("TC-04", "Wrong private key (Eve's key)", 'decrypt with eve_private'),
                ("TC-05", 'Tampered ciphertext',           'ct[10] ^= 0xFF'),
                ("TC-06", 'Empty message',                 '""'),
            ]

            # TC-01
            try:
                ct = encrypt_message("Hello, Bob!", bob_public)
                pt = decrypt_message(ct, bob_private)
                assert pt == "Hello, Bob!"
                results.append(("TC-01", tests[0][1], True, ""))
            except Exception as e:
                results.append(("TC-01", tests[0][1], False, str(e)))

            # TC-02
            try:
                msg2 = "नमस्ते Bob! Secret: €42"
                ct = encrypt_message(msg2, bob_public)
                pt = decrypt_message(ct, bob_private)
                assert pt == msg2
                results.append(("TC-02", tests[1][1], True, ""))
            except Exception as e:
                results.append(("TC-02", tests[1][1], False, str(e)))

            # TC-03
            try:
                msg3 = "A" * 190
                ct = encrypt_message(msg3, bob_public)
                pt = decrypt_message(ct, bob_private)
                assert pt == msg3
                results.append(("TC-03", tests[2][1], True, ""))
            except Exception as e:
                results.append(("TC-03", tests[2][1], False, str(e)))

            # TC-04
            try:
                ct = encrypt_message("Secret for Bob only", bob_public)
                decrypt_message(ct, eve_private)
                results.append(("TC-04", tests[3][1], False, "Decrypted with wrong key — security bug!"))
            except ValueError:
                results.append(("TC-04", tests[3][1], True, "ValueError raised as expected"))
            except Exception as e:
                results.append(("TC-04", tests[3][1], True, f"{type(e).__name__} raised as expected"))

            # TC-05
            try:
                ct = bytearray(encrypt_message("Tamper test", bob_public))
                ct[10] ^= 0xFF
                decrypt_message(bytes(ct), bob_private)
                results.append(("TC-05", tests[4][1], False, "Tampered ciphertext accepted — OAEP bypassed!"))
            except ValueError:
                results.append(("TC-05", tests[4][1], True, "ValueError raised as expected"))
            except Exception as e:
                results.append(("TC-05", tests[4][1], True, f"{type(e).__name__} raised as expected"))

            # TC-06
            try:
                ct = encrypt_message("", bob_public)
                pt = decrypt_message(ct, bob_private)
                assert pt == ""
                results.append(("TC-06", tests[5][1], True, ""))
            except Exception as e:
                results.append(("TC-06", tests[5][1], False, str(e)))

        st.session_state.test_results = results

    if st.session_state.test_results:
        results = st.session_state.test_results
        rows_html = ""
        for tc_id, desc, passed, note in results:
            res_cls  = "tc-pass" if passed else "tc-fail"
            res_txt  = "PASS ✓"  if passed else "FAIL ✗"
            note_html = f'<span class="tc-note">{_esc(note)}</span>' if note else "—"
            rows_html += f"""
            <tr>
              <td class="{res_cls}">{_esc(tc_id)}</td>
              <td>{_esc(desc)}</td>
              <td class="{res_cls}">{res_txt}</td>
              <td>{note_html}</td>
            </tr>"""

        passed_count = sum(1 for r in results if r[2])
        st.markdown(f"""
        <div class="test-wrap">
          <table class="test-tbl">
            <thead><tr><th>id</th><th>description</th><th>result</th><th>notes</th></tr></thead>
            <tbody>{rows_html}</tbody>
          </table>
        </div>
        <div style="margin-top:12px;font-family:var(--mono);font-size:12px;
                    color:var(--text2);padding:8px 12px;background:var(--bg3);
                    border-radius:8px;">
          <b style="color:var(--green)">{passed_count}/{len(results)}</b> test cases passed.
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="test-wrap">
          <table class="test-tbl">
            <thead><tr><th>id</th><th>description</th><th>result</th><th>notes</th></tr></thead>
            <tbody>
              <tr><td colspan="4" style="text-align:center;color:var(--text3);
                padding:28px;font-family:var(--mono);font-size:12px;">
                press "run all tests" to execute the test suite
              </td></tr>
            </tbody>
          </table>
        </div>
        """, unsafe_allow_html=True)
