"""
=============================================================================
  Secure Message Communication - Streamlit Simulation
  RSA-2048 (Encryption) + ECC SECP384R1 (Digital Signatures)
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

from secure_ecc_comm import (
    generate_ecc_keypair,
    serialize_ecc_public_key,
    deserialize_ecc_public_key,
    sign_message,
    verify_signature,
)

# -----------------------------------------------------------------------------
# Page config
# -----------------------------------------------------------------------------

st.set_page_config(
    page_title="RSA + ECC Secure Comm",
    page_icon="-",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# -----------------------------------------------------------------------------
# CSS - dark terminal aesthetic
# -----------------------------------------------------------------------------

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2-family=JetBrains+Mono:wght@400;500&family=Syne:wght@400;500;600&display=swap');

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

/* -- Tabs -- */
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

/* -- Buttons -- */
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

/* -- Text input -- */
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

/* -- Terminal card -- */
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
  min-height: 600px;
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

/* -- Channel -- */
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

/* -- Step pills -- */
.step-strip { display: flex; gap: 5px; flex-wrap: wrap; align-items: center; margin-bottom: 14px; }
.step-lbl   { font-family: var(--mono); font-size: 10.5px; color: var(--text3); margin-right: 4px; }
.sp-idle    { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid var(--border); color:var(--text3); }
.sp-active  { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid rgba(232,168,56,.5); color:var(--amber); background:rgba(232,168,56,.08); }
.sp-done    { padding:3px 11px; border-radius:999px; font-size:10.5px; font-family:var(--mono); border:0.5px solid rgba(91,191,110,.35); color:var(--green); background:rgba(91,191,110,.07); }

/* -- Info chips -- */
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

/* -- Security note -- */
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

/* -- Test table -- */
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

/* -- Page header -- */
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
.bdg-alg {
  border-color: rgba(79,163,224,.3);
  color: var(--alice);
  background: rgba(79,163,224,.09);
}

</style>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Helper: build terminal HTML
# -----------------------------------------------------------------------------

def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def render_terminal(lines: list[tuple[str, str]], actor: str, show_cursor: bool = True) -> str:
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
    labels = ["1. key gen", "2. exchange", "3. enc & sign", "4. transmit", "5. dec & ver", "6. verified"]
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
        ("encryption", "RSA-2048-OAEP"),
        ("signature",  "ECC-SECP384R1"),
        ("rsa keygen", data.get("rsa_keygen_ms",   "--")),
        ("ecc keygen", data.get("ecc_keygen_ms",   "--")),
        ("encrypt",    data.get("encrypt_ms",  "--")),
        ("decrypt",    data.get("decrypt_ms",  "--")),
        ("payload",    data.get("payload_bytes",    "--")),
    ]
    html = '<div class="chips">'
    for label, val in items:
        html += f'<div class="chip">{label} <b>{_esc(str(val))}</b></div>'
    status     = data.get("status", "")
    status_cls = "chip chip-ok" if "secure" in status else ("chip chip-err" if "FAIL" in status else "chip")
    if status:
        html += f'<div class="{status_cls}">status <b>{_esc(status)}</b></div>'
    html += "</div>"
    return html


# -----------------------------------------------------------------------------
# Page header
# -----------------------------------------------------------------------------

st.markdown("""
<div class="page-hdr">
  <div>
    <h1>RSA + ECC Secure Protocol</h1>
    <p>RSA-2048 (Encryption / OAEP / SHA-256) + ECC-ECDSA (Digital Signatures)</p>
  </div>
  <div class="badge-row">
    <span class="bdg bdg-alg">RSA-2048 (Encryption)</span>
    <span class="bdg bdg-alg">ECC-SECP384R1 (Signature)</span>
    <span class="bdg bdg-alg">SHA-256</span>
    <span class="bdg bdg-alg">OAEP</span>
    <span class="bdg bdg-live">live backend</span>
  </div>
</div>
""", unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Tabs
# -----------------------------------------------------------------------------

tab_sim, tab_tests = st.tabs(["simulation", "test suite"])


# ------------------------------------------------------------------------------
# TAB 1 - SIMULATION
# ------------------------------------------------------------------------------

with tab_sim:

    # -- Message input --
    col_inp, col_bc = st.columns([5, 1])
    max_msg_chars = 190

    with col_inp:
        message = st.text_input(
            "alice@message $",
            value="Hello Bob! This is a secret message encrypted with RSA and signed with ECC.",
            max_chars=max_msg_chars,
            placeholder=f"Enter Alice's plaintext message (max {max_msg_chars} bytes)-",
            label_visibility="visible",
        )
    with col_bc:
        byte_count = len(message.encode("utf-8"))
        st.markdown(f"<div style='padding-top:32px;font-family:var(--mono);font-size:11px;color:var(--text3)'>{byte_count} / {max_msg_chars} bytes</div>", unsafe_allow_html=True)

    # -- Run button --
    run_col, reset_col, _ = st.columns([1, 1, 6])
    with run_col:
        run_clicked = st.button("run simulation", key="run_sim")
    with reset_col:
        reset_clicked = st.button("reset", key="reset_sim")

    # -- State init --
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

    # -- Step strip --
    st.markdown(render_steps(st.session_state.step), unsafe_allow_html=True)

    # -- Terminals placeholder --
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

    # -- Simulation already ran (state persists on re-render) --
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
          <b>Why this is secure:</b> This protocol combines <b>RSA-2048</b> and <b>ECC-ECDSA</b>. <br>
          1. <b>Confidentiality (RSA-2048 OAEP)</b>: Alice encrypts the message with Bob's RSA public key. Only Bob's private key can decrypt it.<br>
          2. <b>Authenticity (ECC-ECDSA)</b>: Alice signs the ciphertext with her ECC private key. Bob verifies the signature, proving it came from Alice and wasn't tampered with.
        </div>
        """, unsafe_allow_html=True)

    # -- Run the simulation --
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

        # -- STEP 0: Key Generation --
        update_step(0)
        bL.append(("cmd",   "python3 keygen.py --algo rsa --bits 2048"))
        bL.append(("t-out", "Generating Bob's RSA key pair (for Decryption)-"))
        aL.append(("cmd",   "python3 keygen.py --algo ecc --curve secp384r1"))
        aL.append(("t-out", "Generating Alice's ECC key pair (for Signing)-"))
        redraw()

        t0 = time.perf_counter()
        bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair(key_size=2048)
        rsa_keygen_ms = int((time.perf_counter() - t0) * 1000)

        t1 = time.perf_counter()
        alice_ecc_priv, alice_ecc_pub = generate_ecc_keypair()
        ecc_keygen_ms = int((time.perf_counter() - t1) * 1000)

        bob_rsa_pem = serialize_public_key(bob_rsa_pub)
        alice_ecc_pem = serialize_ecc_public_key(alice_ecc_pub)

        bL.append(("t-key",  "  bob_rsa_private.pem  [secured]"))
        bL.append(("t-key",  "  bob_rsa_public.pem   [ready to share]"))
        bL.append(("t-ok",   f"  keygen time: {rsa_keygen_ms} ms"))
        bL.append(("blank",  ""))
        aL.append(("t-key",  "  alice_ecc_private.pem  [secured]"))
        aL.append(("t-key",  "  alice_ecc_public.pem   [ready to share]"))
        aL.append(("t-ok",   f"  keygen time: {ecc_keygen_ms} ms"))
        aL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # -- STEP 1: Key exchange --
        update_step(1)
        aL.append(("cmd",    "cat alice_ecc_public.pem | nc bob.local 4433"))
        bL.append(("cmd",    "cat bob_rsa_public.pem | nc alice.local 4434"))
        redraw(ch_status="public keys -", ch_pkt="down")
        time.sleep(0.4)
        redraw(ch_status="public keys -", ch_pkt="up")
        time.sleep(0.4)

        aL.append(("t-info", "  Sent Alice's ECC Signature Public Key."))
        aL.append(("t-key",  f"  Received: bob_rsa_public.pem ({len(bob_rsa_pem)} bytes)"))
        aL.append(("blank",  ""))
        bL.append(("t-info", "  Sent Bob's RSA Encryption Public Key."))
        bL.append(("t-key",  f"  Received: alice_ecc_public.pem ({len(alice_ecc_pem)} bytes)"))
        bL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # -- STEP 2: Alice Encrypts (RSA) and Signs (ECC) --
        update_step(2)
        alice_received_rsa_key = deserialize_public_key(bob_rsa_pem)

        aL.append(("cmd",     "python3 encrypt_sign.py --rsa-key bob_rsa_public.pem --ecc-key alice_ecc_private.pem"))
        aL.append(("t-label", f'  plaintext  : "{message[:60]}" ({len(message.encode())} bytes)'))
        aL.append(("t-out",   "  [1/2] encrypting message with Bob's RSA-2048 public key (OAEP)-"))
        redraw()

        t1 = time.perf_counter()
        ciphertext = encrypt_message(message, alice_received_rsa_key)

        aL.append(("t-out",   "  [2/2] signing ciphertext with Alice's ECC private key (ECDSA)-"))
        redraw()
        signature = sign_message(ciphertext, alice_ecc_priv)
        encrypt_ms = int((time.perf_counter() - t1) * 1000)

        ct_b64  = base64.b64encode(ciphertext).decode()
        sig_b64 = base64.b64encode(signature).decode()

        aL.append(("t-cipher", f"[RSA-OAEP Ciphertext] {ct_b64[:64]}-"))
        aL.append(("t-cipher", f"[ECC-ECDSA Signature] {sig_b64[:64]}-"))
        aL.append(("t-dim",   f"  process time:  {encrypt_ms} ms"))
        aL.append(("blank",   ""))
        redraw()
        time.sleep(0.4)

        # -- STEP 3: Transmit payload --
        update_step(3)
        total_size = len(ciphertext) + len(signature)
        aL.append(("cmd",   "cat payload.bin | nc bob.local 4435"))
        aL.append(("t-out", "Transmitting [RSA Ciphertext] + [ECC Signature]-"))
        bL.append(("t-dim", "Listening for incoming payload-"))
        redraw(ch_status="payload -", ch_pkt="down")
        time.sleep(0.7)

        aL.append(("t-info", "  transmission complete."))
        aL.append(("blank",  ""))
        bL.append(("t-out",  "Payload received from Alice."))
        bL.append(("t-info", f"  {total_size} bytes received."))
        bL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # -- STEP 4: Bob verifies and decrypts --
        update_step(4)
        alice_received_ecc_key = deserialize_ecc_public_key(alice_ecc_pem)
        bL.append(("cmd",   "python3 verify_decrypt.py --rsa-key bob_rsa_private.pem --ecc-key alice_ecc_public.pem"))
        bL.append(("t-out", "  [1/2] verifying ECDSA signature with Alice's public key-"))
        redraw()

        t2 = time.perf_counter()
        is_valid = verify_signature(ciphertext, signature, alice_received_ecc_key)

        if is_valid:
            bL.append(("t-ok", "  Signature Valid - (Authentic from Alice)"))
        else:
            bL.append(("t-err", "  Signature Invalid - (Tampered or forged!)"))

        bL.append(("t-out", "  [2/2] decrypting ciphertext with Bob's RSA-2048 private key-"))
        redraw()

        try:
            if is_valid:
                decrypted = decrypt_message(ciphertext, bob_rsa_priv)
                bL.append(("t-plain", f'  plaintext   : "{decrypted}"'))
                decrypt_success = True
            else:
                bL.append(("t-err", "  Aborting decryption due to invalid signature."))
                decrypted = ""
                decrypt_success = False
        except Exception as e:
            bL.append(("t-err", f"  Decryption Failed - ({str(e)})"))
            decrypted = ""
            decrypt_success = False

        decrypt_ms = int((time.perf_counter() - t2) * 1000)
        bL.append(("t-dim",  f"  process time:  {decrypt_ms} ms"))
        bL.append(("blank",  ""))
        redraw()
        time.sleep(0.4)

        # -- STEP 5: Verify --
        update_step(5)
        match = decrypted == message and is_valid and decrypt_success
        bL.append(("cmd",  "python3 sys_check.py"))
        bL.append(("t-ok" if match else "t-err", f"  signature   : {'VALID' if is_valid else 'FAILED'}"))
        bL.append(("t-ok" if match else "t-err", f"  integrity   : {'OK' if decrypt_success else 'TAMPERED'}"))
        bL.append(("t-ok" if match else "t-err",  "  RSA + ECC protocol success. fully secure." if match else "  SECURITY CHECK FAILED."))
        bL.append(("blank", ""))
        aL.append(("cmd",   "# Transmission complete. Session ended."))
        aL.append(("blank", ""))

        chips = {
            "rsa_keygen_ms": f"{rsa_keygen_ms} ms",
            "ecc_keygen_ms": f"{ecc_keygen_ms} ms",
            "encrypt_ms": f"{encrypt_ms} ms",
            "decrypt_ms": f"{decrypt_ms} ms",
            "payload_bytes": f"{total_size} bytes",
            "status": "secure -" if match else "FAILED -",
        }
        st.session_state.chips          = chips
        st.session_state.channel_status = "closed"
        st.session_state.sim_done       = True
        redraw(ch_status="closed", ch_pkt="", a_cur=True, b_cur=True)


# ------------------------------------------------------------------------------
# TAB 2 - TEST SUITE
# ------------------------------------------------------------------------------

with tab_tests:

    run_tests = st.button("run RSA + ECC test suite", key="run_tests")

    if "test_results" not in st.session_state:
        st.session_state.test_results = None

    if st.button("reset tests", key="reset_tests"):
        st.session_state.test_results = None
        st.rerun()

    if run_tests:
        st.session_state.test_results = None
        results = []

        with st.spinner("Running RSA + ECC test suite-"):
            bob_rsa_priv, bob_rsa_pub     = generate_rsa_keypair()
            alice_ecc_priv, alice_ecc_pub = generate_ecc_keypair()
            eve_rsa_priv, eve_rsa_pub     = generate_rsa_keypair()
            eve_ecc_priv, eve_ecc_pub     = generate_ecc_keypair()

            tests = [
                ("TC-01", "Standard message (RSA enc + ECC sign)",  "Full encrypt-sign-verify-decrypt roundtrip"),
                ("TC-02", "Wrong RSA key (Eve tries to decrypt)",   "Eve attempts to decrypt with her RSA key"),
                ("TC-03", "Tampered ciphertext",                    "Ciphertext altered in transit"),
                ("TC-04", "Forged ECC signature",                   "Eve signs message with her ECC key"),
            ]

            # TC-01: Standard roundtrip
            try:
                msg = "Hello Bob! Secure message."
                ct = encrypt_message(msg, bob_rsa_pub)
                sig = sign_message(ct, alice_ecc_priv)
                assert verify_signature(ct, sig, alice_ecc_pub) == True
                pt = decrypt_message(ct, bob_rsa_priv)
                assert pt == msg
                results.append(("TC-01", tests[0][1], True, "Roundtrip success"))
            except Exception as e:
                results.append(("TC-01", tests[0][1], False, str(e)))

            # TC-02: Eve tries to decrypt
            try:
                ct = encrypt_message("Secret for Bob", bob_rsa_pub)
                decrypt_message(ct, eve_rsa_priv)
                results.append(("TC-02", tests[1][1], False, "Decrypted with wrong key!"))
            except (ValueError, Exception) as e:
                results.append(("TC-02", tests[1][1], True, f"{type(e).__name__} raised as expected"))

            # TC-03: Tampered ciphertext
            try:
                ct = bytearray(encrypt_message("Tamper test", bob_rsa_pub))
                ct[10] ^= 0xFF
                decrypt_message(bytes(ct), bob_rsa_priv)
                results.append(("TC-03", tests[2][1], False, "Tampered ciphertext accepted!"))
            except (ValueError, Exception) as e:
                results.append(("TC-03", tests[2][1], True, f"{type(e).__name__} raised - OAEP caught it"))

            # TC-04: Forged ECC signature
            try:
                ct = encrypt_message("Forged msg", bob_rsa_pub)
                sig = sign_message(ct, eve_ecc_priv)
                assert verify_signature(ct, sig, alice_ecc_pub) == False
                results.append(("TC-04", tests[3][1], True, "Signature verification failed as expected"))
            except Exception as e:
                results.append(("TC-04", tests[3][1], False, str(e)))

        st.session_state.test_results = results

    if st.session_state.test_results:
        results = st.session_state.test_results
        rows_html = ""
        for tc_id, desc, passed, note in results:
            res_cls  = "tc-pass" if passed else "tc-fail"
            res_txt  = "PASS -"  if passed else "FAIL -"
            note_html = f'<span class="tc-note">{_esc(note)}</span>' if note else "-"
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
                press "run RSA + ECC test suite" to execute the test suite
              </td></tr>
            </tbody>
          </table>
        </div>
        """, unsafe_allow_html=True)

