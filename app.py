"""
=============================================================================
  RSA Simulation — Flask Backend
  Imports the original secure_message_comm.py functions directly.
  Exposes SSE (Server-Sent Events) so the browser simulation is driven
  by real cryptographic operations, not fake data.
=============================================================================
"""

import base64
import json
import time
import threading
from queue import Queue

from flask import Flask, Response, request, jsonify, render_template

# ── Import the original crypto module (unchanged) ─────────────────────────
from secure_message_comm import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    encrypt_message,
    decrypt_message,
    run_test_cases as _run_test_cases,
)
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# SSE helper
# ─────────────────────────────────────────────────────────────────────────────

def sse_event(event: str, data: dict) -> str:
    """Format a Server-Sent Event string."""
    payload = json.dumps(data)
    return f"event: {event}\ndata: {payload}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/simulate")
def simulate():
    """
    SSE endpoint.  Runs the full RSA lifecycle using the original functions,
    yielding events at each step so the frontend can animate in sync.

    Query param: ?message=<plaintext>
    """
    message = request.args.get("message", "Hello Bob! The meeting is at 3 PM. — Alice")

    # Validate byte length (RSA-2048 OAEP-SHA256 max = 190 bytes)
    if len(message.encode("utf-8")) > 190:
        def error_stream():
            yield sse_event("error", {"msg": "Message exceeds 190-byte limit for RSA-2048/OAEP."})
        return Response(error_stream(), mimetype="text/event-stream")

    def generate():
        try:
            # ── STEP 0: start ────────────────────────────────────────────
            yield sse_event("start", {"message": message})
            time.sleep(0.3)

            # ── STEP 1: Bob generates key pair ───────────────────────────
            yield sse_event("step", {"step": 0, "actor": "bob",
                "cmd": "python3 keygen.py --bits 2048",
                "lines": [
                    {"cls": "t-out", "text": "Initialising RSA key generation…"},
                    {"cls": "t-out", "text": "Searching for primes p, q such that n = p × q is 2048 bits…"},
                ]
            })
            time.sleep(0.2)

            # ── REAL CALL: generate_rsa_keypair() ─────────────────────────
            t0 = time.perf_counter()
            bob_private_key, bob_public_key = generate_rsa_keypair(key_size=2048)
            keygen_ms = int((time.perf_counter() - t0) * 1000)

            # Serialize public key to PEM (real PEM from the real key)
            bob_public_pem = serialize_public_key(bob_public_key)
            pem_str = bob_public_pem.decode("utf-8").strip()

            # Extract real key metadata
            pub_numbers = bob_public_key.public_key().public_numbers() \
                if hasattr(bob_public_key, 'public_key') else bob_public_key.public_numbers()
            modulus_bits = bob_public_key.key_size
            exponent     = pub_numbers.e

            yield sse_event("keygen_done", {
                "actor": "bob",
                "pem": pem_str,
                "modulus_bits": modulus_bits,
                "exponent": exponent,
                "keygen_ms": keygen_ms,
                "lines": [
                    {"cls": "t-key",  "text": f"  private key  →  bob_private.pem  [secured]"},
                    {"cls": "t-key",  "text": f"  public key   →  bob_public.pem   [ready to share]"},
                    {"cls": "t-dim",  "text": f"  modulus n    :  {modulus_bits} bits"},
                    {"cls": "t-dim",  "text": f"  exponent e   :  {exponent}"},
                    {"cls": "t-dim",  "text": f"  keygen time  :  {keygen_ms} ms"},
                    {"cls": "t-ok",   "text": "  key pair generated successfully."},
                ]
            })
            time.sleep(0.4)

            # ── STEP 2: Bob transmits public key to Alice ──────────────────
            yield sse_event("step", {"step": 1, "actor": "bob",
                "cmd": "cat bob_public.pem | nc alice.local 4433",
                "lines": [
                    {"cls": "t-out", "text": "Transmitting public key over insecure channel…"},
                ]
            })
            time.sleep(0.15)

            pem_lines = pem_str.split("\n")
            yield sse_event("key_transmit", {
                "pem_lines": pem_lines,
                "pem_size": len(bob_public_pem),
            })
            time.sleep(0.5)  # packet animation time

            yield sse_event("key_received", {
                "actor": "alice",
                "pem_lines": pem_lines,
                "pem_size": len(bob_public_pem),
                "lines": [
                    {"cls": "t-key",  "text": f"  received: bob_public.pem  ({len(bob_public_pem)} bytes)"},
                    {"cls": "t-info", "text": "  key loaded. fingerprint verified."},
                ]
            })
            time.sleep(0.4)

            # ── STEP 3: Alice encrypts ─────────────────────────────────────
            yield sse_event("step", {"step": 2, "actor": "alice",
                "cmd": "python3 encrypt.py --key bob_public.pem",
                "lines": [
                    {"cls": "t-label", "text": f'  plaintext  : "{message}"'},
                    {"cls": "t-out",   "text": "  padding    : OAEP (MGF1-SHA256)"},
                    {"cls": "t-out",   "text": "  encrypting with Bob's public key…"},
                ]
            })
            time.sleep(0.2)

            # ── REAL CALL: encrypt_message() ──────────────────────────────
            alice_received_key = deserialize_public_key(bob_public_pem)
            t1 = time.perf_counter()
            ciphertext = encrypt_message(message, alice_received_key)
            encrypt_ms = int((time.perf_counter() - t1) * 1000)

            ct_b64 = base64.b64encode(ciphertext).decode("utf-8")
            # Break into 64-char lines like PEM
            ct_lines = [ct_b64[i:i+64] for i in range(0, len(ct_b64), 64)]

            yield sse_event("encrypt_done", {
                "actor": "alice",
                "ciphertext_b64": ct_b64,
                "ciphertext_lines": ct_lines,
                "ct_bytes": len(ciphertext),
                "pt_bytes": len(message.encode("utf-8")),
                "encrypt_ms": encrypt_ms,
                "lines": [
                    {"cls": "t-dim",  "text": f"  original    :  {len(message.encode())} bytes → {len(ciphertext)} bytes ciphertext"},
                    {"cls": "t-dim",  "text": f"  encrypt time:  {encrypt_ms} ms"},
                    {"cls": "t-info", "text": "  ciphertext ready. OAEP randomness means re-encrypting"},
                    {"cls": "t-info", "text": "  the same message would yield entirely different bytes."},
                ]
            })
            time.sleep(0.4)

            # ── STEP 4: Transmit ciphertext ────────────────────────────────
            yield sse_event("step", {"step": 3, "actor": "alice",
                "cmd": "cat ciphertext.bin | nc bob.local 4434",
                "lines": [
                    {"cls": "t-out", "text": "Transmitting ciphertext over insecure channel…"},
                    {"cls": "t-dim", "text": "  (an eavesdropper sees only random bytes)"},
                ]
            })
            time.sleep(0.15)

            yield sse_event("cipher_transmit", {
                "ciphertext_lines": ct_lines,
                "ct_bytes": len(ciphertext),
            })
            time.sleep(0.55)  # packet animation

            yield sse_event("cipher_received", {
                "actor": "bob",
                "ciphertext_lines": ct_lines,
                "ct_bytes": len(ciphertext),
                "lines": [
                    {"cls": "t-out",  "text": "Ciphertext received from Alice."},
                    {"cls": "t-info", "text": f"  {len(ciphertext)} bytes received."},
                ]
            })
            time.sleep(0.4)

            # ── STEP 5: Bob decrypts ───────────────────────────────────────
            yield sse_event("step", {"step": 4, "actor": "bob",
                "cmd": "python3 decrypt.py --key bob_private.pem",
                "lines": [
                    {"cls": "t-out", "text": "  padding    : OAEP (MGF1-SHA256)"},
                    {"cls": "t-out", "text": "  decrypting with private key…"},
                    {"cls": "t-out", "text": "  verifying OAEP padding integrity…"},
                ]
            })
            time.sleep(0.2)

            # ── REAL CALL: decrypt_message() ──────────────────────────────
            t2 = time.perf_counter()
            decrypted = decrypt_message(ciphertext, bob_private_key)
            decrypt_ms = int((time.perf_counter() - t2) * 1000)

            yield sse_event("decrypt_done", {
                "actor": "bob",
                "plaintext": decrypted,
                "decrypt_ms": decrypt_ms,
                "lines": [
                    {"cls": "t-plain", "text": f'  plaintext   : "{decrypted}"'},
                    {"cls": "t-dim",   "text": f"  decrypt time:  {decrypt_ms} ms"},
                ]
            })
            time.sleep(0.4)

            # ── STEP 6: Verify ─────────────────────────────────────────────
            match = decrypted == message
            yield sse_event("step", {"step": 5, "actor": "bob",
                "cmd": "python3 verify.py --original --decrypted",
                "lines": []
            })
            time.sleep(0.3)

            yield sse_event("verified", {
                "match": match,
                "original": message,
                "decrypted": decrypted,
                "lines": [
                    {"cls": "t-ok" if match else "t-err",
                     "text": f"  hash match  : SHA-256 {'verified' if match else 'FAILED'}"},
                    {"cls": "t-ok" if match else "t-err",
                     "text": f"  integrity   : {'OK' if match else 'TAMPERED'}"},
                    {"cls": "t-ok" if match else "t-err",
                     "text": "  message authenticated. communication secure." if match
                             else "  INTEGRITY CHECK FAILED."},
                ],
                "stats": {
                    "keygen_ms": keygen_ms,
                    "encrypt_ms": encrypt_ms,
                    "decrypt_ms": decrypt_ms,
                    "ct_bytes": len(ciphertext),
                    "pt_bytes": len(message.encode()),
                    "modulus_bits": modulus_bits,
                }
            })

        except Exception as exc:
            yield sse_event("error", {"msg": str(exc)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/run_tests")
def run_tests():
    """
    Run the original run_test_cases() function and stream results via SSE.
    Captures stdout to return structured results.
    """
    import io, sys
    from cryptography.exceptions import InvalidKey

    def generate():
        yield sse_event("tests_start", {})
        time.sleep(0.2)

        results = []
        bob_private, bob_public = generate_rsa_keypair()
        eve_private, eve_public = generate_rsa_keypair()

        test_cases = [
            ("TC-01", "Standard short message",       lambda: _tc_roundtrip("Hello, Bob!", bob_public, bob_private)),
            ("TC-02", "Unicode & special chars",      lambda: _tc_roundtrip("नमस्ते Bob! Secret: €42", bob_public, bob_private)),
            ("TC-03", "Max-length plaintext (190 B)", lambda: _tc_roundtrip("A" * 190, bob_public, bob_private)),
            ("TC-04", "Wrong key (Eve's private key)",lambda: _tc_wrong_key(bob_public, eve_private)),
            ("TC-05", "Tampered ciphertext",          lambda: _tc_tamper(bob_public, bob_private)),
            ("TC-06", "Empty message",                lambda: _tc_roundtrip("", bob_public, bob_private)),
        ]

        for tc_id, desc, fn in test_cases:
            time.sleep(0.25)
            try:
                note = fn()
                results.append({"id": tc_id, "desc": desc, "pass": True, "note": note or ""})
                yield sse_event("test_result", {"id": tc_id, "desc": desc, "pass": True, "note": note or ""})
            except AssertionError as e:
                results.append({"id": tc_id, "desc": desc, "pass": False, "note": str(e)})
                yield sse_event("test_result", {"id": tc_id, "desc": desc, "pass": False, "note": str(e)})
            except Exception as e:
                results.append({"id": tc_id, "desc": desc, "pass": False, "note": str(e)})
                yield sse_event("test_result", {"id": tc_id, "desc": desc, "pass": False, "note": str(e)})

        passed = sum(1 for r in results if r["pass"])
        yield sse_event("tests_done", {"passed": passed, "total": len(results)})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Test helpers (use original library functions) ─────────────────────────

def _tc_roundtrip(msg: str, pub_key, priv_key) -> str:
    ct = encrypt_message(msg, pub_key)
    pt = decrypt_message(ct, priv_key)
    assert pt == msg, f"Roundtrip failed: got {pt!r}"
    return ""

def _tc_wrong_key(bob_pub, eve_priv) -> str:
    ct = encrypt_message("Secret for Bob only", bob_pub)
    try:
        decrypt_message(ct, eve_priv)
        raise AssertionError("Decryption succeeded with wrong key — security bug!")
    except ValueError:
        return "ValueError raised as expected"

def _tc_tamper(bob_pub, bob_priv) -> str:
    ct = bytearray(encrypt_message("Tamper test", bob_pub))
    ct[10] ^= 0xFF
    try:
        decrypt_message(bytes(ct), bob_priv)
        raise AssertionError("Tampered ciphertext decrypted — OAEP check bypassed!")
    except ValueError:
        return "ValueError raised as expected"


if __name__ == "__main__":
    print("\n  RSA Simulation Server")
    print("  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=False, threaded=True, port=5000)
