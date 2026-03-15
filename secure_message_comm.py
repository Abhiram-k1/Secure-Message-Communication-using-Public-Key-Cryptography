"""
=============================================================================
  Secure Message Communication using Public Key Cryptography
  End-Semester Project | Python + cryptography (hazmat) library
=============================================================================
  Entities  : Alice (Sender)  <-->  Bob (Receiver)
  Algorithm : RSA-2048 with OAEP padding (SHA-256)
  Library   : cryptography.hazmat (low-level primitives)
=============================================================================
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import base64
import os


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — KEY GENERATION (Bob's side)
# ─────────────────────────────────────────────────────────────────────────────

def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate an RSA key pair for Bob.

    RSA security is based on the computational difficulty of factoring the
    product of two large primes (p and q).  A 2048-bit key is the current
    industry minimum for production systems.

    Parameters
    ----------
    key_size : int
        Bit-length of the RSA modulus n = p × q.  Default is 2048.

    Returns
    -------
    private_key : RSAPrivateKey  — kept secret by Bob
    public_key  : RSAPublicKey  — shared openly with Alice (and anyone else)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,      # Standard Fermat prime e; widely adopted
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """
    Serialize Bob's public key to PEM format so it can be shared / stored.

    PEM (Privacy Enhanced Mail) is a base64-encoded DER structure wrapped
    in -----BEGIN PUBLIC KEY----- headers.  It is the standard wire format
    for exchanging RSA public keys.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_bytes: bytes):
    """Load a PEM-encoded public key back into a usable key object."""
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — MESSAGE ENCRYPTION (Alice's side)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_message(plaintext: str, bob_public_key) -> bytes:
    """
    Alice encrypts a plaintext message using Bob's RSA public key.

    Padding scheme : OAEP (Optimal Asymmetric Encryption Padding)
    Hash function  : SHA-256 (for the mask generation function)
    Label hash     : SHA-256 (for the OAEP label; label itself is empty)

    WHY OAEP?
    ----------
    Raw (textbook) RSA — ciphertext = m^e mod n — is deterministic and
    vulnerable to:
      • Chosen-plaintext attacks (same message → same ciphertext every time)
      • Malleability attacks (an attacker can craft related ciphertexts)

    OAEP introduces randomness (a random seed is mixed in before encryption)
    and uses a Feistel-like structure with a mask generation function (MGF1).
    This means the same plaintext encrypted twice produces *different*
    ciphertexts, destroying the attacker's ability to correlate outputs.

    Parameters
    ----------
    plaintext      : str   — the message Alice wants Bob to receive secretly
    bob_public_key : RSAPublicKey — Bob's public key (NOT Alice's own key)

    Returns
    -------
    ciphertext : bytes — the encrypted message, safe to transmit over any
                         untrusted channel (internet, email, etc.)
    """
    ciphertext = bob_public_key.encrypt(
        plaintext.encode("utf-8"),          # Convert string → bytes
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None                      # Empty label (standard practice)
        )
    )
    return ciphertext


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — MESSAGE DECRYPTION (Bob's side)
# ─────────────────────────────────────────────────────────────────────────────

def decrypt_message(ciphertext: bytes, bob_private_key) -> str:
    """
    Bob decrypts the received ciphertext using his RSA private key.

    The OAEP padding is automatically verified and stripped during decryption.
    If the ciphertext was tampered with, or a wrong key is used, the
    cryptography library raises a ValueError — the decryption fails
    loudly rather than silently returning garbage.

    Parameters
    ----------
    ciphertext      : bytes          — the encrypted bytes from Alice
    bob_private_key : RSAPrivateKey  — Bob's secret key (never shared)

    Returns
    -------
    plaintext : str — the original message Alice sent
    """
    plaintext_bytes = bob_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext_bytes.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# HELPER — Pretty display utilities
# ─────────────────────────────────────────────────────────────────────────────

def display_banner(title: str) -> None:
    width = 70
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


def display_ciphertext(ciphertext: bytes) -> None:
    """Display ciphertext as base64 — binary bytes are not printable."""
    b64 = base64.b64encode(ciphertext).decode("utf-8")
    print("\n  [Ciphertext — Base64 encoded, safe for text channels]")
    # Print in 76-character lines (PEM-style readability)
    for i in range(0, len(b64), 76):
        print(f"  {b64[i:i+76]}")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — SIMULATION WORKFLOW  (main script)
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation(user_message: str = None) -> None:
    """
    Full lifecycle demonstration:
      1. Bob generates his RSA-2048 key pair.
      2. Bob shares his public key with Alice.
      3. Alice encrypts her message with Bob's public key.
      4. Ciphertext is "transmitted" (displayed on screen).
      5. Bob decrypts the ciphertext with his private key.
    """

    # ── 1. Key Generation ──────────────────────────────────────────────────
    display_banner("STEP 1 │ Bob generates his RSA-2048 key pair")
    print("\n  Generating 2048-bit RSA key pair … ", end="", flush=True)
    bob_private_key, bob_public_key = generate_rsa_keypair(key_size=2048)
    print("Done ✓")

    # Serialize to PEM so Alice can receive the public key
    bob_public_pem = serialize_public_key(bob_public_key)
    print("\n  Bob's Public Key (PEM) — shared with Alice:\n")
    print(bob_public_pem.decode("utf-8"))
    print("  Bob stores his Private Key securely (never transmitted).")

    # ── 2. Alice receives Bob's public key ─────────────────────────────────
    display_banner("STEP 2 │ Alice prepares her secret message")

    # Simulate Alice receiving Bob's public key over an insecure channel
    alice_received_key = deserialize_public_key(bob_public_pem)

    if user_message is None:
        print()
        user_message = input("  Alice, enter your message for Bob: ").strip()
        if not user_message:
            user_message = "Hello Bob! This is a secret message from Alice."

    print(f"\n  Plaintext Message : {user_message!r}")

    # ── 3. Encryption ──────────────────────────────────────────────────────
    display_banner("STEP 3 │ Alice encrypts the message with Bob's Public Key")
    ciphertext = encrypt_message(user_message, alice_received_key)
    print(f"\n  Original size : {len(user_message.encode())} bytes")
    print(f"  Encrypted size: {len(ciphertext)} bytes (RSA-2048 block size)")
    display_ciphertext(ciphertext)

    # ── 4. Transmission ────────────────────────────────────────────────────
    display_banner("STEP 4 │ Ciphertext is transmitted over an insecure channel")
    print("\n  The ciphertext above is now safely sent over the internet.")
    print("  An eavesdropper sees only random-looking bytes — useless without")
    print("  Bob's private key.")

    # ── 5. Decryption ──────────────────────────────────────────────────────
    display_banner("STEP 5 │ Bob decrypts the ciphertext with his Private Key")
    decrypted_message = decrypt_message(ciphertext, bob_private_key)
    print(f"\n  Decrypted Message : {decrypted_message!r}")

    # ── Verification ───────────────────────────────────────────────────────
    display_banner("RESULT │ Integrity Verification")
    if decrypted_message == user_message:
        print("\n  ✅  SUCCESS — Decrypted message matches the original plaintext!")
    else:
        print("\n  ❌  FAILURE — Messages do not match (should never happen).")

    print("\n" + "═" * 70 + "\n")
    return bob_private_key, bob_public_key, ciphertext, user_message


# ─────────────────────────────────────────────────────────────────────────────
# TEST CASES
# ─────────────────────────────────────────────────────────────────────────────

def run_test_cases() -> None:
    """
    Test Case Suite
    ───────────────
    TC-01 : Standard short message            → should decrypt correctly
    TC-02 : Special characters / Unicode      → should decrypt correctly
    TC-03 : Maximum-length message for RSA    → should decrypt correctly
    TC-04 : Wrong private key                 → must raise ValueError
    TC-05 : Tampered ciphertext               → must raise ValueError
    TC-06 : Empty message                     → should decrypt correctly
    """
    print("\n\n")
    display_banner("TEST SUITE — Robustness Verification")

    bob_private, bob_public = generate_rsa_keypair()
    eve_private, eve_public = generate_rsa_keypair()   # Eve's separate key pair

    results = []

    # ── TC-01 : Standard message ───────────────────────────────────────────
    try:
        ct = encrypt_message("Hello, Bob!", bob_public)
        pt = decrypt_message(ct, bob_private)
        assert pt == "Hello, Bob!"
        results.append(("TC-01", "Standard short message", "PASS ✅", ""))
    except Exception as e:
        results.append(("TC-01", "Standard short message", "FAIL ❌", str(e)))

    # ── TC-02 : Unicode / Special characters ──────────────────────────────
    msg_unicode = "नमस्ते Bob! 🔐 Secret: €42"
    try:
        ct = encrypt_message(msg_unicode, bob_public)
        pt = decrypt_message(ct, bob_private)
        assert pt == msg_unicode
        results.append(("TC-02", "Unicode & special characters", "PASS ✅", ""))
    except Exception as e:
        results.append(("TC-02", "Unicode & special characters", "FAIL ❌", str(e)))

    # ── TC-03 : Near-maximum plaintext length ─────────────────────────────
    # RSA-2048 + OAEP-SHA256 max plaintext = (2048/8) - 2*32 - 2 = 190 bytes
    max_msg = "A" * 190
    try:
        ct = encrypt_message(max_msg, bob_public)
        pt = decrypt_message(ct, bob_private)
        assert pt == max_msg
        results.append(("TC-03", "Max-length plaintext (190 bytes)", "PASS ✅", ""))
    except Exception as e:
        results.append(("TC-03", "Max-length plaintext (190 bytes)", "FAIL ❌", str(e)))

    # ── TC-04 : Wrong private key (Eve tries to decrypt) ──────────────────
    try:
        ct = encrypt_message("Secret for Bob only", bob_public)
        decrypt_message(ct, eve_private)        # Eve uses her own private key
        results.append(("TC-04", "Wrong private key (Eve's key)", "FAIL ❌",
                         "Decryption succeeded — this is a security bug!"))
    except ValueError:
        results.append(("TC-04", "Wrong private key (Eve's key)",
                         "PASS ✅", "ValueError raised as expected"))
    except Exception as e:
        results.append(("TC-04", "Wrong private key (Eve's key)",
                         "PASS ✅", f"Exception raised: {type(e).__name__}"))

    # ── TC-05 : Tampered ciphertext ───────────────────────────────────────
    try:
        ct = bytearray(encrypt_message("Tamper test", bob_public))
        ct[10] ^= 0xFF                  # Flip bits in the 11th byte
        decrypt_message(bytes(ct), bob_private)
        results.append(("TC-05", "Tampered ciphertext", "FAIL ❌",
                         "Decryption succeeded — OAEP check bypassed!"))
    except ValueError:
        results.append(("TC-05", "Tampered ciphertext",
                         "PASS ✅", "ValueError raised as expected"))
    except Exception as e:
        results.append(("TC-05", "Tampered ciphertext",
                         "PASS ✅", f"Exception raised: {type(e).__name__}"))

    # ── TC-06 : Empty string ──────────────────────────────────────────────
    try:
        ct = encrypt_message("", bob_public)
        pt = decrypt_message(ct, bob_private)
        assert pt == ""
        results.append(("TC-06", "Empty message", "PASS ✅", ""))
    except Exception as e:
        results.append(("TC-06", "Empty message", "FAIL ❌", str(e)))

    # ── Print results table ────────────────────────────────────────────────
    print(f"\n  {'ID':<8} {'Description':<38} {'Result':<12} {'Notes'}")
    print("  " + "─" * 80)
    for tc_id, desc, result, note in results:
        print(f"  {tc_id:<8} {desc:<38} {result:<12} {note}")
    print()

    passed = sum(1 for r in results if "PASS" in r[2])
    print(f"\n  {passed}/{len(results)} test cases passed.\n")
    print("═" * 70 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║   Secure Message Communication using Public Key Cryptography        ║
║   RSA-2048 + OAEP (SHA-256) | Alice → Bob Simulation               ║
╚══════════════════════════════════════════════════════════════════════╝
    """)

    print("  Select mode:")
    print("  [1] Interactive simulation (enter your own message)")
    print("  [2] Run automated test suite")
    print("  [3] Both\n")
    choice = input("  Your choice (1/2/3): ").strip()

    if choice in ("1", "3"):
        run_simulation()
    if choice in ("2", "3"):
        run_test_cases()
    if choice not in ("1", "2", "3"):
        print("  Invalid choice. Running full simulation with a default message.\n")
        run_simulation("Hello Bob! The meeting is at 3 PM. — Alice")
        run_test_cases()
