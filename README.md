# Secure Message Communication — RSA-2048 Live Simulation

End-semester project | Python + Flask backend + live browser simulation.

## Project structure

```
rsa_sim/
├── app.py                  ← Flask backend (imports original crypto module)
├── secure_message_comm.py  ← Original crypto code (unchanged)
├── requirements.txt
└── templates/
    └── index.html          ← Simulation UI (SSE-driven from real Python calls)
```

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
python app.py

# 3. Open in browser
# http://127.0.0.1:5000
```

## How it works

The browser simulation is driven entirely by **real cryptographic operations**:

| Frontend event          | Backend call                          |
|-------------------------|---------------------------------------|
| Key generation step     | `generate_rsa_keypair(key_size=2048)` |
| Public key shown in PEM | `serialize_public_key(public_key)`    |
| Encryption step         | `encrypt_message(msg, bob_public_key)`|
| Decryption step         | `decrypt_message(ciphertext, bob_private_key)` |
| Test suite tab          | All 6 original test cases             |

Events are streamed from `/simulate` as **Server-Sent Events (SSE)**, so the
terminal animation is paced by real key generation and crypto timings — the
keygen step genuinely takes ~100–300ms depending on your hardware.

## Notes

- The PEM block shown in Alice's terminal is Bob's **actual** generated public key.
- The ciphertext shown is the **real** OAEP-encrypted output, base64-encoded.
- Performance chips (keygen/encrypt/decrypt ms) reflect real CPU timings.
- The test suite tab runs all 6 original test cases via `/run_tests`.
