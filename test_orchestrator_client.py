"""
End-to-end test client for the C# orchestrator, acting like a real
KeePassXC-Browser extension: generates its own X25519 keypair, does the
change-public-keys handshake, then sends an encrypted get-logins request.

Install: pip install websockets pynacl
Run:     python test_orchestrator_client.py
"""

import asyncio
import base64
import json
import os

import nacl.bindings as nb
import websockets

ALLOWED_ORIGIN = "chrome-extension://oboonakemofpalcgghocfoadofidjkkk"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def main():
    client_pk, client_sk = nb.crypto_box_keypair()
    client_id = b64(os.urandom(16))

    async with websockets.connect("ws://127.0.0.1:19455/", origin=ALLOWED_ORIGIN) as ws:
        # 1. change-public-keys (plaintext key exchange)
        nonce1 = os.urandom(24)
        req1 = {
            "action": "change-public-keys",
            "publicKey": b64(client_pk),
            "nonce": b64(nonce1),
            "clientID": client_id,
        }
        await ws.send(json.dumps(req1))
        resp1 = json.loads(await ws.recv())
        print("change-public-keys response:", resp1)

        host_pk = base64.b64decode(resp1["publicKey"])

        # 2. get-logins (encrypted)
        inner = {"action": "get-logins", "url": "https://example.com", "submitUrl": "https://example.com/login"}
        inner_bytes = json.dumps(inner).encode()
        nonce2 = os.urandom(24)
        ciphertext = nb.crypto_box(inner_bytes, nonce2, host_pk, client_sk)

        req2 = {
            "action": "get-logins",
            "message": b64(ciphertext),
            "nonce": b64(nonce2),
            "clientID": client_id,
        }
        await ws.send(json.dumps(req2))
        resp2 = json.loads(await ws.recv())
        print("get-logins outer response:", resp2)

        resp_nonce = base64.b64decode(resp2["nonce"])
        resp_ciphertext = base64.b64decode(resp2["message"])
        plaintext = nb.crypto_box_open(resp_ciphertext, resp_nonce, host_pk, client_sk)
        print("get-logins decrypted inner response:", json.loads(plaintext))

        # 3. Replay attempt: resend the exact same encrypted request again.
        await ws.send(json.dumps(req2))
        try:
            resp3 = await asyncio.wait_for(ws.recv(), timeout=2)
            print("UNEXPECTED: server responded to replay:", resp3)
        except asyncio.TimeoutError:
            print("OK: server did not respond to replayed nonce (silently rejected)")


if __name__ == "__main__":
    asyncio.run(main())
