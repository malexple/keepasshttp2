"""
End-to-end test client for the C# orchestrator, acting like a real
KeePassXC-Browser extension: generates its own X25519 keypair, does the
change-public-keys handshake, then associate/test-associate, then sends
an encrypted get-logins request.

Install: pip install websockets pynacl
Run:     python test_orchestrator_client.py

Note: the "associate" step below will pop up a real "Allow/Deny" dialog
in the running KeePass instance - click Allow within the timeout to see
the full happy path. Clicking Deny (or letting it time out) now gets a
real success:false response instead of a client-side timeout.
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

        # 2. test-associate before ever pairing - we haven't associated
        # yet, so this must come back with success: false, not a timeout.
        id_pk, id_sk = nb.crypto_box_keypair()
        unknown_id = "demo-client"

        inner_test_before = {"action": "test-associate", "id": unknown_id, "key": b64(id_pk)}
        nonce_test1 = os.urandom(24)
        ciphertext_test1 = nb.crypto_box(json.dumps(inner_test_before).encode(), nonce_test1, host_pk, client_sk)
        req_test1 = {
            "action": "test-associate",
            "message": b64(ciphertext_test1),
            "nonce": b64(nonce_test1),
            "clientID": client_id,
        }
        await ws.send(json.dumps(req_test1))
        resp_test1 = json.loads(await ws.recv())
        resp_test1_nonce = base64.b64decode(resp_test1["nonce"])
        resp_test1_ciphertext = base64.b64decode(resp_test1["message"])
        inner_test1 = json.loads(nb.crypto_box_open(resp_test1_ciphertext, resp_test1_nonce, host_pk, client_sk))
        print("test-associate (before pairing) decrypted inner response:", inner_test1)
        assert inner_test1["success"] == "false", "expected no existing association yet"

        # 3. associate - this pops up a real Allow/Deny dialog in KeePass.
        # Click Allow within the timeout below to see the full happy path;
        # clicking Deny (or an unattended timeout) now gets a real
        # success:false response instead of leaving the client hanging.
        inner_associate = {"action": "associate", "key": b64(client_pk), "idKey": b64(id_pk)}
        nonce_assoc = os.urandom(24)
        ciphertext_assoc = nb.crypto_box(json.dumps(inner_associate).encode(), nonce_assoc, host_pk, client_sk)
        req_assoc = {
            "action": "associate",
            "message": b64(ciphertext_assoc),
            "nonce": b64(nonce_assoc),
            "clientID": client_id,
        }
        await ws.send(json.dumps(req_assoc))
        print("Waiting for you to click Allow in the KeePass dialog (60s timeout)...")
        resp_assoc = json.loads(await asyncio.wait_for(ws.recv(), timeout=60))
        resp_assoc_nonce = base64.b64decode(resp_assoc["nonce"])
        resp_assoc_ciphertext = base64.b64decode(resp_assoc["message"])
        inner_assoc = json.loads(nb.crypto_box_open(resp_assoc_ciphertext, resp_assoc_nonce, host_pk, client_sk))
        print("associate decrypted inner response:", inner_assoc)

        if inner_assoc["success"] != "true":
            print("Pairing was declined (or no database open) - stopping here, this is expected behavior.")
            return

        associated_id = inner_assoc["id"]

        # 4. test-associate again, now that we're paired - must succeed.
        inner_test_after = {"action": "test-associate", "id": associated_id, "key": b64(id_pk)}
        nonce_test2 = os.urandom(24)
        ciphertext_test2 = nb.crypto_box(json.dumps(inner_test_after).encode(), nonce_test2, host_pk, client_sk)
        req_test2 = {
            "action": "test-associate",
            "message": b64(ciphertext_test2),
            "nonce": b64(nonce_test2),
            "clientID": client_id,
        }
        await ws.send(json.dumps(req_test2))
        resp_test2 = json.loads(await ws.recv())
        resp_test2_nonce = base64.b64decode(resp_test2["nonce"])
        resp_test2_ciphertext = base64.b64decode(resp_test2["message"])
        inner_test2 = json.loads(nb.crypto_box_open(resp_test2_ciphertext, resp_test2_nonce, host_pk, client_sk))
        print("test-associate (after pairing) decrypted inner response:", inner_test2)
        assert inner_test2["success"] == "true", "expected the pairing we just made to be recognized"

        # 5. get-logins (encrypted)
        inner = {"action": "get-logins", "url": "https://keepass.info/", "submitUrl": "https://example.com/login"}
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

        # 6. Replay attempt: resend the exact same encrypted request again.
        await ws.send(json.dumps(req2))
        try:
            resp3 = await asyncio.wait_for(ws.recv(), timeout=2)
            print("UNEXPECTED: server responded to replay:", resp3)
        except asyncio.TimeoutError:
            print("OK: server did not respond to replayed nonce (silently rejected)")


if __name__ == "__main__":
    asyncio.run(main())