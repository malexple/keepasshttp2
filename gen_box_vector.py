"""
Generates a crypto_box test vector using PyNaCl (a real libsodium binding,
the same primitive family the KeePassXC-Browser extension uses).

We copy the printed hex arrays into a Zig test and check that
std.crypto.nacl.Box.seal/open produce byte-identical output. That proves
binary compatibility, not just internal self-consistency.

Install: pip install pynacl
Run:     python gen_box_vector.py
"""

import nacl.bindings as b
import os

alice_pk, alice_sk = b.crypto_box_keypair()
bob_pk, bob_sk = b.crypto_box_keypair()
nonce = os.urandom(24)
message = b"Hello KeePassHTTP2 from PyNaCl"

ciphertext = b.crypto_box(message, nonce, bob_pk, alice_sk)


def zig_array(name, data):
    hexed = ", ".join(f"0x{byte:02x}" for byte in data)
    print(f"const {name} = [_]u8{{ {hexed} }};")


zig_array("alice_pk", alice_pk)
zig_array("alice_sk", alice_sk)
zig_array("bob_pk", bob_pk)
zig_array("bob_sk", bob_sk)
zig_array("nonce", nonce)
zig_array("message", message)
zig_array("ciphertext", ciphertext)
print(f"// message.len = {len(message)}, ciphertext.len = {len(ciphertext)}")
