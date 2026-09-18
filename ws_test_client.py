"""
Manual WebSocket protocol test client for ws_handshake.zig.
Explicitly drives ping and close so we can see the server's
"received ping, sending pong" / "received close frame..." log lines.

Also sends a legitimate extension Origin, since ws_handshake.zig now
rejects connections without an allowed Origin header (403 + close).

Install: pip install websockets
Run:     python ws_test_client.py
"""

import asyncio
import websockets

ALLOWED_ORIGIN = "chrome-extension://oboonakemofpalcgghocfoadofidjkkk"


async def main():
    uri = "ws://127.0.0.1:19455/"
    async with websockets.connect(uri, origin=ALLOWED_ORIGIN) as ws:
        print("Connected")

        await ws.send("hello")
        reply = await ws.recv()
        print(f"echo reply: {reply!r}")

        pong_waiter = await ws.ping()
        await pong_waiter
        print("pong received")

        await ws.close(code=1000, reason="bye")
        print("closed cleanly")


if __name__ == "__main__":
    asyncio.run(main())