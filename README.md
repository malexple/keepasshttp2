# KeePassHttp2

A KeePass 2.x plugin implementing the KeePassXC-Browser protocol (crypto_box
key exchange + encrypted JSON messages over a local WebSocket), built as a
single self-contained managed .NET assembly.

## Why this exists / history

This project started as an exploration of writing the crypto/transport
layer in Zig and calling it from C# via P/Invoke (see git history / the
`orchestrator/` era for that approach). That approach was abandoned in
favor of a fully managed .NET implementation: no native DLLs, no NuGet
packages in the shipped plugin, so the built `KeePassHttp2.dll` has zero
external dependencies beyond KeePass itself and the .NET Framework.

## Architecture

```
src/KeePassHttp2/
  Crypto/NaClBox.cs       crypto_box (X25519 + XSalsa20-Poly1305), built on
                          vendored Chaos.NaCl primitives
  Json/                   hand-rolled JSON parser + writer (no System.Text.Json)
  Transport/              WebSocketServer, built on System.Net.HttpListener
  Protocol/               envelope parsing, inner message DTOs, nonce replay
                          tracking, plugin log
  Vendor/ChaosNaCl/       vendored NaCl primitives (Curve25519, Salsa20,
                          Poly1305) - source-vendored, not a NuGet package
  KeePassHttp2Ext.cs      the actual KeePass.Plugins.Plugin entry point
```

Every layer is covered by xUnit tests in `tests/KeePassHttp2.Tests/` against
official test vectors (crypto), real traffic captures (protocol), and a
real `ClientWebSocket` (transport) - not just synthetic examples.

## Build

```powershell
cd src/KeePassHttp2
dotnet build
```

The project references your local `KeePass.exe` at compile time only (to
resolve `KeePass.Plugins`/`KeePassLib` types - `Private=false`, so it is
NOT copied into the output). If your KeePass install isn't at the default
path baked into `KeePassHttp2.csproj`, override it:

```powershell
dotnet build -p:KeePassDir="C:\Path\To\Your\KeePass"
```

## Install

Copy `bin\Debug\net48\KeePassHttp2.dll` into your KeePass `Plugins` folder
and restart KeePass. It should appear under `Tools > Plugins`.

If it doesn't appear at all (no error, just missing from the list): check
the DLL's file version info - the `Product` field must be exactly
`KeePass Plugin`, or KeePass silently skips it while scanning the folder.
This is set via `<Product>KeePass Plugin</Product>` in the csproj; don't
remove it.

## Test

```powershell
dotnet test
```

Runs the full suite (crypto vectors, JSON parser/writer, protocol envelope
validation, transport handshake/close/shutdown, nonce replay tracking) -
no KeePass process required for any of this.

## Diagnostics

The plugin has no console (KeePass is a GUI app), so it logs to
`keepasshttp2.log` next to `KeePass.exe`. Every accepted connection,
received envelope, decrypt failure, and rejection reason is logged there.

## Manual end-to-end check

`test_orchestrator_client.py` drives a full real handshake against the
running plugin: `change-public-keys` (key exchange) followed by an
encrypted `get-logins` request, and also verifies that a replayed nonce is
silently rejected.

```powershell
python test_orchestrator_client.py
```

## Protocol status

Implemented:
- `change-public-keys` (key exchange, not yet persisted across KeePass restarts)
- `get-logins` (encrypted, queries the currently open database by URL host)
- Nonce replay protection (per clientID)

Not yet implemented (rejected with `unhandled inner action`):
- `associate` / `test-associate` - required by the real KeePassXC-Browser
  extension to establish and verify a persistent pairing; without these,
  only ad-hoc test clients that skip straight to `get-logins` after
  `change-public-keys` will work.
- `generate-password`, `lock-database`, `get-logins-count`

## Known caveats

- Client public keys from `change-public-keys` are held in memory only -
  they do not survive a KeePass restart. The real KeePassXC-Browser
  extension expects `associate` to persist an association (normally in the
  database's `CustomData`), so it can skip `change-public-keys`+`associate`
  on subsequent connections.
- Only one WebSocket connection is served at a time (matches the original
  design - not yet verified whether multiple simultaneous browser tabs
  need concurrent connections).