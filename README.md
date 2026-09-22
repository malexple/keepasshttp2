# KeePassHttp2

A KeePass 2.x plugin implementing the KeePassXC-Browser protocol (crypto_box
key exchange + encrypted JSON messages over a local WebSocket), built as a
single self-contained managed .NET assembly.

## Why this exists / history

This project started as an exploration of writing the crypto/transport
layer in Zig and calling it from C# via P/Invoke. That approach was
abandoned in favor of a fully managed .NET implementation: no native
DLLs, no NuGet packages in the shipped plugin, so the built
`KeePassHttp2.dll` has zero external dependencies beyond KeePass itself
and the .NET Framework.

No existing plugin implements this NaCl-based protocol for classic
KeePass 2.x - the closest prior art, `keepass-natmsg`, only forwards
Native Messaging traffic, it doesn't speak the protocol itself. KeePassXC
has no plugin system at all (a deliberate design choice on their part),
so this plugin can never be ported to run inside KeePassXC - there is no
extension point to port it to.

## Architecture

```
src/KeePassHttp2/
  Crypto/NaClBox.cs       crypto_box (X25519 + XSalsa20-Poly1305), built on
                          vendored Chaos.NaCl primitives
  Json/                   hand-rolled JSON parser + writer (no System.Text.Json)
  Transport/              WebSocketServer, built on System.Net.HttpListener
  Protocol/               envelope parsing, inner message DTOs, nonce replay
                          tracking, plugin settings, plugin log
  UI/                     AssociateDialog (pairing consent prompt),
                          OptionsDialog (port / allowed Origins)
  Vendor/ChaosNaCl/       vendored NaCl primitives (Curve25519, Salsa20,
                          Poly1305) - source-vendored, not a NuGet package
  KeePassHttp2Ext.cs      the actual KeePass.Plugins.Plugin entry point
```

Every layer except `KeePassHttp2Ext.cs` itself is covered by xUnit tests
in `tests/KeePassHttp2.Tests/` against official test vectors (crypto),
real traffic captures (protocol), and a real `ClientWebSocket`
(transport). `KeePassHttp2Ext.cs` (dialogs, KeePassLib access) has no
automated coverage - it requires a live KeePass process with an open
database, which is out of scope for `dotnet test`. It's exercised
manually via `test_orchestrator_client.py`.

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

`global.json` pins the exact .NET SDK version this project builds with
(`rollForward: disable` - a different SDK version will refuse to build
rather than silently produce different bytes).

### Reproducible builds / verifying a release

`KeePassHttp2.csproj` sets `Deterministic`, `ContinuousIntegrationBuild`,
and `PathMap` - no NuGet package needed for this, they're plain
MSBuild/Roslyn switches. Given the same source and the exact SDK version
in `global.json`, anyone should get a byte-identical DLL:

```powershell
dotnet build src\KeePassHttp2 -c Release
Get-FileHash src\KeePassHttp2\bin\Release\net48\KeePassHttp2.dll -Algorithm SHA256
```

Each release should ship a `SHA256SUMS.txt` with the published DLL's
hash, so anyone who builds from the tagged source can confirm their own
build matches - i.e. confirm the published binary wasn't tampered with
or built from different code than what's in this repo.

## Install

Copy `bin\Debug\net48\KeePassHttp2.dll` (or `Release`, once you've built
that configuration) into your KeePass `Plugins` folder and restart
KeePass. It should appear under `Tools > Plugins`, and a
**"KeePassHttp2 Options..."** entry appears directly in the `Tools` menu.

If the plugin doesn't appear at all (no error, just missing from the
list): check the DLL's file version info - the `Product` field must be
exactly `KeePass Plugin`, or KeePass silently skips it while scanning the
folder. This is set via `<Product>KeePass Plugin</Product>` in the
csproj; don't remove it.

We deliberately did not package this as a `.plgx` - KeePass's built-in
PLGX compiler only supports up to C# 5, and this codebase uses `record`,
`init`-only properties, nullable reference types, and modern `switch`
expressions throughout. Rewriting down to C# 5 just for PLGX packaging
would cost far more than the plain-DLL install method it would save.

## Configure

`Tools > KeePassHttp2 Options...`:

- **Listen port** - default `19455`. Takes effect immediately; changing
  it restarts the internal WebSocket server without restarting KeePass.
- **Allowed WebSocket Origins** - comma-separated, empty = allow any
  (default). See "Known limitations" below - this is a weaker,
  supplementary check, not the actual trust boundary.

Settings are stored in `keepasshttp2-settings.json` next to the plugin
DLL (not `IPluginHost.CustomConfig` - see that file's header for why).

## Test

```powershell
cd tests/KeePassHttp2.Tests
dotnet test
```

Runs the full suite (crypto vectors, JSON parser/writer, protocol
envelope validation, transport handshake/close/shutdown/Origin
rejection, nonce replay tracking) - no KeePass process required for any
of this.

## Diagnostics

The plugin has no console (KeePass is a GUI app), so it logs to
`keepasshttp2.log` next to `KeePass.exe`.

**This log is intentionally minimal.** It never contains: full
request/response JSON, decrypted payload content, URLs from get-logins
requests (that's browsing history), full clientIDs, or passwords. If this
file is ever read by someone it shouldn't be, the most it should reveal
is "something connected and did X at time Y" - not which sites you
visited or what was in any message. The one deliberate exception is the
associate/test-associate audit trail (which pairing name was used, when)
- that's a feature, not a leak: it lets you notice an unexpected pairing
  in your own log.

## Manual end-to-end check

`test_orchestrator_client.py` drives a full real handshake against the
running plugin: `change-public-keys` -> `test-associate` (expected to
fail, not yet paired) -> `associate` (pops up a real Allow/Deny dialog in
KeePass - click Allow to see the full happy path) -> `test-associate`
again (now succeeds) -> encrypted `get-logins` -> a replayed-nonce check
(must be silently rejected).

```powershell
pip install websockets pynacl
python test_orchestrator_client.py
```

## Protocol status

Implemented:
- `change-public-keys` (ephemeral session key exchange)
- `associate` / `test-associate` (persistent pairing via a human-approved
  dialog, stored in the open database's `CustomData`)
- `get-logins` (encrypted, queries the currently open database by URL host)
- Nonce replay protection (per clientID)

Not yet implemented (rejected with `unhandled inner action`):
- `generate-password`, `lock-database`, `get-logins-count`

## Known limitations / accepted risks

These are deliberate, documented trade-offs, not oversights:

- **`test-associate` is a plain key comparison, not challenge-response.**
  This matches how the real KeePassXC-Browser protocol itself works -
  their own docs note this as a known, minor protocol weakness. We did
  not "fix" this ourselves because doing so would make us incompatible
  with the protocol we're implementing.
- **The Origin allow-list only stops real browsers, not local
  processes.** A browser can't lie about its own `Origin` header; any
  other local program can set it to whatever it wants, since it's just
  another HTTP header under the client's control. The actual trust
  boundary is the `associate` Allow/Deny dialog, not Origin filtering.
- **`associate`/`test-associate` currently have no automated test
  coverage.** They require a live KeePass process with an open database
  and a human clicking a real dialog - verified manually via
  `test_orchestrator_client.py`, not via `dotnet test`.
- **Client identification keys live in the database's `CustomData` in
  plaintext (base64).** This matches the original protocol's own design;
  anyone with read access to the `.kdbx` file's decrypted contents (i.e.
  anyone who could already open the database) can see which clients are
  paired.
- **A brief race exists when changing the port via the Options dialog**:
  during the moment `HttpListener` on the old port is closing while the
  new one starts, a connection attempt can get an inconsistent response
  instead of a clean refusal. Reconnecting a second later works
  correctly. Not security-relevant, just a rough edge during manual
  reconfiguration.

## Planned / future work

- A minimal custom browser extension (separate project, one codebase
  built for multiple browsers via a tool like `wxt.dev`) speaking this
  protocol directly over WebSocket in JS (`tweetnacl-js` for crypto_box) -
  the real KeePassXC-Browser extension can't be pointed at this plugin,
  since it only speaks Native Messaging, not raw WebSocket.