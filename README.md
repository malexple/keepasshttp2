## KeePassHttp2

```bash
zig build
dotnet build
Copy-Item keepasshttp2.dll bin\Debug\net8.0\keepasshttp2.dll -Force
dotnet bin\Debug\net8.0\keepasshttp2.dll
```


## webSocket
```bash
zig build-exe tcp_probe.zig
.\tcp_probe.exe
```

```bash
curl.exe -v --http1.1 -H "Upgrade: websocket" -H "Connection: Upgrade" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" -H "Sec-WebSocket-Version: 13" http://127.0.0.1:19455/
```

## crypto

````bash
zig build-exe ws_accept_test.zig
.\ws_accept_test.exe
````