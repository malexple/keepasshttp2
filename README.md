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

## TCP -> WebSocket handshake -> frame echo server.
```bash
zig build-exe ws_handshake.zig
.\ws_handshake.exe
```

Выполнить в консоли браузера
```javascript
const ws = new WebSocket("ws://127.0.0.1:19455/");
ws.onopen = () => { console.log("OPEN"); ws.send("hello"); };
ws.onmessage = (e) => console.log("MSG:", e.data);
ws.onclose = () => console.log("CLOSED");
```


Получаем в консоли сервер
```bash
Connection accepted
LINE: [GET / HTTP/1.1]
LINE: [Host: 127.0.0.1:19455]
LINE: [Connection: Upgrade]
LINE: [Pragma: no-cache]
LINE: [Cache-Control: no-cache]
LINE: [User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36]
LINE: [Upgrade: websocket]
LINE: [Origin: https://git.malexple.ru]
LINE: [Sec-WebSocket-Version: 13]
LINE: [Accept-Encoding: gzip, deflate, br, zstd]
LINE: [Accept-Language: en-US,en;q=0.9]
LINE: [Sec-WebSocket-Key: oe7CURXuKi5whB9PTx2OEQ==]
LINE: [Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits]
LINE: []
--- end of headers ---
Sent 101 response, Accept: ar5RQtHCpiss1MUyUCP08hYDcgs=
FRAME opcode=1 fin=true payload="hello"
echoed back "hello"

```

В консоли браузера
```bash
OPEN
MSG: hello
```

## python websocket client ws_test_client.py

pip install websockets
python ws_test_client.py

python -m pip install websockets
python ws_test_client.py
