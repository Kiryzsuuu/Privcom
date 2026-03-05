# Terminal Chat (CMD) + Password

Two-way chat over the Windows terminal (CMD/PowerShell). Designed for **LAN / direct IP** use.

Important: “No VPN” is possible, but you still need a **network path** from the client to `IP:PORT` (LAN, port-forwarding, public server, etc.). If there is no network path at all, two computers cannot exchange messages.

## Requirements

- Windows 10/11
- Python 3.10+

Check:

```bat
py -3 --version
```

If `py -3` is not available, `chat.bat` will try `python` / `python3` automatically.

## Quick start (double-click)

1. Run `chat.bat`.
2. Select:
   - `1` for **SERVER** (host)
   - `2` for **CLIENT**

## Server (host)

On first run, the server asks you to create a password. The password is stored as a **hash** (not plaintext) in `chat_config.json`.

Default settings:

- Port: `5050`
- Bind host: `0.0.0.0` (accept connections from LAN)

Run manually:

```bat
py -3 chat.py --mode server
```

### (Optional) Show client location (GeoIP)

The server can **optionally** display an approximate location (city/region/country)
for **public** client IPs. This is best-effort and **requires internet**.

Enable:

```bat
py -3 chat.py --mode server --geoip
```

Notes:

- For LAN/private IPs (e.g. `192.168.x.x`), it will show `LAN/private`.
- This only affects the server console output (it does not broadcast location to clients).

Reset password:

```bat
py -3 chat.py --mode server --reset-password
```

## Client

Run manually:

```bat
py -3 chat.py --mode client --server 192.168.1.10
```

### (Optional) Send GPS / Windows Location Services to server

If Windows Location Services is enabled, the client can send coordinates (latitude/longitude)
to the server **with your consent**.

Send once on connect:

```bat
py -3 chat.py --mode client --server 192.168.1.10 --gps
```

Or while connected, type:

- `/gps` (sent to server console only)

Notes:

- This requires Windows location permission and may fail if blocked/disabled.
- The server logs it and acknowledges only to the sender (not broadcast to others).

## Chat commands

- `/help` show help
- `/quit` quit
- `/cls` clear screen
- `/gps` send current Windows location to server (server-only)

## Nicer CMD output (optional)

The client can show colored names + timestamps (when ANSI is supported).

Options:

- Disable color: `--no-color`
- Hide timestamps: `--no-ts`

If colors do not show on older CMD, install:

```bat
py -3 -m pip install colorama
```

## Automation / non-interactive (optional)

- Reset server password via environment variables:

```bat
set CHAT_SETUP_PASSWORD=YourPassword
set CHAT_SETUP_PASSWORD_CONFIRM=YourPassword
py -3 chat.py --mode server --reset-password
```

- Send one message and exit:

```bat
set CHAT_PASSWORD=YourPassword
py -3 chat.py --mode client --server 127.0.0.1 --name Alice --once "hello"
```

## Remote use (most secure)

For use over the internet/WAN, the safest option is **TLS encryption + certificate fingerprint pinning**.

### 1) Create a self-signed certificate (OpenSSL)

If you have `openssl` available:

```bat
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes ^
  -keyout server.key -out server.crt -subj "/CN=terminal-chat"
```

### 2) Get the SHA256 fingerprint

Use the built-in helper:

```bat
py -3 chat.py --print-fingerprint server.crt
```

### 3) Run server with TLS

```bat
py -3 chat.py --mode server --tls --tls-cert server.crt --tls-key server.key
```

### 4) Run client with TLS + fingerprint pinning

```bat
py -3 chat.py --mode client --tls --tls-fingerprint YOUR_SHA256_FP --server SERVER_IP_OR_DNS
```

Notes:

- If you do **not** provide `--tls-fingerprint`, the client will use the system trust store + hostname validation (best when using a CA-signed certificate for a real domain).
- Fingerprint pinning is the recommended approach for self-signed certs.

## Remote use without VPN (port forwarding)

This works if your server machine can be reached from outside.

1. Give the server a stable LAN IP (DHCP reservation recommended).
2. On your router, forward TCP `5050` -> `SERVER_LAN_IP:5050`.
3. Check for **CGNAT**: if your router WAN IP is in `10.x.x.x`, `192.168.x.x`, or `100.64.x.x`, port-forwarding from the internet usually won’t work.

Then connect from outside:

```bat
py -3 chat.py --mode client --server PUBLIC_IP_OR_DDNS --port 5050
```
