#!/usr/bin/env python3
"""Terminal two-way chat (server/client) with password auth.

- Works offline over LAN (no internet required).
- For remote use, you still need a network path (VPN/port forwarding/etc.).

This script intentionally avoids stealth/evasion features.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

PROTOCOL_VERSION = 1
DEFAULT_PORT = 5050
DEFAULT_CONFIG = "chat_config.json"
ENCODING = "utf-8"


def _normalize_fp(text: str) -> str:
    """Normalize certificate fingerprint input.

    Accepts hex with optional ':' separators. Returns lowercase hex without separators.
    """
    return "".join(ch for ch in text.strip().lower() if ch in "0123456789abcdef")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _supports_color() -> bool:
    # Enable ANSI processing on some Windows terminals
    if os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass

    try:
        import colorama  # type: ignore

        colorama.just_fix_windows_console()
        return True
    except Exception:
        return False


class _Ansi:
    RESET = "\x1b[0m"
    DIM = "\x1b[2m"
    BOLD = "\x1b[1m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    CYAN = "\x1b[36m"
    YELLOW = "\x1b[33m"


def _fmt_ts(ts: Optional[int]) -> str:
    if not ts:
        return ""
    try:
        return time.strftime("%H:%M:%S", time.localtime(int(ts)))
    except Exception:
        return ""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _pbkdf2_hash(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(ENCODING), salt, iterations, dklen=32)


def _load_config(path: str) -> Optional[dict[str, Any]]:
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_config(path: str, cfg: dict[str, Any]) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


def _ensure_password_config(path: str, reset: bool) -> dict[str, Any]:
    existing = _load_config(path)
    if existing is not None and not reset:
        return existing

    if existing is None:
        print(f"[i] Config not found: {path}")
    else:
        print(f"[i] Resetting password for config: {path}")

    env_pw = os.environ.get("CHAT_SETUP_PASSWORD")
    env_pw2 = os.environ.get("CHAT_SETUP_PASSWORD_CONFIRM")
    if env_pw is not None:
        pw1 = env_pw
        pw2 = env_pw if env_pw2 is None else env_pw2
        if not pw1:
            raise ValueError("CHAT_SETUP_PASSWORD must not be empty")
        if pw1 != pw2:
            raise ValueError("CHAT_SETUP_PASSWORD_CONFIRM does not match")
        print("[i] Password set from environment variables.")
    else:
        while True:
            pw1 = getpass.getpass("Create new password: ")
            pw2 = getpass.getpass("Confirm password: ")
            if not pw1:
                print("[!] Password must not be empty.")
                continue
            if pw1 != pw2:
                print("[!] Passwords do not match, try again.")
                continue
            break

    salt = secrets.token_bytes(16)
    iterations = 200_000
    pw_hash = _pbkdf2_hash(pw1, salt, iterations)

    cfg = {
        "protocol_version": PROTOCOL_VERSION,
        "auth": {
            "kdf": "pbkdf2_hmac_sha256",
            "iterations": iterations,
            "salt_b64": _b64e(salt),
            "hash_b64": _b64e(pw_hash),
        },
        "created_at": int(time.time()),
    }
    _save_config(path, cfg)
    print("[i] Password saved (hashed) in config.")
    return cfg


def _verify_password(cfg: dict[str, Any], password: str) -> bool:
    auth = cfg.get("auth") or {}
    if auth.get("kdf") != "pbkdf2_hmac_sha256":
        return False
    iterations = int(auth.get("iterations") or 0)
    salt_b64 = auth.get("salt_b64")
    hash_b64 = auth.get("hash_b64")
    if not iterations or not salt_b64 or not hash_b64:
        return False

    salt = _b64d(str(salt_b64))
    expected = _b64d(str(hash_b64))
    actual = _pbkdf2_hash(password, salt, iterations)
    return secrets.compare_digest(expected, actual)


def _json_send_line(writer, obj: dict[str, Any]) -> None:
    data = json.dumps(obj, ensure_ascii=False)
    writer.write(data + "\n")
    writer.flush()


def _json_recv_line(reader) -> Optional[dict[str, Any]]:
    line = reader.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


@dataclass
class ConnectedClient:
    sock: socket.socket
    reader: Any
    writer: Any
    address: tuple[str, int]
    name: str
    send_lock: threading.Lock


class ChatServer:
    def __init__(
        self,
        host: str,
        port: int,
        config_path: str,
        reset_password: bool,
        *,
        tls: bool,
        tls_cert: Optional[str],
        tls_key: Optional[str],
    ) -> None:
        self.host = host
        self.port = port
        self.cfg = _ensure_password_config(config_path, reset_password)
        self.tls = tls
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self._sock: Optional[socket.socket] = None
        self._clients: list[ConnectedClient] = []
        self._clients_lock = threading.Lock()
        self._stop = threading.Event()

        self._ssl_context: Optional[ssl.SSLContext] = None
        if self.tls:
            if not self.tls_cert or not self.tls_key:
                raise ValueError("TLS enabled but --tls-cert/--tls-key not provided")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)
            self._ssl_context = ctx

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        transport = "TLS" if self.tls else "TCP"
        print(f"[+] Server listening on {self.host}:{self.port} ({transport})")
        print("[i] Stop: press Ctrl+C")

        try:
            while not self._stop.is_set():
                try:
                    client_sock, addr = self._sock.accept()
                except OSError:
                    break
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\n[i] Server stopped.")
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._clients_lock:
            clients = list(self._clients)
            self._clients.clear()
        for c in clients:
            try:
                c.sock.close()
            except OSError:
                pass

    def _broadcast(self, obj: dict[str, Any], *, exclude: Optional[ConnectedClient] = None) -> None:
        with self._clients_lock:
            targets = list(self._clients)
        for c in targets:
            if exclude is not None and c is exclude:
                continue
            try:
                with c.send_lock:
                    _json_send_line(c.writer, obj)
            except OSError:
                pass

    def _remove_client(self, client: ConnectedClient) -> None:
        with self._clients_lock:
            self._clients = [c for c in self._clients if c is not client]

    def _handle_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        raw_sock = client_sock
        raw_sock.settimeout(30)

        sock: socket.socket
        if self._ssl_context is not None:
            try:
                sock = self._ssl_context.wrap_socket(raw_sock, server_side=True)
            except ssl.SSLError:
                try:
                    raw_sock.close()
                except OSError:
                    pass
                return
        else:
            sock = raw_sock

        reader = sock.makefile("r", encoding="utf-8", newline="\n")
        writer = sock.makefile("w", encoding="utf-8", newline="\n")

        try:
            _json_send_line(writer, {"type": "hello", "version": PROTOCOL_VERSION})

            auth_msg = _json_recv_line(reader)
            if not auth_msg or auth_msg.get("type") != "auth":
                _json_send_line(writer, {"type": "error", "message": "auth_required"})
                return

            name = str(auth_msg.get("name") or "").strip()[:32]
            password = str(auth_msg.get("password") or "")
            if not name:
                _json_send_line(writer, {"type": "error", "message": "name_required"})
                return

            if not _verify_password(self.cfg, password):
                _json_send_line(writer, {"type": "auth_fail", "message": "invalid_password"})
                return

            sock.settimeout(None)
            cc = ConnectedClient(
                sock=sock,
                reader=reader,
                writer=writer,
                address=addr,
                name=name,
                send_lock=threading.Lock(),
            )

            with self._clients_lock:
                self._clients.append(cc)

            _json_send_line(writer, {"type": "auth_ok", "message": "welcome"})
            self._broadcast({"type": "system", "message": f"{name} joined.", "ts": int(time.time())}, exclude=cc)
            print(f"[+] {name} connected from {addr[0]}:{addr[1]}")

            while True:
                msg = _json_recv_line(reader)
                if msg is None:
                    break
                if msg.get("type") == "msg":
                    text = str(msg.get("text") or "")
                    text = text.replace("\r", "").replace("\n", " ").strip()
                    if not text:
                        continue
                    if len(text) > 1000:
                        text = text[:1000] + "…"
                    payload = {
                        "type": "msg",
                        "from": name,
                        "text": text,
                        "ts": int(time.time()),
                    }
                    self._broadcast(payload)
                elif msg.get("type") == "ping":
                    _json_send_line(writer, {"type": "pong", "ts": int(time.time())})
                else:
                    _json_send_line(writer, {"type": "error", "message": "unknown_message"})

        except (ConnectionError, OSError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

            # If authenticated, remove and announce
            try:
                with self._clients_lock:
                    known = next((c for c in self._clients if c.sock is sock), None)
                if known is not None:
                    self._remove_client(known)
                    self._broadcast({"type": "system", "message": f"{known.name} left.", "ts": int(time.time())})
                    print(f"[-] {known.name} disconnected")
            except Exception:
                pass


class ChatClient:
    def __init__(
        self,
        server_host: str,
        port: int,
        name: str,
        password: str,
        *,
        use_color: bool,
        show_timestamps: bool,
        set_title: bool,
    ) -> None:
        self.server_host = server_host
        self.port = port
        self.name = name
        self.password = password
        self.sock: Optional[socket.socket] = None
        self.reader = None
        self.writer = None
        self._stop = threading.Event()
        self.use_color = use_color
        self.show_timestamps = show_timestamps
        self.set_title = set_title

    def _c(self, text: str, color: str) -> str:
        if not self.use_color:
            return text
        return f"{color}{text}{_Ansi.RESET}"

    def _print_msg(self, sender: str, text: str, ts: Optional[int]) -> None:
        prefix = ""
        if self.show_timestamps:
            t = _fmt_ts(ts)
            if t:
                prefix = self._c(f"[{t}] ", _Ansi.DIM)
        if sender == self.name:
            sender_fmt = self._c("YOU", _Ansi.GREEN)
        else:
            sender_fmt = self._c(str(sender), _Ansi.CYAN)
        print(f"{prefix}{sender_fmt}: {text}")

    def _print_system(self, text: str, ts: Optional[int]) -> None:
        prefix = ""
        if self.show_timestamps:
            t = _fmt_ts(ts)
            if t:
                prefix = self._c(f"[{t}] ", _Ansi.DIM)
        star = self._c("*", _Ansi.YELLOW)
        print(f"{prefix}{star} {text}")

    def _print_header(self) -> None:
        width = 62
        line = "=" * width
        title = " TERMINAL CHAT "
        title_line = title.center(width, "=")

        transport = "TLS" if isinstance(self.sock, ssl.SSLSocket) else "TCP"
        net_path = "VPN/LAN"  # informational label; actual path is determined by your network setup

        def row(label: str, value: str) -> str:
            label = f"{label}:"
            return f"{label:<12}{value}"

        print(line)
        print(self._c(title_line, _Ansi.BOLD) if self.use_color else title_line)
        print(line)
        print(row("User", self.name))
        print(row("Server", f"{self.server_host}:{self.port}"))
        print(row("Transport", transport))
        print(row("Network", net_path))
        print(line)
        print(self._c("[+] CONNECTED", _Ansi.GREEN) + self._c("  Ready to chat.", _Ansi.DIM))
        print(self._c("[i] Type and press Enter.", _Ansi.DIM))
        print(self._c("[i] /help  /quit  /cls", _Ansi.DIM))
        print("")

    def run(self, *, once_message: Optional[str] = None) -> None:
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.connect((self.server_host, self.port))
            self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
            self.writer = self.sock.makefile("w", encoding="utf-8", newline="\n")
        else:
            # Socket was pre-established (e.g., TLS-wrapped) by the caller.
            if self.reader is None or self.writer is None:
                self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
                self.writer = self.sock.makefile("w", encoding="utf-8", newline="\n")

        hello = _json_recv_line(self.reader)
        if not hello or hello.get("type") != "hello":
            raise RuntimeError("Incompatible server")

        _json_send_line(self.writer, {"type": "auth", "name": self.name, "password": self.password})
        resp = _json_recv_line(self.reader)
        if not resp:
            raise RuntimeError("Server did not respond")
        if resp.get("type") == "auth_fail":
            raise RuntimeError("Invalid password")
        if resp.get("type") != "auth_ok":
            raise RuntimeError(f"Login failed: {resp}")

        # Avoid idle read timeouts: after auth, keep the connection open indefinitely.
        # (The initial 15s timeout is only for connect+handshake.)
        try:
            self.sock.settimeout(None)
        except Exception:
            pass

        if self.set_title and os.name == "nt":
            safe_host = self.server_host.replace("\"", "").replace("\r", "").replace("\n", "")
            safe_name = self.name.replace("\"", "").replace("\r", "").replace("\n", "")
            os.system(f"title Terminal Chat - {safe_name} @ {safe_host}:{self.port}")

        if once_message is not None:
            text = once_message.replace("\r", "").replace("\n", " ").strip()
            if text:
                _json_send_line(self.writer, {"type": "msg", "text": text})
                time.sleep(0.2)
            try:
                if self.sock is not None:
                    self.sock.close()
            except OSError:
                pass
            return

        os.system("cls" if os.name == "nt" else "clear")
        self._print_header()

        t = threading.Thread(target=self._recv_loop, daemon=True)
        t.start()

        try:
            while not self._stop.is_set():
                try:
                    line = input()
                except EOFError:
                    break
                line = line.strip()
                if not line:
                    continue
                if line.lower() in {"/q", "/quit", "/exit"}:
                    break
                if line.lower() == "/help":
                    print("Commands:")
                    print("  /help  Show help")
                    print("  /quit  Quit")
                    print("  /cls   Clear screen")
                    continue
                if line.lower() in {"/cls", "/clear"}:
                    os.system("cls" if os.name == "nt" else "clear")
                    continue
                _json_send_line(self.writer, {"type": "msg", "text": line})
        except KeyboardInterrupt:
            pass
        finally:
            self._stop.set()
            try:
                if self.sock is not None:
                    self.sock.close()
            except OSError:
                pass

    def _recv_loop(self) -> None:
        assert self.reader is not None
        while not self._stop.is_set():
            try:
                msg = _json_recv_line(self.reader)
            except TimeoutError:
                # Should not happen when socket timeout is None, but be defensive.
                continue
            if msg is None:
                print("[i] Disconnected from server.")
                self._stop.set()
                return

            mtype = msg.get("type")
            if mtype == "msg":
                sender = msg.get("from")
                text = msg.get("text")
                self._print_msg(str(sender), str(text), msg.get("ts"))
            elif mtype == "system":
                self._print_system(str(msg.get("message")), msg.get("ts"))
            else:
                # Ignore pongs/errors for now
                pass


def _prompt_if_empty(value: Optional[str], prompt: str) -> str:
    if value:
        return value
    while True:
        x = input(prompt).strip()
        if x:
            return x


def main() -> int:
    parser = argparse.ArgumentParser(description="Terminal chat (server/client) with password")
    parser.add_argument("--mode", choices=["server", "client"], help="Run as server or client")

    parser.add_argument("--host", default="0.0.0.0", help="(server) Bind host, default 0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port, default {DEFAULT_PORT}")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help=f"(server) Config path, default {DEFAULT_CONFIG}")
    parser.add_argument("--reset-password", action="store_true", help="(server) Reset password")

    parser.add_argument("--tls", action="store_true", help="Enable TLS transport")
    parser.add_argument("--tls-cert", help="(server) TLS certificate PEM file")
    parser.add_argument("--tls-key", help="(server) TLS private key PEM file")
    parser.add_argument(
        "--tls-fingerprint",
        help="(client) Expected server certificate SHA256 fingerprint (hex, optional ':')",
    )

    parser.add_argument(
        "--print-fingerprint",
        metavar="CERT_PEM",
        help="Print SHA256 fingerprint for a PEM certificate and exit",
    )

    parser.add_argument("--server", dest="server_host", help="(client) IP/hostname server")
    parser.add_argument("--name", help="(client) User name")
    parser.add_argument("--once", help="(client) Send one message then exit (non-interactive)")
    parser.add_argument("--no-color", action="store_true", help="(client) Disable colored output")
    parser.add_argument("--no-ts", action="store_true", help="(client) Hide timestamps")
    parser.add_argument("--no-title", action="store_true", help="(client) Do not set the CMD window title")

    args = parser.parse_args()

    if args.print_fingerprint:
        with open(args.print_fingerprint, "r", encoding="utf-8") as f:
            pem = f.read()
        der = ssl.PEM_cert_to_DER_cert(pem)
        print(_sha256_hex(der))
        return 0

    mode = args.mode
    if not mode:
        print("Select mode: 1) server  2) client")
        choice = input("Choice (1/2): ").strip()
        mode = "server" if choice == "1" else "client"

    if mode == "server":
        server = ChatServer(
            host=args.host,
            port=args.port,
            config_path=args.config,
            reset_password=args.reset_password,
            tls=bool(args.tls),
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
        server.serve_forever()
        return 0

    # client
    server_host = _prompt_if_empty(args.server_host, "Server IP/hostname: ")
    name = _prompt_if_empty(args.name, "Your name: ")
    password = os.environ.get("CHAT_PASSWORD")
    if password is None:
        password = getpass.getpass("Password: ")
    if not password:
        print("[!] Empty password.")
        return 2

    try:
        use_color = (not args.no_color) and _supports_color()
        show_timestamps = not args.no_ts
        set_title = (os.name == "nt") and (not args.no_title)
        # Establish TCP socket first, then optionally upgrade to TLS.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((server_host, args.port))

        if args.tls:
            fp_expected = _normalize_fp(args.tls_fingerprint) if args.tls_fingerprint else ""
            if fp_expected:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=server_host)
                cert_bin = tls_sock.getpeercert(binary_form=True) or b""
                fp_actual = _sha256_hex(cert_bin)
                if fp_actual != fp_expected:
                    tls_sock.close()
                    raise RuntimeError(
                        "TLS fingerprint mismatch. "
                        f"Expected {fp_expected}, got {fp_actual}."
                    )
                sock = tls_sock
            else:
                # Use system trust store + hostname validation (best when using a CA-signed cert).
                ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                sock = ctx.wrap_socket(sock, server_hostname=server_host)

        # Continue with the regular protocol using the (possibly TLS-wrapped) socket.
        client = ChatClient(
            server_host=server_host,
            port=args.port,
            name=name,
            password=password,
            use_color=use_color,
            show_timestamps=show_timestamps,
            set_title=set_title,
        )
        client.sock = sock
        client.reader = sock.makefile("r", encoding="utf-8", newline="\n")
        client.writer = sock.makefile("w", encoding="utf-8", newline="\n")
        client.run(once_message=args.once)
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
