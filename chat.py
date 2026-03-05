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
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

PROTOCOL_VERSION = 1
DEFAULT_PORT = 5050
DEFAULT_CONFIG = "chat_config.json"
ENCODING = "utf-8"


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
        print(f"[i] Config belum ada: {path}")
    else:
        print(f"[i] Reset password untuk config: {path}")

    env_pw = os.environ.get("CHAT_SETUP_PASSWORD")
    env_pw2 = os.environ.get("CHAT_SETUP_PASSWORD_CONFIRM")
    if env_pw is not None:
        pw1 = env_pw
        pw2 = env_pw if env_pw2 is None else env_pw2
        if not pw1:
            raise ValueError("CHAT_SETUP_PASSWORD tidak boleh kosong")
        if pw1 != pw2:
            raise ValueError("CHAT_SETUP_PASSWORD_CONFIRM tidak cocok")
        print("[i] Password di-set dari environment variable.")
    else:
        while True:
            pw1 = getpass.getpass("Buat password baru: ")
            pw2 = getpass.getpass("Ulangi password: ")
            if not pw1:
                print("[!] Password tidak boleh kosong.")
                continue
            if pw1 != pw2:
                print("[!] Password tidak sama, coba lagi.")
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
    print("[i] Password tersimpan (hash) di config.")
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
    def __init__(self, host: str, port: int, config_path: str, reset_password: bool) -> None:
        self.host = host
        self.port = port
        self.cfg = _ensure_password_config(config_path, reset_password)
        self._sock: Optional[socket.socket] = None
        self._clients: list[ConnectedClient] = []
        self._clients_lock = threading.Lock()
        self._stop = threading.Event()

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(50)
        print(f"[+] Server listening di {self.host}:{self.port}")
        print("[i] Stop: tekan Ctrl+C")

        try:
            while not self._stop.is_set():
                try:
                    client_sock, addr = self._sock.accept()
                except OSError:
                    break
                t = threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True)
                t.start()
        except KeyboardInterrupt:
            print("\n[i] Server dihentikan.")
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
        client_sock.settimeout(30)
        reader = client_sock.makefile("r", encoding="utf-8", newline="\n")
        writer = client_sock.makefile("w", encoding="utf-8", newline="\n")

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
                _json_send_line(writer, {"type": "auth_fail", "message": "password_salah"})
                return

            client_sock.settimeout(None)
            cc = ConnectedClient(
                sock=client_sock,
                reader=reader,
                writer=writer,
                address=addr,
                name=name,
                send_lock=threading.Lock(),
            )

            with self._clients_lock:
                self._clients.append(cc)

            _json_send_line(writer, {"type": "auth_ok", "message": "selamat_datang"})
            self._broadcast({"type": "system", "message": f"{name} bergabung.", "ts": int(time.time())}, exclude=cc)
            print(f"[+] {name} connected dari {addr[0]}:{addr[1]}")

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
                client_sock.close()
            except OSError:
                pass

            # If authenticated, remove and announce
            try:
                with self._clients_lock:
                    known = next((c for c in self._clients if c.sock is client_sock), None)
                if known is not None:
                    self._remove_client(known)
                    self._broadcast({"type": "system", "message": f"{known.name} keluar.", "ts": int(time.time())})
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

    def run(self, *, once_message: Optional[str] = None) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect((self.server_host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8", newline="\n")
        self.writer = self.sock.makefile("w", encoding="utf-8", newline="\n")

        hello = _json_recv_line(self.reader)
        if not hello or hello.get("type") != "hello":
            raise RuntimeError("Server tidak kompatibel")

        _json_send_line(self.writer, {"type": "auth", "name": self.name, "password": self.password})
        resp = _json_recv_line(self.reader)
        if not resp:
            raise RuntimeError("Server tidak merespons")
        if resp.get("type") == "auth_fail":
            raise RuntimeError("Password salah")
        if resp.get("type") != "auth_ok":
            raise RuntimeError(f"Gagal login: {resp}")

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
            return

        os.system("cls" if os.name == "nt" else "clear")
        banner_left = self._c("OPERATOR CONSOLE", _Ansi.BOLD) if self.use_color else "OPERATOR CONSOLE"
        print("=" * 46)
        print(f"{banner_left}  (via VPN)")
        print("=" * 46)
        print(self._c("[+] CONNECTED", _Ansi.GREEN) + f"  {self.name} -> {self.server_host}:{self.port}")
        print(self._c("[i] Ketik pesan lalu Enter.", _Ansi.DIM))
        print(self._c("[i] Perintah: /help, /quit, /cls", _Ansi.DIM))
        print("")

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
                    print("Perintah tersedia:")
                    print("  /help  - bantuan")
                    print("  /quit  - keluar")
                    print("  /cls   - bersihkan layar")
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
                print("[i] Terputus dari server.")
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
    parser = argparse.ArgumentParser(description="Terminal chat (server/client) dengan password")
    parser.add_argument("--mode", choices=["server", "client"], help="Jalankan sebagai server atau client")

    parser.add_argument("--host", default="0.0.0.0", help="(server) Bind host, default 0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port, default {DEFAULT_PORT}")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help=f"(server) Path config, default {DEFAULT_CONFIG}")
    parser.add_argument("--reset-password", action="store_true", help="(server) Reset password")

    parser.add_argument("--server", dest="server_host", help="(client) IP/hostname server")
    parser.add_argument("--name", help="(client) Nama pengguna")
    parser.add_argument("--once", help="(client) Kirim 1 pesan lalu keluar (non-interaktif)")
    parser.add_argument("--no-color", action="store_true", help="(client) Matikan output berwarna")
    parser.add_argument("--no-ts", action="store_true", help="(client) Sembunyikan timestamp")
    parser.add_argument("--no-title", action="store_true", help="(client) Jangan set judul window CMD")

    args = parser.parse_args()

    mode = args.mode
    if not mode:
        print("Pilih mode: 1) server  2) client")
        choice = input("Pilihan (1/2): ").strip()
        mode = "server" if choice == "1" else "client"

    if mode == "server":
        server = ChatServer(host=args.host, port=args.port, config_path=args.config, reset_password=args.reset_password)
        server.serve_forever()
        return 0

    # client
    server_host = _prompt_if_empty(args.server_host, "Server IP/hostname: ")
    name = _prompt_if_empty(args.name, "Nama kamu: ")
    password = os.environ.get("CHAT_PASSWORD")
    if password is None:
        password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password kosong.")
        return 2

    try:
        use_color = (not args.no_color) and _supports_color()
        show_timestamps = not args.no_ts
        set_title = (os.name == "nt") and (not args.no_title)
        client = ChatClient(
            server_host=server_host,
            port=args.port,
            name=name,
            password=password,
            use_color=use_color,
            show_timestamps=show_timestamps,
            set_title=set_title,
        )
        client.run(once_message=args.once)
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
