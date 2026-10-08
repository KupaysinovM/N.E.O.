"""
dashboard/server.py — NEO remote HTTPS dashboard

HTTPS on port 8000 using an installation-local self-signed certificate.
Dashboard commands use the TLS-protected same-origin session.

Install deps:  pip install fastapi "uvicorn[standard]" cryptography
"""

import asyncio
import re
import secrets
import socket
import string
import threading
import time
from collections import deque
from pathlib import Path

_DEPS_OK = False
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    import uvicorn
    _DEPS_OK = True
except ImportError:
    pass

# python-multipart is required for file uploads — optional dependency
_UPLOAD_OK = False
try:
    from fastapi import UploadFile, File as FastAPIFile
    _UPLOAD_OK = True
except Exception:
    pass

BASE_DIR    = Path(__file__).resolve().parent.parent
STATIC_DIR  = Path(__file__).parent / "static"
PORT        = 8000
MAX_UPLOAD_MB = 500


def _make_uploads_dir() -> Path:
    """Return (and create) the cross-platform uploads folder."""
    for candidate in [
        Path.home() / "Downloads" / "NEO Uploads",
        Path.home() / "Documents" / "NEO Uploads",
        BASE_DIR / "uploads",
    ]:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except Exception:
            pass
    return BASE_DIR / "uploads"


UPLOADS_DIR = _make_uploads_dir()

def _get_gemini_key() -> str | None:
    """The credential comes from core/secret_store.py, never a settings file."""
    try:
        from core import secret_store
        return secret_store.get_api_key() or None
    except Exception:
        return None

_KEY_CHARS = [c for c in (string.ascii_uppercase + string.digits)
              if c not in ('O', 'I', 'L', '0', '1')]

def _ensure_network_access(port: int) -> None:
    """Cross-platform, best-effort: open port in the OS firewall for LAN access.

    Runs in a background thread — never blocks uvicorn startup.

    Windows : writes a .bat file, runs it elevated via Windows ShellExecuteW
              (native UAC dialog, guaranteed to appear). One-time setup.
    macOS   : osascript admin dialog if the Application Firewall is on.
    Linux   : pkexec GUI → sudo -n → prints manual command as fallback.
    """
    import sys, subprocess, os, tempfile, threading

    # ── Windows ──────────────────────────────────────────────────────────────
    if sys.platform == "win32":
        import ctypes, time

        port_rule = f"NEO Dashboard Port {port}"
        prog_rule  = "NEO Dashboard Python"
        py_exe     = sys.executable

        def _netsh_rule_exists(name: str) -> bool:
            try:
                r = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"],
                    capture_output=True, text=True, timeout=5,
                )
                return r.returncode == 0 and "No rules match" not in r.stdout
            except Exception:
                return False

        def _network_is_public() -> bool:
            try:
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "(Get-NetConnectionProfile | "
                     "Where-Object {$_.NetworkCategory -eq 'Public'} | "
                     "Measure-Object).Count"],
                    capture_output=True, text=True, timeout=6,
                )
                return r.stdout.strip() not in ("", "0")
            except Exception:
                return False

        need_port    = not _netsh_rule_exists(port_rule)
        need_prog    = not _netsh_rule_exists(prog_rule)
        need_private = _network_is_public()

        if not need_port and not need_prog and not need_private:
            return  # already fully configured

        # Build a .bat file — netsh + powershell, runs fast when elevated
        bat_lines = ["@echo off"]
        if need_private:
            bat_lines.append(
                'powershell -NoProfile -NonInteractive -Command "'
                'Get-NetConnectionProfile | '
                "Where-Object {$_.NetworkCategory -eq 'Public'} | "
                'Set-NetConnectionProfile -NetworkCategory Private"'
            )
        if need_port:
            bat_lines.append(
                f'netsh advfirewall firewall add rule '
                f'name="{port_rule}" protocol=TCP dir=in '
                f'localport={port} action=allow'
            )
        if need_prog:
            bat_lines.append(
                f'netsh advfirewall firewall add rule '
                f'name="{prog_rule}" dir=in action=allow '
                f'program="{py_exe}" enable=yes'
            )

        bat_body = "\r\n".join(bat_lines) + "\r\n"
        fd, bat_path = tempfile.mkstemp(suffix=".bat", prefix="neo_fw_")
        try:
            os.write(fd, bat_body.encode("mbcs"))   # Windows cmd.exe expects ANSI
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            return

        # ── Try running directly (succeeds when already admin) ────────────────
        try:
            r = subprocess.run(
                [bat_path], capture_output=True, timeout=8, shell=True
            )
            if r.returncode == 0:
                print(f"[Dashboard] Firewall configured for port {port}.")
                try:
                    os.unlink(bat_path)
                except Exception:
                    pass
                return
        except Exception:
            pass

        # ── ShellExecuteW: native UAC elevation (most reliable on Windows) ────
        # ShellExecuteW with verb "runas" always shows the UAC dialog regardless
        # of UAC level settings. Non-blocking — uvicorn is already running.
        print("[Dashboard] One-time network setup required.")
        print("[Dashboard] >>> A Windows security dialog will appear — click 'Yes' <<<")
        try:
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,       # hwnd  (no parent window)
                "runas",    # verb  (request elevation)
                bat_path,   # file  (our .bat)
                None,       # params
                None,       # working dir
                0,          # SW_HIDE (run without a visible cmd window)
            )
            if int(ret) > 32:
                # ShellExecuteW returns immediately; bat finishes in ~1 second.
                # Sleep briefly so the rules are in place before the first retry.
                time.sleep(2)
                print(f"[Dashboard] Network setup complete — port {port} is open.")
                print("[Dashboard] Refresh your phone browser to connect.")
            else:
                print("[Dashboard] Setup was not allowed.")
                print("[Dashboard] Phone connections may fail until NEO is run as Administrator.")
        except Exception as e:
            print(f"[Dashboard] Firewall setup error: {e}")
        finally:
            # Cleanup after the bat has had time to run
            def _cleanup(path: str) -> None:
                time.sleep(5)
                try:
                    os.unlink(path)
                except Exception:
                    pass
            threading.Thread(target=_cleanup, args=(bat_path,), daemon=True).start()
        return

    # ── macOS ─────────────────────────────────────────────────────────────────
    if sys.platform == "darwin":
        fw_ctl = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        try:
            r = subprocess.run(
                [fw_ctl, "--getglobalstate"], capture_output=True, text=True, timeout=5,
            )
            if "disabled" in r.stdout.lower():
                return  # firewall off — nothing to do

            py = sys.executable
            listed = subprocess.run(
                [fw_ctl, "--listapps"], capture_output=True, text=True, timeout=5,
            )
            if py in listed.stdout:
                return  # already allowed

            print("[Dashboard] One-time network setup — enter your password in the macOS dialog.")
            subprocess.run(
                ["osascript", "-e",
                 f'do shell script "{fw_ctl} --add {py} && {fw_ctl} --unblockapp {py}"'
                 f' with administrator privileges'],
                timeout=60,
            )
        except Exception:
            pass  # macOS firewall is off by default — silent failure is fine
        return

    # ── Linux ─────────────────────────────────────────────────────────────────
    def _privileged(cmd: list[str]) -> bool:
        for prefix in (["pkexec"], ["sudo", "-n"]):
            try:
                r = subprocess.run(prefix + cmd, capture_output=True, timeout=30)
                if r.returncode == 0:
                    return True
            except Exception:
                pass
        return False

    try:  # ufw
        r = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
        if "active" in r.stdout.lower():
            if _privileged(["ufw", "allow", f"{port}/tcp"]):
                print(f"[Dashboard] ufw: port {port} allowed.")
            else:
                print(f"[Dashboard] Run manually:  sudo ufw allow {port}/tcp")
            return
    except FileNotFoundError:
        pass

    try:  # firewalld
        r = subprocess.run(
            ["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5,
        )
        if "running" in r.stdout.lower():
            ok = (_privileged(["firewall-cmd", "--add-port", f"{port}/tcp", "--permanent"])
                  and _privileged(["firewall-cmd", "--reload"]))
            if ok:
                print(f"[Dashboard] firewalld: port {port} allowed.")
            else:
                print(f"[Dashboard] Run manually:  sudo firewall-cmd --add-port={port}/tcp --permanent && sudo firewall-cmd --reload")
            return
    except FileNotFoundError:
        pass

    try:  # iptables (not persistent but works until reboot)
        r = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, timeout=5)
        if r.returncode == 0:
            if _privileged(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"]):
                print(f"[Dashboard] iptables: port {port} opened.")
            else:
                print(f"[Dashboard] Run manually:  sudo iptables -A INPUT -p tcp --dport {port} -j ACCEPT")
    except FileNotFoundError:
        pass  # no iptables means firewall is probably off — nothing to do


def _firewall_assist_enabled() -> bool:
    """Off by default. NEO does not touch the host firewall or the network
    profile on its own — not even when the remote dashboard was switched on."""
    try:
        from config import get_config
        return bool(get_config().get("dashboard_open_firewall", False))
    except Exception:
        return False


# ── helpers ───────────────────────────────────────────────────────────────────

def _local_ip() -> str:
    """Return the best LAN-facing IPv4 address, no internet required."""
    # Method 1: route trick (fast, works when internet is available)
    for probe in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect((probe, 80))
            ip = s.getsockname()[0]
            s.close()
            if not ip.startswith("127."):
                return ip
        except Exception:
            pass

    # Method 2: hostname resolution (works offline on most systems)
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass

    # Method 3: enumerate all interfaces (fully offline, no external deps)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                return ip
    except Exception:
        pass

    return "127.0.0.1"


def _ensure_certs() -> bool:
    """
    Make sure config/certs holds a TLS key pair, generating a self-signed one the
    first time the dashboard runs.

    The pair is deliberately NOT shipped in the repository. A private key that
    every user downloads is the same as having no private key at all: anyone can
    present a certificate that matches it. Generating locally gives each install
    its own key, costs about a second, and happens exactly once.

    Returns True when a usable pair exists afterwards; False leaves the caller on
    no dashboard service. Plain HTTP would expose PINs and session tokens.
    """
    certs = BASE_DIR / "config" / "certs"
    key_p = certs / "neo.key"
    crt_p = certs / "neo.crt"
    if key_p.exists() and crt_p.exists():
        return True

    try:
        import datetime
        import ipaddress
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        print("[Dashboard] cryptography not installed — dashboard disabled.")
        print("[Dashboard] For HTTPS run:  pip install cryptography")
        return False

    try:
        certs.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        who = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "NEO Dashboard"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NEO"),
        ])

        # The SAN has to cover every address the phone might use: the LAN IP the
        # QR code encodes, plus localhost when testing on the machine itself.
        alt = [x509.DNSName("localhost"),
               x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
        try:
            lan = _local_ip()
            if not lan.startswith("127."):
                alt.append(x509.IPAddress(ipaddress.IPv4Address(lan)))
        except Exception:
            pass          # no LAN address resolvable — localhost entries still work

        # Timezone-aware UTC: datetime.utcnow() is deprecated from Python 3.12 on,
        # and the builder normalises aware values to UTC itself.
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(who)
            .issuer_name(who)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        key_p.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        crt_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        try:
            import os as _os
            _os.chmod(key_p, 0o600)   # best effort — largely a no-op on Windows
        except Exception:
            pass

        print(f"[Dashboard] Generated a self-signed certificate for this machine: {certs}")
        return True
    except Exception as e:
        print(f"[Dashboard] Certificate generation failed ({type(e).__name__}) — dashboard disabled.")
        return False


def _read(name: str) -> str:
    return (STATIC_DIR / name).read_text(encoding="utf-8")


class LoginAttemptLimiter:
    """Bound repeated login failures per direct client address."""

    def __init__(self, max_failures: int = 5, window_seconds: float = 60.0):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        for address, failures in list(self._failures.items()):
            while failures and failures[0] <= cutoff:
                failures.popleft()
            if not failures:
                del self._failures[address]
        if len(self._failures) > 2048:
            for address in list(self._failures)[:len(self._failures) - 2048]:
                del self._failures[address]

    def retry_after(self, address: str, now: float | None = None) -> int:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(now)
            failures = self._failures.get(address)
            if not failures or len(failures) < self.max_failures:
                return 0
            return max(1, int(self.window_seconds - (now - failures[0]) + 0.999))

    def record_failure(self, address: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(now)
            self._failures.setdefault(address, deque()).append(now)

    def clear(self, address: str) -> None:
        with self._lock:
            self._failures.pop(address, None)


# ── DashboardServer ───────────────────────────────────────────────────────────

class DashboardServer:

    def __init__(self):
        self._ip                          = _local_ip()
        self._tokens: set[str]            = set()
        self._token_expiries: dict[str, float] = {}
        self._clients: set[WebSocket]     = set()
        self._history: list[dict]         = []
        self._command_queue               = asyncio.Queue()
        self._wake_callback               = None
        self._connect_callback            = None
        self._pending_keys: dict[str, float] = {}
        self._login_limiter               = LoginAttemptLimiter()
        self._device_sessions: dict[str, dict] = {}  # device_token → expiry
        self._phone_audio_queue: asyncio.Queue    = asyncio.Queue(maxsize=200)
        self._uploads_dir                 = UPLOADS_DIR
        self._login_html                  = _read("login.html")
        self._app_html                    = _read("app.html")
        self.app                          = self._build_app()

    # ── one-time key management ───────────────────────────────────────────

    def new_key(self, expiry_secs: int = 600) -> str:
        now = time.time()
        self._pending_keys = {k: v for k, v in self._pending_keys.items() if v > now}
        key = ''.join(secrets.choice(_KEY_CHARS) for _ in range(6))
        self._pending_keys[key] = now + expiry_secs
        return key

    @staticmethod
    def _ssl_enabled() -> bool:
        certs = BASE_DIR / "config" / "certs"
        return (certs / "neo.key").exists() and (certs / "neo.crt").exists()

    def get_url(self) -> str:
        return f"https://{self._ip}:{PORT}"

    def get_manual_url(self) -> str:
        """HTTPS alias for manual entry when the browser upgrades a bare IP."""
        return f"https://{self._ip}:{PORT + 1}"

    def _issue_session_token(self) -> str:
        token = secrets.token_urlsafe(32)
        self._tokens.add(token)
        self._token_expiries[token] = time.time() + 12 * 60 * 60
        return token

    def _valid_session_token(self, token: str) -> bool:
        if token not in self._tokens:
            return False
        if self._token_expiries.get(token, 0) > time.time():
            return True
        self._tokens.discard(token)
        self._token_expiries.pop(token, None)
        return False

    # ── callbacks ────────────────────────────────────────────────────────

    def set_wake_callback(self, fn) -> None:
        self._wake_callback = fn

    def set_connect_callback(self, fn) -> None:
        self._connect_callback = fn

    # ── broadcast ────────────────────────────────────────────────────────

    async def broadcast(self, msg: dict) -> None:
        self._history.append(msg)
        if len(self._history) > 300:
            self._history = self._history[-300:]
        dead: set[WebSocket] = set()
        for ws in list(self._clients):
            try:
                await ws.send_json(msg)
            except Exception:
                dead.add(ws)
        self._clients -= dead

    # ── FastAPI app ───────────────────────────────────────────────────────

    def _build_app(self) -> "FastAPI":
        app = FastAPI(docs_url=None, redoc_url=None)

        @app.middleware("http")
        async def security_headers(req: Request, call_next):
            nonce = secrets.token_urlsafe(18)
            req.state.csp_nonce = nonce
            if (req.method not in {"GET", "HEAD", "OPTIONS"}
                    and (req.cookies.get("neo_session")
                         or req.cookies.get("neo_device"))):
                origin = req.headers.get("origin", "").rstrip("/")
                expected_origin = str(req.base_url).rstrip("/")
                if origin != expected_origin:
                    return JSONResponse(
                        {"error": "Cross-origin request denied"},
                        status_code=403)
            response = await call_next(req)
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Permissions-Policy"] = (
                "camera=(self), microphone=(self)")
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                f"script-src 'nonce-{nonce}'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: blob:; "
                "connect-src 'self' wss:; "
                "media-src 'self' blob:; "
                "worker-src 'self' blob:; "
                "object-src 'none'; base-uri 'self'; form-action 'self'; "
                "frame-ancestors 'none'")
            return response

        def _auth_token(req: Request) -> str:
            cookie = req.cookies.get("neo_session", "")
            return cookie if self._valid_session_token(cookie) else ""

        def _auth(req: Request) -> bool:
            return bool(_auth_token(req))

        def _set_auth_cookie(response, req: Request, token: str) -> None:
            response.set_cookie(
                "neo_session", token, httponly=True,
                secure=req.url.scheme == "https", samesite="strict",
                path="/", max_age=12 * 60 * 60)

        def _set_device_cookie(response, req: Request, token: str) -> None:
            response.set_cookie(
                "neo_device", token, httponly=True,
                secure=req.url.scheme == "https", samesite="strict",
                path="/", max_age=30 * 24 * 60 * 60)

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(req: Request):
            return HTMLResponse(
                self._login_html.replace("__CSP_NONCE__", req.state.csp_nonce))

        @app.get("/", response_class=HTMLResponse)
        async def index(req: Request):
            if not _auth(req):
                from fastapi.responses import RedirectResponse
                return RedirectResponse("/login", status_code=303)
            html = (self._app_html
                    .replace("__IP__", self._ip)
                    .replace("__PORT__", str(PORT))
                    .replace("__CSP_NONCE__", req.state.csp_nonce))
            return HTMLResponse(html)

        @app.post("/login")
        async def login(req: Request):
            address = req.client.host if req.client else "unknown"
            retry_after = self._login_limiter.retry_after(address)
            if retry_after:
                return JSONResponse(
                    {"ok": False, "error": "Login temporarily unavailable"},
                    status_code=429, headers={"Retry-After": str(retry_after)})
            try:
                body = await req.json()
            except Exception:
                self._login_limiter.record_failure(address)
                return JSONResponse({"ok": False, "error": "Invalid or expired key"},
                                    status_code=401)
            pin = body.get("pin") if isinstance(body, dict) else None
            entered = pin.strip().upper() if isinstance(pin, str) else ""
            now     = time.time()
            if entered in self._pending_keys and self._pending_keys[entered] > now:
                del self._pending_keys[entered]          # one-time use
                self._login_limiter.clear(address)
                tok = self._issue_session_token()
                if self._connect_callback:
                    self._connect_callback()
                asyncio.create_task(self.broadcast(
                    {"type": "sys", "text": "Remote connection established."}
                ))
                # Bearer token in response body — no cookies needed (works on any browser/HTTP)
                response = JSONResponse({"ok": True})
                _set_auth_cookie(response, req, tok)
                return response
            self._login_limiter.record_failure(address)
            return JSONResponse({"ok": False, "error": "Invalid or expired key"},
                                status_code=401)

        @app.get("/auto-login", response_class=HTMLResponse)
        async def auto_login_page(req: Request):
            """Load QR-login UI; the PIN is carried only in the URL fragment."""
            return HTMLResponse("""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Connect to NEO</title></head><body>
<p id="status">Connecting to NEO…</p>
<script nonce="__CSP_NONCE__">
(async function () {
  const params = new URLSearchParams(location.hash.slice(1));
  const pin = params.get('key') || '';
  history.replaceState(null, '', location.pathname);
  if (!/^[A-Z2-9]{6}$/.test(pin)) {
    document.getElementById('status').textContent = 'Invalid or expired key';
    return;
  }
  try {
    const response = await fetch('/api/qr-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin })
    });
    const data = await response.json();
    if (!response.ok || !data.ok) throw new Error('Login failed');
    location.replace('/');
  } catch (_) {
    document.getElementById('status').textContent = 'Connection failed; request a new QR code';
  }
})();
</script></body></html>""".replace(
                "__CSP_NONCE__", req.state.csp_nonce))

        @app.post("/api/qr-login")
        async def qr_login(req: Request):
            """Consume the one-time QR PIN received from the URL fragment."""
            address = req.client.host if req.client else "unknown"
            retry_after = self._login_limiter.retry_after(address)
            if retry_after:
                return JSONResponse(
                    {"ok": False, "error": "Login temporarily unavailable"},
                    status_code=429, headers={"Retry-After": str(retry_after)})
            try:
                body = await req.json()
            except Exception:
                self._login_limiter.record_failure(address)
                return JSONResponse({"ok": False}, status_code=400)
            pin = body.get("pin") if isinstance(body, dict) else None
            key = pin.strip().upper() if isinstance(pin, str) else ""
            now = time.time()
            if not key or key not in self._pending_keys or self._pending_keys[key] <= now:
                self._login_limiter.record_failure(address)
                return JSONResponse({"ok": False}, status_code=401)

            self._login_limiter.clear(address)
            del self._pending_keys[key]
            tok = self._issue_session_token()
            dev_tok = secrets.token_urlsafe(32)
            self._device_sessions[dev_tok] = {
                "expires_at": time.time() + 30 * 24 * 60 * 60,
            }
            if self._connect_callback:
                self._connect_callback()
            asyncio.create_task(self.broadcast(
                {"type": "sys", "text": "Remote connection established via QR code."}
            ))
            response = JSONResponse({"ok": True})
            _set_auth_cookie(response, req, tok)
            _set_device_cookie(response, req, dev_tok)
            return response

        @app.post("/api/device-login")
        async def device_login_ep(req: Request):
            """Return a fresh auth token for a previously paired device token."""
            address = req.client.host if req.client else "unknown"
            retry_after = self._login_limiter.retry_after(address)
            if retry_after:
                return JSONResponse(
                    {"ok": False, "error": "Login temporarily unavailable"},
                    status_code=429, headers={"Retry-After": str(retry_after)})
            dev_tok = req.cookies.get("neo_device", "").strip()
            device = self._device_sessions.get(dev_tok)
            if not device or device.get("expires_at", 0) <= time.time():
                self._device_sessions.pop(dev_tok, None)
                self._login_limiter.record_failure(address)
                response = JSONResponse({"ok": False}, status_code=401)
                response.delete_cookie(
                    "neo_device", path="/", secure=req.url.scheme == "https",
                    httponly=True, samesite="strict")
                return response
            self._login_limiter.clear(address)
            tok = self._issue_session_token()
            if self._connect_callback:
                self._connect_callback()
            asyncio.create_task(self.broadcast(
                {"type": "sys", "text": "Known device reconnected automatically."}
            ))
            response = JSONResponse({"ok": True})
            _set_auth_cookie(response, req, tok)
            return response

        @app.post("/api/revoke-devices")
        async def revoke_devices(req: Request):
            """Invalidate all persistent device tokens (admin action)."""
            if not _auth(req):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            count = len(self._device_sessions)
            self._device_sessions.clear()
            response = JSONResponse({"ok": True, "revoked": count})
            response.delete_cookie(
                "neo_device", path="/", secure=req.url.scheme == "https",
                httponly=True, samesite="strict")
            return response

        @app.post("/api/command")
        async def command(req: Request):
            if not _auth(req):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            body = await req.json()
            if not isinstance(body, dict):
                return JSONResponse({"error": "Expected a JSON object"},
                                    status_code=400)
            if "enc" in body:
                return JSONResponse(
                    {"error": "Unsupported encrypted command format"},
                    status_code=400)
            command_text = body.get("text", "")
            if not isinstance(command_text, str):
                return JSONResponse({"error": "Command text must be a string"},
                                    status_code=400)
            text = command_text.strip()
            if text:
                await self._command_queue.put(text)
                if self._wake_callback:
                    self._wake_callback()
            return JSONResponse({"ok": True})

        @app.post("/api/wake")
        async def wake_ep(req: Request):
            if not _auth(req):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            if self._wake_callback:
                self._wake_callback()
            return JSONResponse({"ok": True})

        # ── Phone mic real-time audio → Gemini Live ──────────────────────────

        @app.websocket("/ws/phone-audio")
        async def phone_audio_ws(websocket: WebSocket):
            tok = websocket.cookies.get("neo_session", "").strip()
            origin = websocket.headers.get("origin", "").rstrip("/")
            scheme = ("https" if websocket.url.scheme in {"https", "wss"}
                      else "http")
            expected_origin = f"{scheme}://{websocket.headers.get('host', '')}"
            if not self._valid_session_token(tok) or origin != expected_origin:
                await websocket.close(code=4001)
                return
            await websocket.accept()
            asyncio.create_task(self.broadcast(
                {"type": "sys", "text": "Phone microphone live."}
            ))
            try:
                while True:
                    data = await websocket.receive_bytes()
                    try:
                        self._phone_audio_queue.put_nowait(
                            {"data": data, "mime_type": "audio/pcm"}
                        )
                    except asyncio.QueueFull:
                        pass  # drop frame rather than block
            except WebSocketDisconnect:
                pass
            finally:
                asyncio.create_task(self.broadcast(
                    {"type": "sys", "text": "Phone microphone stopped."}
                ))

        # ── File sharing ──────────────────────────────────────────────────────

        def _safe_filename(raw: str) -> str:
            name = Path(raw).name                          # strip path components
            name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(". ")
            return name or "upload"

        if _UPLOAD_OK:
            @app.post("/api/upload")
            async def upload_file(req: Request, file: UploadFile = FastAPIFile(...)):
                if not _auth(req):
                    return JSONResponse({"error": "Unauthorized"}, status_code=401)

                safe = _safe_filename(file.filename or "upload")
                dest = self._uploads_dir / safe
                stem, suffix = Path(safe).stem, Path(safe).suffix
                counter = 1
                while dest.exists():
                    dest = self._uploads_dir / f"{stem}_{counter}{suffix}"
                    counter += 1

                size = 0
                max_bytes = MAX_UPLOAD_MB * 1024 * 1024
                try:
                    with open(dest, "wb") as fout:
                        while True:
                            chunk = await file.read(65536)
                            if not chunk:
                                break
                            size += len(chunk)
                            if size > max_bytes:
                                fout.close()
                                dest.unlink(missing_ok=True)
                                return JSONResponse(
                                    {"error": f"File too large (max {MAX_UPLOAD_MB} MB)"},
                                    status_code=413,
                                )
                            fout.write(chunk)
                except Exception as exc:
                    try:
                        dest.unlink(missing_ok=True)
                    except Exception:
                        pass
                    return JSONResponse({"error": str(exc)}, status_code=500)

                asyncio.create_task(self.broadcast({
                    "type": "file_received",
                    "name": dest.name,
                    "size": size,
                    "saved_to": str(self._uploads_dir),
                }))
                return JSONResponse({"ok": True, "name": dest.name, "size": size})
        else:
            @app.post("/api/upload")
            async def upload_unavailable(req: Request):
                return JSONResponse(
                    {"error": "File uploads require: pip install python-multipart"},
                    status_code=503,
                )

        @app.get("/api/files")
        async def list_files(req: Request):
            if not _auth(req):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            files = []
            try:
                for f in sorted(
                    (p for p in self._uploads_dir.iterdir() if p.is_file()),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                ):
                    files.append({"name": f.name, "size": f.stat().st_size})
            except Exception:
                pass
            return JSONResponse({"files": files})

        @app.get("/uploads/{filename}")
        async def download_file(filename: str, req: Request):
            if not _auth(req):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            safe = re.sub(r'[/\\]', '', filename)
            path = self._uploads_dir / safe
            if not path.exists() or not path.is_file():
                return JSONResponse({"error": "Not found"}, status_code=404)
            return FileResponse(str(path), filename=safe)

        @app.websocket("/ws")
        async def ws_ep(websocket: WebSocket):
            tok = websocket.cookies.get("neo_session", "").strip()
            origin = websocket.headers.get("origin", "").rstrip("/")
            scheme = ("https" if websocket.url.scheme in {"https", "wss"}
                      else "http")
            expected_origin = f"{scheme}://{websocket.headers.get('host', '')}"
            if not self._valid_session_token(tok) or origin != expected_origin:
                await websocket.close(code=4001)
                return
            await websocket.accept()
            self._clients.add(websocket)
            for entry in self._history[-50:]:
                try:
                    await websocket.send_json(entry)
                except Exception:
                    break
            try:
                while True:
                    data = await websocket.receive_json()
                    if data.get("type") == "command":
                        command_text = data.get("text", "")
                        if isinstance(command_text, str) and command_text.strip():
                            await self._command_queue.put(command_text.strip())
                            if self._wake_callback:
                                self._wake_callback()
            except WebSocketDisconnect:
                pass
            finally:
                self._clients.discard(websocket)

        return app

    # ── serve ─────────────────────────────────────────────────────────────

    async def _serve_alias(self) -> None:
        """Second HTTPS server on PORT+1 sharing the same app and in-memory state.
        Chrome HTTPS-upgrades any bare IP:PORT the user types, so this port also needs TLS.
        User types IP:8001 → Chrome tries https → self-signed cert warning → accept once → done."""
        ssl_key  = BASE_DIR / "config" / "certs" / "neo.key"
        ssl_cert = BASE_DIR / "config" / "certs" / "neo.crt"
        if _firewall_assist_enabled():
            asyncio.get_event_loop().run_in_executor(None, _ensure_network_access, PORT + 1)
        cfg = uvicorn.Config(
            self.app, host="0.0.0.0", port=PORT + 1, log_level="warning",
            ssl_keyfile=str(ssl_key), ssl_certfile=str(ssl_cert),
        )
        print(f"[Dashboard] Manual entry:  {self._ip}:{PORT + 1}  (type in browser, accept cert once)")
        await uvicorn.Server(cfg).serve()

    async def serve(self) -> None:
        if not _DEPS_OK:
            print("[Dashboard] fastapi/uvicorn not installed — dashboard disabled.")
            print("[Dashboard] Run:  pip install fastapi 'uvicorn[standard]' cryptography")
            return

        # Credentials and bearer tokens must never be sent over plaintext HTTP.
        # If local TLS setup fails, fail closed rather than serving a PIN page.
        if not _ensure_certs() or not self._ssl_enabled():
            print("[Dashboard] HTTPS is unavailable — remote access is disabled.")
            return

        # Firewall/network-profile changes are OFF by default, and they stay off
        # unless 'dashboard_open_firewall' is set in config/neo_settings.json.
        # Switching the dashboard on is consent to run a local web server, not
        # consent to add host-firewall rules and flip the network profile to
        # Private — so that is a separate, explicit decision.
        if _firewall_assist_enabled():
            # Runs in a thread — uvicorn starts immediately, no waiting for UAC
            # dialogs or subprocess timeouts.
            asyncio.get_event_loop().run_in_executor(None, _ensure_network_access, PORT)
        else:
            print("[Dashboard] Firewall/network-profile changes are OFF. If the "
                  "phone cannot reach this machine, allow the port yourself or set "
                  "'dashboard_open_firewall' to true in config/neo_settings.json.")

        use_ssl  = True
        ssl_key  = BASE_DIR / "config" / "certs" / "neo.key"
        ssl_cert = BASE_DIR / "config" / "certs" / "neo.crt"

        if use_ssl:
            asyncio.create_task(self._serve_alias())

        cfg = uvicorn.Config(
            self.app, host="0.0.0.0", port=PORT, log_level="warning",
            **({"ssl_keyfile": str(ssl_key), "ssl_certfile": str(ssl_cert)} if use_ssl else {}),
        )

        proto = "https" if use_ssl else "http"
        print(f"[Dashboard] {proto}://{self._ip}:{PORT}")
        print("[Dashboard] Press 'Remote Control' in NEO's UI to get the QR code.")
        await uvicorn.Server(cfg).serve()
