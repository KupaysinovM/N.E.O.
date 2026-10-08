from __future__ import annotations

import asyncio
import http.cookiejar
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
import urllib.request
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dashboard import server as dashboard_server
from dashboard.server import DashboardServer, LoginAttemptLimiter
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class LoginAttemptLimiterTests(unittest.TestCase):

    def test_limiter_blocks_after_five_failures_and_expires(self):
        limiter = LoginAttemptLimiter(max_failures=5, window_seconds=60)
        for attempt in range(5):
            limiter.record_failure("192.0.2.1", now=float(attempt))

        self.assertEqual(limiter.retry_after("192.0.2.1", now=10), 50)
        self.assertEqual(limiter.retry_after("192.0.2.2", now=10), 0)
        self.assertEqual(limiter.retry_after("192.0.2.1", now=60), 0)

    def test_successful_login_clears_failed_attempts(self):
        limiter = LoginAttemptLimiter(max_failures=5)
        for _ in range(4):
            limiter.record_failure("192.0.2.1", now=10)

        limiter.clear("192.0.2.1")
        self.assertEqual(limiter.retry_after("192.0.2.1", now=10), 0)

    def test_login_endpoint_returns_429_after_five_invalid_pins(self):
        server = DashboardServer()
        with TestClient(server.app) as client:
            for _ in range(5):
                self.assertEqual(client.post("/login", json={"pin": "wrong"}).status_code, 401)
            limited = client.post("/login", json={"pin": "wrong"})
            self.assertEqual(limited.status_code, 429)
            self.assertIn("Retry-After", limited.headers)
            self.assertEqual(limited.headers["Cache-Control"], "no-store")
            self.assertEqual(limited.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(limited.headers["Strict-Transport-Security"],
                             "max-age=31536000")

    def test_login_key_is_one_use(self):
        server = DashboardServer()
        server._pending_keys["ABCDEF"] = 9_999_999_999
        with TestClient(server.app) as client:
            response = client.post("/login", json={"pin": "abcdef"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"ok": True})
            cookie = response.cookies.get("neo_session")
            self.assertTrue(cookie)
            self.assertIn("httponly", response.headers["set-cookie"].lower())
            self.assertIn("samesite=strict", response.headers["set-cookie"].lower())
            self.assertNotIn("ABCDEF", server._pending_keys)
            self.assertEqual(
                client.post("/login", json={"pin": "abcdef"},
                            headers={"Origin": "http://testserver"}).status_code,
                401)
            self.assertEqual(client.get("/").status_code, 200)

    def test_dashboard_home_requires_server_side_session_cookie(self):
        server = DashboardServer()
        with TestClient(server.app) as client:
            response = client.get("/", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(response.headers["location"], "/login")

    def test_https_login_marks_session_cookie_secure(self):
        server = DashboardServer()
        server._pending_keys["ABCDEF"] = 9_999_999_999
        with TestClient(server.app, base_url="https://testserver") as client:
            response = client.post("/login", json={"pin": "ABCDEF"})
            self.assertEqual(response.status_code, 200)
            cookie = response.headers["set-cookie"].lower()
            self.assertIn("secure", cookie)
            self.assertIn("httponly", cookie)
            self.assertIn("samesite=strict", cookie)

    def test_session_cookie_expiry_is_enforced_server_side(self):
        server = DashboardServer()
        server._tokens.add("expired-session")
        server._token_expiries["expired-session"] = time.time() - 1
        with TestClient(server.app) as client:
            client.cookies.set("neo_session", "expired-session")
            response = client.post(
                "/api/wake", json={},
                headers={"Origin": "http://testserver"})
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("expired-session", server._tokens)

    def test_expired_device_cookie_is_revoked_server_side(self):
        server = DashboardServer()
        server._device_sessions["expired-device"] = {
            "expires_at": time.time() - 1}
        with TestClient(server.app) as client:
            client.cookies.set("neo_device", "expired-device")
            response = client.post(
                "/api/device-login", json={},
                headers={"Origin": "http://testserver"})
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("expired-device", server._device_sessions)

    def test_qr_pin_is_exchanged_by_post_and_never_returns_bearer_tokens(self):
        server = DashboardServer()
        server._pending_keys["ABCDEF"] = 9_999_999_999
        with TestClient(server.app) as client:
            page = client.get("/auto-login")
            self.assertEqual(page.status_code, 200)
            self.assertIn("location.hash", page.text)
            self.assertIn("/api/qr-login", page.text)
            self.assertNotIn("neo_token", page.text)
            self.assertNotIn("neo_device_token", page.text)
            self.assertNotIn("sessionStorage", page.text)

            response = client.post("/api/qr-login", json={"pin": "ABCDEF"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"ok": True})
            cookies = response.headers.get_list("set-cookie")
            self.assertEqual(len(cookies), 2)
            self.assertTrue(all("httponly" in cookie.lower() for cookie in cookies))
            self.assertTrue(all("samesite=strict" in cookie.lower() for cookie in cookies))
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(
                client.post("/api/qr-login", json={"pin": "ABCDEF"},
                            headers={"Origin": "http://testserver"}).status_code,
                401)

    def test_device_reconnect_uses_httponly_cookie_not_request_body(self):
        server = DashboardServer()
        server._device_sessions["device-secret"] = {
            "expires_at": time.time() + 60}
        with TestClient(server.app) as client:
            client.cookies.set("neo_device", "device-secret")
            response = client.post(
                "/api/device-login", json={},
                headers={"Origin": "http://testserver"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"ok": True})
            self.assertIn("neo_session", client.cookies)
            self.assertNotIn("token", response.json())

    def test_cookie_authenticated_mutations_reject_cross_origin_requests(self):
        server = DashboardServer()
        called = []
        server.set_wake_callback(lambda: called.append(True))
        session_cookie = server._issue_session_token()
        with TestClient(server.app) as client:
            client.cookies.set("neo_session", session_cookie)
            denied = client.post(
                "/api/wake", json={},
                headers={"Origin": "http://attacker.test"})
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(called, [])
            accepted = client.post(
                "/api/wake", json={},
                headers={"Origin": "http://testserver"})
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(called, [True])

    def test_websocket_session_rejects_cross_origin_hijacking(self):
        server = DashboardServer()
        session_cookie = server._issue_session_token()
        with TestClient(server.app) as client:
            client.cookies.set("neo_session", session_cookie)
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect(
                    "/ws", headers={"Origin": "http://attacker.test"}):
                    pass
            with client.websocket_connect(
                    "/ws", headers={"Origin": "http://testserver"}) as websocket:
                websocket.close()

    def test_dashboard_client_does_not_put_auth_tokens_in_urls(self):
        app_html = (Path(__file__).resolve().parents[1]
                    / "dashboard" / "static" / "app.html").read_text(
                        encoding="utf-8")
        login_html = (Path(__file__).resolve().parents[1]
                      / "dashboard" / "static" / "login.html").read_text(
                          encoding="utf-8")
        self.assertNotIn("neo_token", app_html + login_html)
        self.assertNotIn("neo_device_token", app_html + login_html)
        self.assertNotIn("neo_key", app_html + login_html)
        self.assertNotIn("CryptoJS", app_html + login_html)
        self.assertNotIn("/static/crypto.js", app_html + login_html)
        self.assertNotRegex(app_html + login_html, r"\son[a-z]+\s*=")
        self.assertNotIn("/ws?token=", app_html)
        self.assertNotIn("?token=", app_html)

    def test_dashboard_html_uses_per_response_nonce_csp(self):
        server = DashboardServer()
        server._issue_session_token()
        session_cookie = next(iter(server._tokens))
        with TestClient(server.app) as client:
            login = client.get("/login")
            qr = client.get("/auto-login")
            client.cookies.set("neo_session", session_cookie)
            app = client.get("/")
        for response in (login, qr, app):
            with self.subTest(path=response.url.path):
                policy = response.headers["Content-Security-Policy"]
                nonce_match = re.search(r"script-src 'nonce-([^']+)'", policy)
                self.assertIsNotNone(nonce_match)
                nonce = nonce_match.group(1)
                scripts = re.findall(r"<script[^>]*nonce=\"([^\"]+)\"",
                                     response.text, flags=re.IGNORECASE)
                self.assertTrue(scripts)
                self.assertTrue(all(value == nonce for value in scripts))
                self.assertNotIn("'unsafe-inline'", policy.split("script-src", 1)[1]
                                 .split(";", 1)[0])
                self.assertIn("frame-ancestors 'none'", policy)

    def test_dashboard_command_uses_tls_session_and_rejects_legacy_cbc(self):
        server = DashboardServer()
        session_cookie = server._issue_session_token()
        with TestClient(server.app) as client:
            client.cookies.set("neo_session", session_cookie)
            headers = {
                "Origin": "http://testserver",
                "Content-Type": "application/json",
            }
            accepted = client.post(
                "/api/command", json={"text": "open notes"}, headers=headers)
            self.assertEqual(accepted.status_code, 200)
            self.assertEqual(server._command_queue.get_nowait(), "open notes")
            rejected = client.post(
                "/api/command", json={"enc": "old-cbc-payload"}, headers=headers)
            self.assertEqual(rejected.status_code, 400)
            self.assertEqual(server._command_queue.qsize(), 0)

    def test_qr_login_attempts_are_rate_limited(self):
        server = DashboardServer()
        with TestClient(server.app) as client:
            for _ in range(5):
                self.assertEqual(
                    client.post("/api/qr-login", json={"pin": "wrong"}).status_code,
                    401)
            limited = client.post("/api/qr-login", json={"pin": "wrong"})
            self.assertEqual(limited.status_code, 429)

    def test_device_reconnect_attempts_are_rate_limited(self):
        server = DashboardServer()
        with TestClient(server.app) as client:
            for _ in range(5):
                self.assertEqual(
                    client.post("/api/device-login",
                                json={}).status_code, 401)
            limited = client.post("/api/device-login",
                                  json={})
            self.assertEqual(limited.status_code, 429)

    def test_login_input_masks_the_one_time_access_key(self):
        login_html = (Path(__file__).resolve().parents[1]
                      / "dashboard" / "static" / "login.html").read_text(
                          encoding="utf-8")
        self.assertIn('id="key" type="password"', login_html)

    def test_server_disables_remote_access_if_tls_setup_fails(self):
        server = DashboardServer()
        with patch("dashboard.server._ensure_certs", return_value=False), \
                patch("dashboard.server.uvicorn.Server") as run_server:
            import asyncio
            asyncio.run(server.serve())
        run_server.assert_not_called()

    def test_dashboard_urls_never_advertise_plain_http(self):
        server = DashboardServer()
        self.assertTrue(server.get_url().startswith("https://"))
        self.assertTrue(server.get_manual_url().startswith("https://"))
        self.assertTrue(server.get_manual_url().endswith(":8001"))


class DashboardTlsIntegrationTests(unittest.TestCase):

    def test_login_page_is_served_over_a_real_tls_socket(self):
        with tempfile.TemporaryDirectory() as cert_dir:
            key_path = Path(cert_dir) / "test.key"
            cert_path = Path(cert_dir) / "test.crt"
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(5)
            host, port = listener.getsockname()
            dashboard = DashboardServer()
            dashboard._pending_keys["ABCDEF"] = 9_999_999_999
            app_server = dashboard_server.uvicorn.Server(
                dashboard_server.uvicorn.Config(
                    dashboard.app,
                    host=host,
                    port=port,
                    ssl_keyfile=str(key_path),
                    ssl_certfile=str(cert_path),
                    log_level="critical",
                )
            )
            thread = threading.Thread(
                target=lambda: asyncio.run(app_server.serve(sockets=[listener])),
                daemon=True,
            )
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while (not app_server.started and thread.is_alive()
                       and time.monotonic() < deadline):
                    time.sleep(0.01)
                self.assertTrue(app_server.started, "TLS dashboard server did not start")

                tls_context = ssl._create_unverified_context()
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=tls_context),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                request = urllib.request.Request(f"https://{host}:{port}/login")
                with opener.open(request, timeout=3) as response:
                    body = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["Strict-Transport-Security"],
                                     "max-age=31536000")
                    self.assertIn('type="password"', body)

                login_request = urllib.request.Request(
                    f"https://{host}:{port}/login",
                    data=json.dumps({"pin": "ABCDEF"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                with opener.open(login_request, timeout=3) as response:
                    self.assertEqual(json.loads(response.read()), {"ok": True})
                    cookie = response.headers["Set-Cookie"].lower()
                    self.assertIn("secure", cookie)
                    self.assertIn("httponly", cookie)
                    self.assertIn("samesite=strict", cookie)

                with opener.open(f"https://{host}:{port}/", timeout=3) as response:
                    self.assertEqual(response.status, 200)

                chrome = Path(
                    os.environ.get("ProgramFiles", "C:/Program Files"),
                    "Google", "Chrome", "Application", "chrome.exe")
                if chrome.exists():
                    from playwright.async_api import async_playwright

                    dashboard._pending_keys["ABCDEF"] = 9_999_999_999
                    dashboard._pending_keys["GHIJKM"] = 9_999_999_999
                    browser_errors = []
                    browser_console = []

                    async def exercise_dashboard_in_chrome():
                        async with async_playwright() as playwright:
                            browser = await playwright.chromium.launch(
                                executable_path=str(chrome), headless=True)
                            try:
                                context = await browser.new_context(
                                    ignore_https_errors=True)
                                page = await context.new_page()
                                page.on("pageerror",
                                        lambda error: browser_errors.append(str(error)))
                                page.on("console", lambda message:
                                        browser_console.append(
                                            f"{message.type}: {message.text}"))
                                await page.goto(
                                    f"https://{host}:{port}/login",
                                    wait_until="domcontentloaded")
                                await page.locator("#key").fill("ABCDEF")
                                try:
                                    await page.wait_for_url(
                                        f"https://{host}:{port}/", timeout=10_000)
                                except Exception as error:
                                    raise AssertionError(
                                        f"login did not navigate: url={page.url}; "
                                        f"body={await page.locator('body').inner_text()!r}; "
                                        f"page_errors={browser_errors}; "
                                        f"console={browser_console}") from error
                                await page.locator("#feed").get_by_text(
                                    "Remote session active.").wait_for(
                                        timeout=10_000)
                                self.assertEqual(
                                    await page.evaluate("document.cookie"), "")
                                self.assertEqual(
                                    await page.evaluate("sessionStorage.length"), 0)
                                await page.locator("#inp").fill("TLS command path")
                                async with page.expect_response(
                                        lambda r: r.url.endswith("/api/command")) as pending:
                                    await page.locator("#send").click()
                                self.assertEqual((await pending.value).status, 200)
                                self.assertEqual(
                                    dashboard._command_queue.get_nowait(),
                                    "TLS command path")

                                await context.clear_cookies()
                                await page.goto(
                                    f"https://{host}:{port}/auto-login#key=GHIJKM",
                                    wait_until="domcontentloaded")
                                await page.wait_for_url(
                                    f"https://{host}:{port}/", timeout=10_000)
                                await page.locator("#feed").get_by_text(
                                    "Remote session active.").wait_for(
                                        timeout=10_000)
                                self.assertEqual(
                                    await page.evaluate("location.hash"), "")
                                self.assertEqual(
                                    await page.evaluate("document.cookie"), "")
                                self.assertEqual(
                                    await page.evaluate("sessionStorage.length"), 0)
                                self.assertEqual(
                                    await page.evaluate("localStorage.length"), 0)

                                await page.goto(
                                    f"https://{host}:{port}/login",
                                    wait_until="domcontentloaded")
                                await page.wait_for_url(
                                    f"https://{host}:{port}/", timeout=10_000)
                                await page.locator("#feed").get_by_text(
                                    "Remote session active.").wait_for(
                                        timeout=10_000)
                            finally:
                                await browser.close()

                    browser_result = []
                    browser_failure = []

                    def run_dashboard_browser():
                        try:
                            browser_result.append(
                                asyncio.run(exercise_dashboard_in_chrome()))
                        except Exception as error:
                            browser_failure.append(error)

                    browser_thread = threading.Thread(
                        target=run_dashboard_browser)
                    browser_thread.start()
                    browser_thread.join(timeout=30)
                    self.assertFalse(browser_thread.is_alive(),
                                     "dashboard browser did not stop")
                    if browser_failure:
                        raise browser_failure[0]
                    self.assertFalse(browser_errors, browser_errors)
            finally:
                app_server.should_exit = True
                thread.join(timeout=5)
                listener.close()
                self.assertFalse(thread.is_alive(), "TLS dashboard server did not stop")


if __name__ == "__main__":
    unittest.main()
