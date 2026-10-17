#!/usr/bin/env python3
"""EcoClaim mail relay.

Receives send requests from the claim form (Mileage-Expenses-Claim-Form.html) over HTTP
and delivers them through your SMTP server, so the SMTP password never lives in the web page.

Standard library only - no pip install needed. Configure config.json (see config.example.json),
then run:  python mail_relay.py
"""
import hmac
import json
import os
import smtplib
import ssl
import sys
import threading
import time
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("ECOCLAIM_RELAY_CONFIG", os.path.join(HERE, "config.json"))
MAX_BODY = 200_000


def load_config():
    if not os.path.exists(CONFIG_PATH):
        sys.exit(f"Config not found: {CONFIG_PATH}\nCopy config.example.json to config.json and fill it in.")
    with open(CONFIG_PATH, encoding="utf-8-sig") as f:  # -sig tolerates Notepad's BOM
        cfg = json.load(f)
    # the password may also come from an environment variable instead of the file
    cfg["smtp_password"] = os.environ.get("SMTP_PASSWORD", cfg.get("smtp_password", ""))
    required = ["smtp_host", "smtp_port", "smtp_user", "smtp_password", "from_email", "relay_key"]
    missing = [k for k in required if not str(cfg.get(k, "")).strip() or str(cfg.get(k)).startswith(("PASTE-", "CHANGE-ME"))]
    if missing:
        sys.exit("Please fill in these settings in config.json: " + ", ".join(missing))
    if len(cfg["relay_key"]) < 16:
        sys.exit("relay_key in config.json must be at least 16 characters.")
    cfg.setdefault("security", "starttls")  # starttls | ssl | none
    cfg.setdefault("from_name", "EcoClaim")
    cfg.setdefault("listen_host", "127.0.0.1")
    cfg.setdefault("listen_port", 8025)
    cfg.setdefault("allowed_origins", ["null"])
    cfg.setdefault("max_per_minute", 20)
    cfg["allowed_domains"] = [d.lower().strip() for d in cfg.get("allowed_domains", []) if d.strip()]
    if cfg["security"] not in ("starttls", "ssl", "none"):
        sys.exit('security must be "starttls", "ssl" or "none".')
    return cfg


CFG = load_config()
_sent_times = []
_lock = threading.Lock()


def rate_ok():
    now = time.time()
    with _lock:
        while _sent_times and now - _sent_times[0] > 60:
            _sent_times.pop(0)
        if len(_sent_times) >= int(CFG["max_per_minute"]):
            return False
        _sent_times.append(now)
        return True


def clean_addrs(value):
    """Validate addresses and restrict them to the allowed domains (so the relay can't be used to spam outsiders)."""
    if not value:
        return []
    if isinstance(value, str):
        value = [value]
    out = []
    for a in value:
        a = str(a).strip().lower()
        if not a:
            continue
        if a.count("@") != 1 or any(c in a for c in "\r\n,;<>\" \t"):
            raise ValueError(f"invalid email address: {a}")
        if CFG["allowed_domains"] and a.rsplit("@", 1)[1] not in CFG["allowed_domains"]:
            raise ValueError(f"recipient not allowed (only {', '.join(CFG['allowed_domains'])}): {a}")
        if a not in out:
            out.append(a)
    return out


def one_line(s, limit):
    return " ".join(str(s or "").split())[:limit]


def send_mail(to, cc, subject, text, html, reply_to):
    msg = EmailMessage()
    msg["From"] = formataddr((CFG["from_name"], CFG["from_email"]))
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=CFG["from_email"].rsplit("@", 1)[1])
    msg.set_content(text or " ")
    if html:
        msg.add_alternative(html, subtype="html")

    host, port, timeout = CFG["smtp_host"], int(CFG["smtp_port"]), 30
    if CFG["security"] == "ssl":
        server = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=timeout)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    with server:
        if CFG["security"] == "starttls":
            server.starttls(context=ssl.create_default_context())
        server.ehlo()
        # "none" is only for an internal relay without TLS; log in there only if it offers AUTH
        if CFG["security"] != "none" or server.has_extn("auth"):
            server.login(CFG["smtp_user"], CFG["smtp_password"])
        server.send_message(msg)


class Handler(BaseHTTPRequestHandler):
    server_version = "EcoClaimRelay/1.0"

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin and origin in CFG["allowed_origins"]:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Relay-Key")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return hmac.compare_digest(self.headers.get("X-Relay-Key", "").encode(), CFG["relay_key"].encode())

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path != "/health":
            return self._json(404, {"ok": False, "error": "not found"})
        if not self._authed():
            return self._json(401, {"ok": False, "error": "wrong relay key"})
        self._json(200, {"ok": True, "from": CFG["from_email"], "allowed_domains": CFG["allowed_domains"]})

    def do_POST(self):
        if self.path != "/send":
            return self._json(404, {"ok": False, "error": "not found"})
        if not self._authed():
            return self._json(401, {"ok": False, "error": "wrong relay key"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._json(413, {"ok": False, "error": "request too large or empty"})
        try:
            data = json.loads(self.rfile.read(length))
            to = clean_addrs(data.get("to"))
            cc = [a for a in clean_addrs(data.get("cc")) if a not in to]
            reply = clean_addrs(data.get("reply_to"))
            if not to:
                raise ValueError("no recipients")
            subject = one_line(data.get("subject"), 200) or "EcoClaim notification"
            text = str(data.get("text") or "")[:20_000]
            html = str(data.get("html"))[:100_000] if data.get("html") else None
        except ValueError as e:  # includes JSON decode errors
            return self._json(400, {"ok": False, "error": str(e)})
        if not rate_ok():
            return self._json(429, {"ok": False, "error": "too many emails - try again in a minute"})
        try:
            send_mail(to, cc, subject, text, html, reply[0] if reply else None)
        except smtplib.SMTPAuthenticationError:
            return self._json(502, {"ok": False, "error": "SMTP login failed - check smtp_user and the app password in config.json"})
        except Exception as e:  # report SMTP/network problems back to the form
            return self._json(502, {"ok": False, "error": f"SMTP error: {e}"})
        self.log_message("sent \"%s\" to %s", subject, ", ".join(to + cc))
        self._json(200, {"ok": True, "sent_to": to + cc})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), fmt % args))


def main():
    host, port = CFG["listen_host"], int(CFG["listen_port"])
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"EcoClaim mail relay running on http://{host}:{port}")
    print(f"  sending as {CFG['from_email']} via {CFG['smtp_host']}:{CFG['smtp_port']} ({CFG['security']})")
    print(f"  allowed recipient domains: {', '.join(CFG['allowed_domains']) or 'ANY (not recommended)'}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  NOTE: listening on the network - keep it inside the office LAN, never expose it to the internet.")
    print("Keep this window open. Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
