#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПРИЁМНИК ПИСЕМ СТЕНДА: почтовый узел, которому служба сдаёт письма, и чтение
принятого.

ПРЕДМЕТ. С kaname#456 человек, чей адрес не подтверждён, дальше входа и экрана
подтверждения не проходит, а подтверждает адрес КОД из письма. Стенд посадки
`own` (`.github/scripts/stand-chart.sh`) заводит человека регистрацией, и
довести его до обычного положения можно только тем же путём, что проходит
человек: служба сдаёт письмо почтовому узлу, код читается из письма и
предъявляется полосе входа (`tests/authz-fixtures/seed_login_lane.py`). Узел
этот — здесь: у стенда нет другого почтового узла, а обратное заполнение отметки
закрыло бы ровно то, что судит набор.

ЧТО ОН УМЕЕТ — И ЧЕГО НЕТ НАМЕРЕННО.

  · SMTP поверх TLS с первого байта (`implicit`, порт 465 в поде): полоса до
    узла обязана быть шифрованной и на стенде (незащищённой посадки у
    отправителя службы нет, ban #16), лист узла выписывает УЦ стенда, и служба
    проверяет его тем же якорем, что остальные листы стенда;
  · команды EHLO/HELO, MAIL, RCPT, DATA (с разворотом удвоенной точки), RSET,
    NOOP, QUIT; объявлено `8BITMIME` — тело письма службы в 8 битах;
  · чтение принятого — `GET /messages?to=<адрес>`: письма этому адресату в
    порядке приёма, `{"messages": [{"from", "to", "receivedAt", "data"}]}`;
    `GET /healthz` — 200.

  Удостоверения у узла нет, и отправителю службы его не задают: подделывать
  чужое письмо на стенде некому, а половина настройки удостоверения была бы
  отказом старта (`InviteMailConfig.Validate`). Письма живут в памяти пода —
  столько же, сколько стенд.

ИСХОДЫ ЗАПУСКА: `serve` работает до сигнала; `--self-test` — 0 (доказано), 1
(самопроверка провалена), 75 (условие не создано: нет `openssl`, чтобы выписать
лист самопроверки).

САМОПРОВЕРКА — `--self-test`: поднимает узел на 127.0.0.1 с листом своего УЦ и
сдаёт ему письма клиентом стандартной библиотеки поверх TLS: письмо читается по
адресату в порядке приёма, строка с удвоенной точкой разворачивается, тело в 8
битах доезжает дословно; ЗАКОННЫЙ БЛИЗНЕЦ — письмо другому адресату в чтение
этого адреса не попадает, а неизвестному адресату перечень пуст; открытый текст
на порту узла письма не сдаёт — TLS обязателен.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RC_FINDING = 1
RC_UNMET = 75

# Предел одной строки команды и тела письма: узел стенда принимает письма
# службы, а не почту мира, и неограниченное чтение держало бы память пода
# чужой волей.
LINE_LIMIT = 4096
BODY_LIMIT = 1 << 20
# Срок молчания клиента на соединении: отправитель службы держит свой срок на
# попытку, и узел не обязан ждать дольше.
IDLE_TIMEOUT_S = 60


class Store:
    """Принятые письма в памяти, по порядку приёма."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._msgs: list[dict] = []

    def add(self, sender: str, rcpts: list[str], data: str) -> None:
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self._lock:
            self._msgs.append({"from": sender, "to": list(rcpts), "receivedAt": now,
                               "data": data})

    def to(self, addr: str) -> list[dict]:
        want = addr.strip().lower()
        with self._lock:
            return [dict(m) for m in self._msgs
                    if any(r.strip().lower() == want for r in m["to"])]


def _addr(arg: str) -> str:
    """`<a@b> BODY=8BITMIME` → `a@b`."""
    arg = arg.strip()
    if arg.startswith("<"):
        end = arg.find(">")
        return arg[1:end] if end > 0 else arg[1:]
    return arg.split(" ", 1)[0]


def make_smtp_handler(store: Store, ctx: ssl.SSLContext):
    class Handler(socketserver.StreamRequestHandler):
        timeout = IDLE_TIMEOUT_S

        broken = False

        def setup(self) -> None:
            self.request.settimeout(IDLE_TIMEOUT_S)
            # Рукопожатие — в потоке соединения, а не в цикле приёма: медленный
            # клиент иначе останавливал бы приём всех остальных. Не состоялось
            # (открытый текст, чужой клиент) — соединение закрывается молча:
            # письма без TLS узел не принимает.
            try:
                self.request = ctx.wrap_socket(self.request, server_side=True)
            except (ssl.SSLError, OSError):
                self.broken = True
                return
            super().setup()

        def finish(self) -> None:
            if not self.broken:
                super().finish()

        def _say(self, line: str) -> None:
            self.wfile.write((line + "\r\n").encode("utf-8"))
            self.wfile.flush()

        def _read_data(self) -> str | None:
            chunks: list[bytes] = []
            size = 0
            while True:
                raw = self.rfile.readline(LINE_LIMIT + 2)
                if not raw:
                    return None
                if raw in (b".\r\n", b".\n"):
                    break
                if raw.startswith(b".."):
                    raw = raw[1:]
                size += len(raw)
                if size > BODY_LIMIT:
                    return None
                chunks.append(raw)
            return b"".join(chunks).decode("utf-8", "replace")

        def handle(self) -> None:
            if self.broken:
                return
            sender, rcpts = "", []
            try:
                self._say("220 stand-mailbox ESMTP")
                while True:
                    raw = self.rfile.readline(LINE_LIMIT + 2)
                    if not raw:
                        return
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    verb = line.split(" ", 1)[0].upper()
                    upper = line.upper()
                    if verb == "EHLO":
                        self._say("250-stand-mailbox")
                        self._say("250-8BITMIME")
                        self._say(f"250 SIZE {BODY_LIMIT}")
                    elif verb == "HELO":
                        self._say("250 stand-mailbox")
                    elif upper.startswith("MAIL FROM:"):
                        sender, rcpts = _addr(line[10:]), []
                        self._say("250 OK")
                    elif upper.startswith("RCPT TO:"):
                        if not sender:
                            self._say("503 MAIL first")
                            continue
                        rcpts.append(_addr(line[8:]))
                        self._say("250 OK")
                    elif verb == "DATA":
                        if not sender or not rcpts:
                            self._say("503 MAIL and RCPT first")
                            continue
                        self._say("354 End data with <CR><LF>.<CR><LF>")
                        data = self._read_data()
                        if data is None:
                            self._say("552 message too large or connection lost")
                            return
                        store.add(sender, rcpts, data)
                        sender, rcpts = "", []
                        self._say("250 OK queued")
                    elif verb == "RSET":
                        sender, rcpts = "", []
                        self._say("250 OK")
                    elif verb == "NOOP":
                        self._say("250 OK")
                    elif verb == "QUIT":
                        self._say("221 Bye")
                        return
                    else:
                        self._say("502 Command not implemented")
            except (OSError, ssl.SSLError):
                return

    return Handler


def make_http_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # журнал пода не несёт адресов писем
            return

        def _send(self, code: int, doc: dict) -> None:
            body = json.dumps(doc, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 — имя задаёт http.server
            u = urllib.parse.urlsplit(self.path)
            if u.path == "/healthz":
                self._send(200, {"status": "ok"})
                return
            if u.path == "/messages":
                to = urllib.parse.parse_qs(u.query).get("to", [""])[0]
                if not to:
                    self._send(400, {"message": "Illegal argument to: required"})
                    return
                self._send(200, {"messages": store.to(to)})
                return
            self._send(404, {"message": "not found"})

    return Handler


class _SMTPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(host: str, smtp_port: int, http_port: int, cert: str, key: str,
          store: Store | None = None):
    """Поднимает оба слушателя в потоках; возвращает (store, smtp, http)."""
    store = store or Store()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    smtp = _SMTPServer((host, smtp_port), make_smtp_handler(store, ctx))
    http = ThreadingHTTPServer((host, http_port), make_http_handler(store))
    http.daemon_threads = True
    for srv in (smtp, http):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return store, smtp, http


def serve(args: argparse.Namespace) -> int:
    _store, smtp, http = start(args.host, args.smtp_port, args.http_port, args.cert, args.key)
    print(f"stand-mailbox: SMTP поверх TLS на {args.host}:{smtp.server_address[1]}, "
          f"чтение на {args.host}:{http.server_address[1]}", flush=True)
    threading.Event().wait()
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_FAILED: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _FAILED.append(label)


def _leaf(tmp: pathlib.Path) -> tuple[str, str, str]:
    """УЦ и лист на имя `localhost` — как выписывает стенд."""
    ca_key, ca = tmp / "ca.key", tmp / "ca.crt"
    key, csr, crt, ext = tmp / "m.key", tmp / "m.csr", tmp / "m.crt", tmp / "m.ext"
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
        "-out", str(ca), "-days", "1", "-subj", "/CN=mailbox self-test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
        "-out", str(csr), "-subj", "/CN=localhost")
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                   "extendedKeyUsage=serverAuth\n"
                   "keyUsage=critical,digitalSignature,keyEncipherment\n", encoding="utf-8")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(crt), "-days", "1", "-extfile", str(ext))
    return str(ca), str(crt), str(key)


def _read(port: int, to: str) -> list[dict]:
    import urllib.request
    url = f"http://127.0.0.1:{port}/messages?" + urllib.parse.urlencode({"to": to})
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))["messages"]


def self_test() -> int:
    import smtplib

    if shutil.which("openssl") is None:
        print("УСЛОВИЕ НЕ СОЗДАНО: нет openssl — лист самопроверки выписать нечем",
              file=sys.stderr)
        return RC_UNMET
    print("=== приёмник писем стенда: приём поверх TLS и чтение по адресату ===")
    with tempfile.TemporaryDirectory(prefix="mailbox-selftest-") as td:
        ca, crt, key = _leaf(pathlib.Path(td))
        _store, smtp, http = start("127.0.0.1", 0, 0, crt, key)
        sport, hport = smtp.server_address[1], http.server_address[1]
        client_ctx = ssl.create_default_context(cafile=ca)
        body_a = ("Subject: code\r\nMIME-Version: 1.0\r\n"
                  "Content-Type: text/plain; charset=UTF-8\r\n"
                  "Content-Transfer-Encoding: 8bit\r\n\r\n"
                  "Код подтверждения:\r\n\r\n    ABCDE-FGHIJ\r\n.точка в начале строки\r\n")
        try:
            with smtplib.SMTP_SSL("localhost", sport, context=client_ctx, timeout=10) as s:
                ehlo = s.ehlo("kaname.local")
                s.sendmail("kaname@kaname.local", ["a@stand.invalid"], body_a.encode("utf-8"))
                s.sendmail("kaname@kaname.local", ["b@stand.invalid"], b"Subject: other\r\n\r\nB\r\n")
                s.sendmail("kaname@kaname.local", ["A@stand.invalid"], b"Subject: second\r\n\r\nA2\r\n")
            sent = "ok"
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            ehlo, sent = (0, b""), f"{type(e).__name__}: {e}"
        _c("письма сданы узлу поверх TLS клиентом стандартной библиотеки", sent == "ok", sent)
        _c("узел объявляет 8BITMIME", b"8BITMIME" in (ehlo[1] or b""), f"{ehlo!r}")

        got_a = _read(hport, "a@stand.invalid") if sent == "ok" else []
        _c("письма адресату читаются по порядку приёма, адрес без учёта регистра",
           len(got_a) == 2 and "ABCDE-FGHIJ" in got_a[0]["data"] and "A2" in got_a[1]["data"],
           f"{[m['data'][:40] for m in got_a]}")
        _c("тело в 8 битах доезжает дословно, удвоенная точка развёрнута",
           bool(got_a) and "Код подтверждения:" in got_a[0]["data"]
           and "\r\n.точка в начале строки\r\n" in got_a[0]["data"]
           and "..точка" not in got_a[0]["data"],
           f"{got_a[0]['data'] if got_a else None!r}")
        got_b = _read(hport, "b@stand.invalid") if sent == "ok" else []
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: письмо другому адресату в чтение этого адреса не попадает",
           len(got_b) == 1 and "B" in got_b[0]["data"]
           and all("other" not in m["data"] for m in got_a), f"{got_b}")
        _c("неизвестному адресату перечень пуст", _read(hport, "none@stand.invalid") == [], "")

        plain = "сдано"
        try:
            with socket.create_connection(("127.0.0.1", sport), timeout=5) as raw:
                raw.sendall(b"EHLO x\r\n")
                raw.settimeout(5)
                reply = raw.recv(64)
            plain = "сдано" if reply.startswith(b"220") or reply.startswith(b"250") else "отказано"
        except OSError:
            plain = "отказано"
        _c("открытый текст на порту узла приветствия не получает — TLS обязателен",
           plain == "отказано", plain)
        smtp.shutdown()
        http.shutdown()
    print()
    if _FAILED:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_FAILED)} — {', '.join(_FAILED)}", file=sys.stderr)
        return RC_FINDING
    print("ДОКАЗАНО: узел принимает письма только поверх TLS, разворачивает удвоенную "
          "точку, тело в 8 битах доезжает дословно, чтение отдаёт письма адресата по "
          "порядку и не отдаёт чужих.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sv = sub.add_parser("serve", help="поднять узел и чтение до сигнала")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--smtp-port", type=int, default=465)
    sv.add_argument("--http-port", type=int, default=8025)
    sv.add_argument("--cert", required=True)
    sv.add_argument("--key", required=True)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if args.cmd == "serve":
        return serve(args)
    ap.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
