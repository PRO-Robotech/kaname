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
    `GET /healthz` — 200;
  · чтение КОДОВ — `GET /codes?to=<адрес>&after=<строка>`: по письму на
    элемент, в порядке приёма, первая непустая строка после строки, равной
    `after`, либо null — `{"codes": [...]}`. Его зовёт сквозной набор
    (`tests/newman/cases/kaname-recovery-lane.py`): отчёт прогона выкладывается
    артефактом публичного репозитория, а тело письма несёт код прозой, которую
    чистка отчёта (`.github/scripts/redact-newman-report.py`) не режет. Под
    именем `codes` значение срезается ИМЕНЕМ, поэтому набор читает узел только
    этой дверью. Строку-заголовок называет вызывающий: формы писем службы узел
    не знает;
  · ЗАДЕРЖКА ПРИЁМА — `POST /hold` и `POST /release`, состояние — `GET /hold`:
    `{"hold": <bool>, "refusedWhileHeld": <число>}`. Пока приём задержан, узел
    на каждое соединение отвечает ВРЕМЕННЫМ отказом приветствия
    (`421 4.3.2 …`) и закрывает его, а число таких отказов растёт. Это «Дано»
    позиции Ф5-14 приёмки восстановления: письма НЕ покидают кластер, и
    недоставленное обязано быть видно наблюдаемостью службы; после `release`
    доставка возвращается. Отказ — именно временный (4xx): постоянный (5xx)
    отправитель службы читает настройкой и отравляет строку
    (`internal/clients/invite_mail.go`, `classifySMTPErr`), и строка ушла бы
    из очереди без доставки — проба увидела бы «возраст вернулся к нулю» там,
    где письмо потеряно. Число отказов — положительный контроль: служба
    ПЫТАЛАСЬ сдать письмо и получила отказ, а не молчала.

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
на порту узла письма не сдаёт — TLS обязателен; задержанный приём отвечает
временным отказом 4xx и письма не принимает, счёт отказов растёт, а после
снятия задержки то же письмо принимается (близнец — один изменённый факт,
задержка); двери чтения задержка не трогает.
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


# Ответ приветствия на задержанном приёме. Код — ВРЕМЕННЫЙ (4xx): постоянный
# отправитель службы читает настройкой и отравляет строку очереди.
HOLD_REPLY = "421 4.3.2 stand mailbox is on hold: try again later"


class Store:
    """Принятые письма в памяти, по порядку приёма, и задержка приёма."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._msgs: list[dict] = []
        self._held = False
        self._refused = 0

    def set_hold(self, held: bool) -> dict:
        with self._lock:
            self._held = held
            return {"hold": self._held, "refusedWhileHeld": self._refused}

    def hold_state(self) -> dict:
        with self._lock:
            return {"hold": self._held, "refusedWhileHeld": self._refused}

    def refuse_if_held(self) -> bool:
        """True — приём задержан, и отказ сосчитан."""
        with self._lock:
            if self._held:
                self._refused += 1
            return self._held

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
                if store.refuse_if_held():
                    self._say(HOLD_REPLY)
                    return
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


def code_after(data: str, heading: str) -> str | None:
    """Первая непустая строка после строки, равной `heading`; нет такой — None.

    Строку-заголовок называет ВЫЗЫВАЮЩИЙ: узел формы писем службы не знает и
    своего разбора её не заводит."""
    lines = data.replace("\r\n", "\n").split("\n")
    for i, line in enumerate(lines):
        if line.strip() == heading.strip():
            for nxt in lines[i + 1:]:
                if nxt.strip():
                    return nxt.strip()
            return None
    return None


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
            q = urllib.parse.parse_qs(u.query)
            if u.path in ("/messages", "/codes"):
                to = q.get("to", [""])[0]
                if not to:
                    self._send(400, {"message": "Illegal argument to: required"})
                    return
            if u.path == "/messages":
                self._send(200, {"messages": store.to(to)})
                return
            if u.path == "/codes":
                after = q.get("after", [""])[0]
                if not after:
                    self._send(400, {"message": "Illegal argument after: required"})
                    return
                self._send(200, {"codes": [code_after(m["data"], after) for m in store.to(to)]})
                return
            if u.path == "/hold":
                self._send(200, store.hold_state())
                return
            self._send(404, {"message": "not found"})

        def do_POST(self) -> None:  # noqa: N802 — имя задаёт http.server
            path = urllib.parse.urlsplit(self.path).path
            # У глаголов задержки тела нет; присланная длина вычитывается, чтобы
            # соединение не повисло на непрочитанном.
            length = int(self.headers.get("Content-Length") or 0)
            if 0 < length <= LINE_LIMIT:
                self.rfile.read(length)
            if path == "/hold":
                self._send(200, store.set_hold(True))
                return
            if path == "/release":
                self._send(200, store.set_hold(False))
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


def _codes(port: int, to: str, after: str) -> tuple[int, object]:
    import urllib.error
    import urllib.request
    url = f"http://127.0.0.1:{port}/codes?" + urllib.parse.urlencode({"to": to, "after": after})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))["codes"]
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8")).get("message")


def _hold(port: int, verb: str) -> tuple[int, dict]:
    import urllib.request
    method = "GET" if verb == "state" else "POST"
    path = "/hold" if verb in ("state", "hold") else "/release"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=b"" if method == "POST" else None, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


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

        codes = _codes(hport, "a@stand.invalid", "Код подтверждения:") if sent == "ok" else None
        _c("коды читаются по письму на элемент в порядке приёма: код после названной строки, "
           "у письма без неё — null", codes == (200, ["ABCDE-FGHIJ", None]), f"{codes}")
        other = _codes(hport, "a@stand.invalid", "Код восстановления:") if sent == "ok" else None
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: иная строка-заголовок кода того же письма не находит",
           other == (200, [None, None]), f"{other}")
        _c("чужому адресату кодов нет",
           _codes(hport, "none@stand.invalid", "Код подтверждения:") == (200, []), "")
        _c("чтение кодов без строки-заголовка — 400 с именем поля",
           _codes(hport, "a@stand.invalid", "") == (400, "Illegal argument after: required"), "")

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

        # ЗАДЕРЖКА ПРИЁМА: один изменённый факт против законного приёма выше.
        st0 = _hold(hport, "state")
        _c("задержки нет до первого вызова, отказов ноль",
           st0 == (200, {"hold": False, "refusedWhileHeld": 0}), f"{st0}")
        held = _hold(hport, "hold")
        _c("POST /hold включает задержку",
           held == (200, {"hold": True, "refusedWhileHeld": 0}), f"{held}")
        before = len(_read(hport, "h@stand.invalid"))
        refusal = ""
        try:
            with smtplib.SMTP_SSL("localhost", sport, context=client_ctx, timeout=10) as s:
                s.sendmail("kaname@kaname.local", ["h@stand.invalid"], b"Subject: held\r\n\r\nH\r\n")
            refusal = "принято"
        except smtplib.SMTPConnectError as e:
            refusal = f"{e.smtp_code}"
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            refusal = f"{type(e).__name__}: {e}"
        _c("задержанный приём отвечает ВРЕМЕННЫМ отказом приветствия 421, а не постоянным 5xx",
           refusal == "421", refusal)
        _c("задержанный приём письма не принимает",
           len(_read(hport, "h@stand.invalid")) == before, f"{_read(hport, 'h@stand.invalid')}")
        st1 = _hold(hport, "state")
        _c("отказ на задержке сосчитан — отправитель пытался сдать, а не молчал",
           st1 == (200, {"hold": True, "refusedWhileHeld": 1}), f"{st1}")
        _c("двери чтения задержка не трогает",
           _codes(hport, "a@stand.invalid", "Код подтверждения:") == (200, ["ABCDE-FGHIJ", None]), "")
        rel = _hold(hport, "release")
        _c("POST /release снимает задержку, счёт отказов сохранён",
           rel == (200, {"hold": False, "refusedWhileHeld": 1}), f"{rel}")
        after = "не принято"
        try:
            with smtplib.SMTP_SSL("localhost", sport, context=client_ctx, timeout=10) as s:
                s.sendmail("kaname@kaname.local", ["h@stand.invalid"], b"Subject: held\r\n\r\nH\r\n")
            after = "принято"
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            after = f"{type(e).__name__}: {e}"
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: то же письмо после снятия задержки принимается",
           after == "принято" and len(_read(hport, "h@stand.invalid")) == before + 1, after)
        smtp.shutdown()
        http.shutdown()
    print()
    if _FAILED:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_FAILED)} — {', '.join(_FAILED)}", file=sys.stderr)
        return RC_FINDING
    print("ДОКАЗАНО: узел принимает письма только поверх TLS, разворачивает удвоенную "
          "точку, тело в 8 битах доезжает дословно, чтение отдаёт письма адресата по "
          "порядку и не отдаёт чужих, а чтение кодов — код после названной строки по "
          "письму на элемент; задержанный приём отвечает временным отказом, считает "
          "его и после снятия принимает то же письмо.")
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
