#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Свойства, которые производит САМА служба на автономном стенде.

ПРЕДМЕТ. Стенд поднят без края платформы, без её сервисов и без достижимого
внешнего поставщика удостоверений. Значит проверять здесь можно ровно то, чей
производитель — служба: её собственные REST-фронты, их взаимная непроницаемость,
её рубеж аутентификации, её разбор доступа на внутреннем слушателе и её честный
отказ там, где нужен отсутствующий сосед.

ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ. Сквозной набор newman адресуется в 40 модулях кейсов из
41 к КРАЮ ПЛАТФОРМЫ, и край — не транспорт: он производит проверяемые свойства
(разбор доступа с извлечением области, скрытие существования побайтово равное
промаху, отображение кода gRPC в HTTP-статус). Навести переменные края на
собственный фронт службы ЗАПРЕЩЕНО гейтом набора, и запрет верен: те же кейсы, тот
же зелёный отчёт, проверено РАЗНОЕ — по отчёту это неотличимо. Долг называется
числом отдельным шагом (`newman-suite-debt.py`), а не замалчивается здесь.

УТВЕРЖДАЕТСЯ ПАРА «код + тело», А НЕ ОДИН КОД. Отказ рубежа и промах
маршрутизатора дают РАЗНЫЕ коды, но 404 приходит и от мёртвого слушателя, и от
опечатки в пути. Поэтому каждое утверждение называет и признак в теле, а
утверждение об отсутствии пути идёт В ПАРЕ с положительным контролем на том же
фронте.

ИСХОДЫ:
    0  — все свойства сошлись;
    1  — НАХОДКА: свойство не сошлось;
    75 — УСЛОВИЕ НЕ СОЗДАНО: слушателя нет, рукопожатие не состоялось по причине,
         не относящейся к предмету, сертификатов стенда нет. Вердикта нет ни одного.

САМОПРОВЕРКА — `--self-test`: поднимает СВОЙ подставной сервер и доказывает, что
каждое утверждение способно упасть, что «нет слушателя» отличимо от «ответил не
тем» КОДОМ, и что положительный контроль не зеленеет на пустом.
"""

from __future__ import annotations

import argparse
import http.server
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request

RC_UNMET = 75

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_PKI = ROOT / ".stand" / "pki"

findings: list[str] = []
unmet: list[str] = []
checked = 0


class Answer:
    """Ответ фронта: код, тело и то, состоялось ли рукопожатие вовсе."""

    def __init__(self, status: int | None, body: str, handshake: bool, why: str = ""):
        self.status, self.body, self.handshake, self.why = status, body, handshake, why


def ask(url: str, *, ca: str, cert: str | None, key: str | None,
        method: str = "GET", timeout: float = 15.0) -> Answer:
    ctx = ssl.create_default_context(cafile=ca)
    # Имя в сертификате стенда — `localhost`; проверка имени ОСТАЁТСЯ включённой:
    # снять её значило бы перестать проверять то, ради чего mTLS и включён.
    if cert and key:
        ctx.load_cert_chain(cert, key)
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return Answer(resp.status, resp.read().decode("utf-8", "replace"), True)
    except urllib.error.HTTPError as e:
        return Answer(e.code, e.read().decode("utf-8", "replace"), True)
    except ssl.SSLError as e:
        return Answer(None, "", False, f"рукопожатие отклонено: {e}")
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        return Answer(None, "", False, f"соединение не состоялось: {e}")


def check(name: str, ok: bool, detail: str) -> None:
    global checked
    checked += 1
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        findings.append(f"{name}: {detail}")
        print(f"       {detail}")


def require_listener(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError as e:
        unmet.append(f":{port} не слушает ({e}) — стенд не поднят, вердикта нет")
        return False


def run(host: str, pki: pathlib.Path, ports: dict[str, int]) -> int:
    ca, cert, key = str(pki / "ca.crt"), str(pki / "srv.crt"), str(pki / "srv.key")
    for f in (ca, cert, key):
        if not pathlib.Path(f).is_file():
            print(f"УСЛОВИЕ НЕ СОЗДАНО: нет {f} — стенд не поднимался.", file=sys.stderr)
            return RC_UNMET

    for p in ports.values():
        if not require_listener(host, p):
            print("УСЛОВИЕ НЕ СОЗДАНО:", file=sys.stderr)
            for u in unmet:
                print(f"  · {u}", file=sys.stderr)
            return RC_UNMET

    pub = f"https://{host}:{ports['public_rest']}"
    intl = f"https://{host}:{ports['internal_rest']}"

    print("── рубеж аутентификации собственного публичного фронта ──────────────")
    a = ask(f"{pub}/iam/v1/accounts", ca=ca, cert=cert, key=key)
    check("без удостоверения фронт отвечает 401, а не 200",
          a.status == 401, f"код {a.status}, тело {a.body[:200]!r}")
    check("и отказ НАЗЫВАЕТ, чем назваться (не глухой 401)",
          '"code":16' in a.body.replace(" ", "") and "Bearer" in a.body,
          f"тело {a.body[:200]!r}")

    print("── взаимная непроницаемость двух фронтов (ban #6 и его зеркало) ─────")
    a_int_on_pub = ask(f"{pub}/iam/v1/internal/limits", ca=ca, cert=cert, key=key)
    check("внутренний путь НЕ резолвится на публичном фронте",
          a_int_on_pub.status == 404, f"код {a_int_on_pub.status}")
    check("и это промах МАРШРУТИЗАТОРА, а не сокрытие ресурса "
          "(голое «Not Found», без имени и идентификатора)",
          "Not Found" in a_int_on_pub.body and "limit" not in a_int_on_pub.body.lower(),
          f"тело {a_int_on_pub.body[:200]!r}")
    a_pub_on_int = ask(f"{intl}/iam/v1/accounts", ca=ca, cert=cert, key=key)
    check("публичный путь НЕ резолвится на внутреннем фронте",
          a_pub_on_int.status == 404, f"код {a_pub_on_int.status}")

    print("── разбор доступа стоит и на ВНУТРЕННЕМ слушателе ───────────────────")
    a_int = ask(f"{intl}/iam/v1/internal/limits", ca=ca, cert=cert, key=key)
    check("внутренний метод с модульным сертификатом отвечает 403, а не 200",
          a_int.status == 403, f"код {a_int.status}, тело {a_int.body[:200]!r}")
    check("и отказ несёт МАШИННЫЙ признак полосы, а не только прозу",
          "AUTHZ_DENIED" in a_int.body, f"тело {a_int.body[:300]!r}")

    print("── взаимный TLS: без клиентского сертификата разговора нет ──────────")
    for label, base in (("публичный", pub), ("внутренний", intl)):
        a_noc = ask(f"{base}/iam/v1/accounts", ca=ca, cert=None, key=None)
        check(f"{label} фронт отвергает клиента БЕЗ сертификата на рукопожатии",
              not a_noc.handshake and a_noc.status is None,
              f"состоялось={a_noc.handshake}, код={a_noc.status}, {a_noc.why}")

    print("── метод вне объявленного отвергается фронтом, а не службой ─────────")
    a_m = ask(f"{pub}/iam/v1/accounts", ca=ca, cert=cert, key=key, method="DELETE")
    check("несуществующий для пути метод даёт 405",
          a_m.status == 405, f"код {a_m.status}, тело {a_m.body[:200]!r}")

    print("── отсутствующий сосед даёт ЧЕСТНЫЙ отказ, а не пустой успех ───────")
    a_j = ask(f"https://{host}:{ports['keyset']}/.well-known/jwks.json",
              ca=ca, cert=cert, key=key)
    check("зеркало набора ключей недостижимого поставщика отвечает 502",
          a_j.status == 502, f"код {a_j.status}, тело {a_j.body[:200]!r}")
    check("и НАЗЫВАЕТ недостижимость, а не отдаёт пустой набор ключей",
          "unavailable" in a_j.body.lower() and '"keys"' not in a_j.body,
          f"тело {a_j.body[:200]!r}")

    a_d = ask(f"https://{host}:{ports['docker']}/iam/token", ca=ca, cert=cert, key=key)
    check("полоса выдачи docker-токена отвечает 401 и объясняет форму входа",
          a_d.status == 401 and "docker login" in a_d.body,
          f"код {a_d.status}, тело {a_d.body[:200]!r}")

    print()
    print(f"перепись: утверждений {checked} · находок {len(findings)} · "
          f"условие не создано у {len(unmet)} проверок")
    if checked == 0:
        print("ОТКАЗ: не исполнено ни одного утверждения — «ноль находок» здесь "
              "означало бы «ноль прочитанного».", file=sys.stderr)
        return 1
    if findings:
        print(f"НАХОДОК {len(findings)}:", file=sys.stderr)
        for f in findings:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("ЧИСТО: служба производит все названные свойства САМА — без края "
          "платформы, её сервисов и достижимого поставщика удостоверений.")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_SELF_FAILURES: list[str] = []


def _self_check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _SELF_FAILURES.append(label)
        if detail:
            print(f"       {detail}")


class _Stub(http.server.BaseHTTPRequestHandler):
    """Подставной фронт: отвечает ВСЕГДА 200 и пустым телом.

    Он заведомо НЕГОДЕН по каждому утверждению сразу — именно поэтому им и
    доказывают способность упасть: подделка, которая могла бы дать зелёное,
    доказывала бы только сама себя.
    """

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    do_DELETE = do_GET

    def log_message(self, *_a):
        pass


def _throwaway_pki() -> pathlib.Path:
    """Одноразовый УЦ для подставного сервера самопроверки.

    Выпускается во ВРЕМЕННЫЙ каталог вне репозитория: инструмент, заводящий
    синтетику внутри дерева, находит его индекс обходом вверх и краснеет по
    ложной причине. Каталог живёт до конца процесса — этого достаточно.
    """
    import tempfile
    d = pathlib.Path(tempfile.mkdtemp(prefix="stand-assert-pki-"))
    cnf = d / "openssl.cnf"
    cnf.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n"
        "[v3_srv]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n", encoding="utf-8")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=stand-assert-selftest",
                    "-config", str(cnf), "-extensions", "v3_srv",
                    "-keyout", str(d / "srv.key"), "-out", str(d / "srv.crt")],
                   check=True, capture_output=True)
    # Свой же сертификат служит и корнем доверия: подставной сервер один, и
    # цепочка из двух звеньев ничего к доказательству не добавила бы.
    (d / "ca.crt").write_bytes((d / "srv.crt").read_bytes())
    return d


def self_test(pki: pathlib.Path) -> int:
    print("stand-assert: доказательство способности упасть")

    # Ось 1: слушателя нет вовсе — ТРЕТИЙ исход, а не находка.
    #
    # Свободный порт берётся у ядра и сразу освобождается: адресовать «другой
    # loopback» нельзя — служба слушает на всех адресах, и соединение состоялось бы.
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    _, closed_port = free.getsockname()
    free.close()
    rc = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve()),
         "--host", "127.0.0.1", "--pki", str(pki),
         "--port-public", str(closed_port), "--port-internal", str(closed_port),
         "--port-keyset", str(closed_port), "--port-docker", str(closed_port)],
        capture_output=True, text=True).returncode
    _self_check("нет слушателя — код 75, а НЕ 1 и не 0", rc == RC_UNMET, f"код {rc}")

    # САМОПРОВЕРКА НЕ ЗАВИСИТ ОТ СТЕНДА — и это несущее свойство, а не удобство:
    # она стоит ДО подъёма (доказать способность упасть надо прежде, чем вердикту
    # поверят), значит PKI стенда в этот момент ещё нет. Свой одноразовый УЦ
    # выпускается здесь и живёт ровно этот прогон.
    if not (pki / "ca.crt").is_file():
        pki = _throwaway_pki()
        print(f"  (PKI стенда ещё нет — выпущен одноразовый: {pki})")

    # Ось 2: слушатель есть и отвечает НЕ ТЕМ — находка, а не третий исход.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki / "srv.crt"), str(pki / "srv.key"))
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        a = ask(f"https://localhost:{port}/iam/v1/accounts",
                ca=str(pki / "ca.crt"), cert=str(pki / "srv.crt"), key=str(pki / "srv.key"))
        _self_check("подставной фронт поднялся и отвечает 200 на всё",
                    a.status == 200, f"код {a.status}, {a.why}")
        # РЕШАЮЩАЯ ОСЬ: гоняются НАСТОЯЩИЕ утверждения против подставного фронта.
        # Проверять «ответил бы он 200» недостаточно — это утверждение о подделке,
        # а не о проверке. Здесь падает сама проверка, и падает КОДОМ 1, а не 75:
        # слушатель есть, отвечает не тем, значит вердикт о дереве вынесен.
        proc = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve()),
             "--host", "localhost", "--pki", str(pki),
             "--port-public", str(port), "--port-internal", str(port),
             "--port-keyset", str(port), "--port-docker", str(port)],
            capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        _self_check("настоящие утверждения на подставном фронте — код 1 (находка), "
                    "а не 75 и не 0", proc.returncode == 1, f"код {proc.returncode}")
        # ЧИСЛО ЧИТАЕТСЯ РАЗБОРОМ, А НЕ ПОДСТРОКОЙ. Первая редакция сверяла
        # «НАХОДОК 1» подстрокой — и совпадала с «НАХОДОК 12», то есть предикат
        # объявлял находкой ровно тот случай, который считал правильным.
        n_found = 0
        for line in out.splitlines():
            if line.startswith("НАХОДОК "):
                n_found = int(line.split()[1].rstrip(":"))
        _self_check("находок НЕСКОЛЬКО: подделка негодна по каждой оси сразу",
                    n_found > 1, f"находок {n_found}; вывод: {out[-300:]}")
        for needle in ("отвечает 401", "НЕ резолвится на публичном фронте",
                       "отвечает 403", "отвергает клиента БЕЗ сертификата",
                       "даёт 405", "отвечает 502"):
            _self_check(f"упало утверждение «{needle}»",
                        f"FAIL" in out and needle in out, out[-300:])
        _self_check("перепись напечатана и на красном",
                    "перепись: утверждений" in out, out[-300:])
    finally:
        srv.shutdown()

    print()
    if _SELF_FAILURES:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF_FAILURES)} — "
              f"{', '.join(_SELF_FAILURES)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: «нет слушателя» отличимо от «ответил не тем» КОДОМ, а подставной "
          "фронт, отвечающий 200 на всё, не проходит ни одного утверждения.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--pki", default=str(DEFAULT_PKI))
    # Порты объявлены флагами, а не выведены из ручки окружения: ручка, которую
    # читает боевой прогон, стала бы способом увести утверждения на другой адрес.
    # Флаги задаёт только самопроверка, и это видно в её собственном вызове.
    ap.add_argument("--port-public", type=int, default=9098)
    ap.add_argument("--port-internal", type=int, default=9099)
    ap.add_argument("--port-keyset", type=int, default=9097)
    ap.add_argument("--port-docker", type=int, default=9096)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    pki = pathlib.Path(args.pki)
    if args.self_test:
        return self_test(pki)
    return run(args.host, pki, {
        "public_rest": args.port_public,
        "internal_rest": args.port_internal,
        "keyset": args.port_keyset,
        "docker": args.port_docker,
    })


if __name__ == "__main__":
    sys.exit(main())
