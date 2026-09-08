#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: суита токен-фасада ЧИТАЕТ ОБЕ ПОЛОСЫ и СПОСОБНА УПАСТЬ на каждой.

# Предмет

`cases/iam-token-facade-conformance.py` был написан под ОДНУ полосу выдачи —
внешнего поставщика. Когда платформа завела собственного подписанта, каждый
литерал полосы стал ложью о верном мире: алгоритм (`RS256`), запись публикатора
(одна), форма утверждений (вложенная) и контроль `sub !== kaname_principal_id`.
Пять кейсов из восьми покраснели на исправной платформе, причём два — чистым
каскадом: падал шаг, делавший ровно то, что положено делать с величиной, которую
суита не захватила.

Литералы заменены свойствами, общими для ОБЕИХ полос. Такая замена не видна в
диффе: утверждение, ослабленное до тождественно истинного, выглядит так же, как
утверждение, переведённое на общую ось. Поэтому — эта проба.

# Что она делает

Гоняет НАСТОЯЩИЙ newman по НАСТОЯЩЕЙ сгенерированной коллекции; ответы даёт
подставной сервер. По каждой оси — пара: законный вход обеих полос обязан
МОЛЧАТЬ, внесённый дефект обязан УПАСТЬ и назвать себя.

| ось                              | законный вход           | инъекция                                   |
|----------------------------------|-------------------------|--------------------------------------------|
| форма утверждений                | обе (плоская/вложенная) | ни одной формы в токене                    |
| алгоритм предъявителя            | ES256 / RS256           | HS256 — симметричный                       |
| kid опубликован фасадом          | своя запись / зеркало   | kid, которого нет ни в одной записи        |
| kid ровно в ОДНОЙ записи         | как есть                | один kid в обеих записях                   |
| alg записи = alg заголовка       | как есть                | запись объявляет другой алгоритм           |
| материал ключа для подделки      | RSA `n` / EC `x`+`y`    | запись без публичного материала            |
| состав ≠ пересказ субъекта       | `soc_…` ≠ `sva…`        | `kaname_sa_key_id` = `kaname_principal_id`   |
| ответ платформы = состав         | совпадает               | платформа называет другого принципала      |
| публикатор — только открытое     | нет приватных членов    | в записи появился приватный член ключа     |
| запись на объявленном адресе     | 200                     | 404 — запись переехала                     |

# Чем это слабее прогона против стенда — названо прямо

Доказано: «утверждение различает эти два входа». НЕ доказано: «продукт на этом
входе отвечает именно так» — это свойство продукта, и его подтверждает прогон
против поднятого стенда. Подпись подставных предъявителей не проверяется никем:
здесь предмет — то, что суита ЧИТАЕТ, а не то, что край ПРОВЕРЯЕТ.

Запуск (стенд не нужен, newman нужен):
    python3 scripts/selftest_token_facade_forms.py

Коды возврата: 0 — свойство держится; 1 — находки; 2 — предпосылка не выполнена
(нет newman, нет коллекции, ни одна ось не исполнилась — то есть проба не
проверила НИЧЕГО и обязана сказать это отдельно от «находок нет»).
"""

from __future__ import annotations

import base64
import copy
import http.server
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = ROOT / "collections" / "iam-token-facade-conformance.postman_collection.json"

MIRROR_PATH = "/.well-known/jwks.json"
OWN_PATH = "/.well-known/kaname/jwks.json"

# Публичный материал ниже — синтетический и никем не проверяется: подставной
# сервер ничего не подписывает. Форма взята с живого публикатора (RSA-запись
# зеркала, EC-запись своя), потому что именно форму суита и разбирает.
MIRROR_KEY = {
    "use": "sig", "kty": "RSA", "kid": "provider-kid-0001", "alg": "RS256",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}
OWN_KEY = {
    "kty": "EC", "kid": "kacho-own-kid-0001", "alg": "ES256", "use": "sig",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}

PRINCIPAL_ID = "svab91854890de887e6d"
PRINCIPAL_TYPE = "service_account"
SA_KEY_ID = "soc_01hxy2m5f0c7pdq"
ACCOUNT_ID = "acc1p2q3r4s5t6u7v8"
SUBJECT = f"{PRINCIPAL_TYPE}:{PRINCIPAL_ID}"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(header: dict, payload: dict) -> str:
    """Собирает предъявителя. Подпись — заполнитель: её здесь никто не проверяет."""
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{b64u(b'not-a-signature-nobody-verifies-it-here')}"


def base_claims() -> dict:
    return {
        "kaname_principal_type": PRINCIPAL_TYPE,
        "kaname_principal_id": PRINCIPAL_ID,
        "kaname_sa_key_id": SA_KEY_ID,
        "kaname_account_id": ACCOUNT_ID,
    }


def own_lane_bearer(**over) -> str:
    """Полоса ПЛАТФОРМЫ: ES256, свой kid, состав ПЛОСКО, `sub` = принципал."""
    claims = base_claims()
    claims.update(over.pop("claims", {}))
    payload = {"iss": "https://kaname.kacho.local", "aud": ["https://api.kacho.cloud"],
               "sub": PRINCIPAL_ID, "exp": 4102444800, **claims}
    payload.update(over.pop("payload", {}))
    header = {"alg": "ES256", "kid": OWN_KEY["kid"], "typ": "at+jwt"}
    header.update(over.pop("header", {}))
    return jwt(header, payload)


def provider_lane_bearer(**over) -> str:
    """Полоса ПОСТАВЩИКА: RS256, kid зеркала, состав ВЛОЖЕН, `sub` — клиент OAuth."""
    claims = base_claims()
    claims.update(over.pop("claims", {}))
    payload = {"iss": "https://provider.example/.ory/hydra/public",
               "aud": ["https://api.kacho.cloud"], "sub": "kacho-bootstrap-admin",
               "exp": 4102444800, "ext": {"ext_claims": claims}, "ext_claims": claims}
    payload.update(over.pop("payload", {}))
    header = {"alg": "RS256", "kid": MIRROR_KEY["kid"], "typ": "JWT"}
    header.update(over.pop("header", {}))
    return jwt(header, payload)


class Stand:
    """Подставной стенд: край (`/iam/v1/me`) и публикатор ключей фасада."""

    def __init__(self, bearer: str, subject: str = SUBJECT,
                 mirror=None, own=None, own_status: int = 200):
        self.bearer = bearer
        self.subject = subject
        self.mirror = {"keys": [copy.deepcopy(MIRROR_KEY)]} if mirror is None else mirror
        self.own = {"keys": [copy.deepcopy(OWN_KEY)]} if own is None else own
        self.own_status = own_status
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # тишина: вывод судит python, а не http-сервер
                pass

            def _send(self, code: int, body: dict):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == MIRROR_PATH:
                    return self._send(200, outer.mirror)
                if path == OWN_PATH:
                    if outer.own_status != 200:
                        return self._send(outer.own_status, {"error": "not_found"})
                    return self._send(200, outer.own)
                if path == "/iam/v1/me":
                    got = (self.headers.get("Authorization") or "").replace("Bearer ", "", 1)
                    if got != outer.bearer:
                        # Всё, что не подлинный предъявитель, — отказ полосы
                        # аутентификации: анонимный, `alg=none`, подделка HS256.
                        return self._send(401, {"code": 16, "message": "token validation failed"})
                    return self._send(200, {"subject": outer.subject, "userId": "", "email": "",
                                            "displayName": "", "systemAdmin": True,
                                            "clusterViewer": True, "accounts": [],
                                            "checkedAt": "2026-08-24T00:00:00Z"})
                return self._send(404, {"code": 5, "message": "Not Found"})

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()
        self._srv.server_close()


def run_folder(stand: Stand, folder: str) -> tuple[int, int, list[str]]:
    """Гоняет один кейс коллекции против подставного стенда.

    Возвращает (упавших утверждений, отказов СКРИПТА, имена/тексты).

    Отказы скрипта считаются ОТДЕЛЬНО и никогда не вычитаются из вердикта:
    newman пишет исключение тест-скрипта в `testScripts`, а НЕ в
    `assertions.failed`, поэтому суита с синтаксической ошибкой в утверждениях
    отчитывается нулём упавших. Это тот самый третий исход — «не выполнилось», —
    и он обязан быть отличим и от зелёного, и от красного. Замер, ради которого
    строка написана: первая редакция этой пробы объявила четыре оси зелёными,
    когда ни одно утверждение кейса не исполнилось вовсе."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        base = f"http://127.0.0.1:{stand.port}"
        cmd = [
            "newman", "run", str(COLLECTION), "--folder", folder,
            "--env-var", f"baseUrl={base}",
            "--env-var", f"internalBaseUrl={base}",
            "--env-var", f"iamJwksBaseUrl={base}",
            "--env-var", f"providerPublicBaseUrl={base}",
            "--env-var", f"jwtBootstrap={stand.bearer}",
            "--reporters", "json", "--reporter-json-export", str(out),
            "--timeout-request", "8000",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if not out.exists():
            return -1, -1, ["НЕТ ОТЧЁТА — прогон не состоялся"]
        rep = json.loads(out.read_text())
        run = rep.get("run", {})
        fails, script_errors = [], 0
        for f in run.get("failures", []):
            err = f.get("error", {}) or {}
            if err.get("test"):
                fails.append(err["test"])
            else:
                script_errors += 1
                fails.append("СКРИПТ НЕ ИСПОЛНИЛСЯ: " + str(err.get("message", "")))
        stats = run.get("stats", {})
        script_errors += int(stats.get("testScripts", {}).get("failed", 0))
        script_errors += int(stats.get("prerequestScripts", {}).get("failed", 0))
        return int(stats.get("assertions", {}).get("failed", 0)), script_errors, fails


def folder_named(prefix: str) -> str:
    col = json.loads(COLLECTION.read_text())
    for item in col["item"]:
        if item["name"].startswith(prefix):
            return item["name"]
    raise SystemExit(f"ПРЕДПОСЫЛКА: в коллекции нет кейса {prefix}")


def main() -> int:
    if not shutil.which("newman"):
        print("ПРЕДПОСЫЛКА НЕ ВЫПОЛНЕНА: newman не найден в PATH — проверено НИЧЕГО",
              file=sys.stderr)
        return 2
    if not COLLECTION.exists():
        print(f"ПРЕДПОСЫЛКА НЕ ВЫПОЛНЕНА: нет коллекции {COLLECTION} — проверено НИЧЕГО",
              file=sys.stderr)
        return 2

    ibt04, ibt10, ibt13 = folder_named("IBT-04"), folder_named("IBT-10"), folder_named("IBT-13")

    # (имя оси, кейс, стенд, ожидание: True — обязан упасть, False — обязан молчать,
    #  подстрока, которую обязано назвать падение)
    axes = [
        # --- форма утверждений: обе полосы законны, отсутствие обеих — дефект ---
        ("форма: плоская (наша полоса) — молчит", ibt13,
         lambda: Stand(own_lane_bearer()), False, None),
        ("форма: вложенная (полоса поставщика) — молчит", ibt13,
         lambda: Stand(provider_lane_bearer(), subject=SUBJECT), False, None),
        ("форма: ни одной — падает и называет три формы", ibt13,
         lambda: Stand(jwt({"alg": "ES256", "kid": OWN_KEY["kid"], "typ": "at+jwt"},
                           {"iss": "https://kaname.kacho.local", "sub": PRINCIPAL_ID,
                            "aud": ["https://api.kacho.cloud"], "exp": 4102444800})),
         True, "composed platform claims"),

        # --- антитавтологический контроль: состав обязан нести НЕ пересказ субъекта ---
        ("состав: `soc_…` ≠ принципала — молчит", ibt13,
         lambda: Stand(own_lane_bearer()), False, None),
        ("состав: sa_key_id = principal_id — падает", ibt13,
         lambda: Stand(own_lane_bearer(claims={"kaname_sa_key_id": PRINCIPAL_ID})),
         True, "SUBJECT cannot supply"),
        ("состав: sa_key_id = sub — падает", ibt13,
         lambda: Stand(provider_lane_bearer(claims={"kaname_sa_key_id": "kacho-bootstrap-admin"})),
         True, "SUBJECT cannot supply"),
        ("состав: нет kaname_account_id — падает", ibt13,
         lambda: Stand(own_lane_bearer(claims={"kaname_account_id": ""})),
         True, "SUBJECT cannot supply"),
        ("ответ платформы: называет ДРУГОГО принципала — падает", ibt13,
         lambda: Stand(own_lane_bearer(), subject="service_account:svaSOMEONEELSE0000"),
         True, "the composition names"),

        # --- алгоритм и запись публикатора (IBT-04) ---
        ("IBT-04: ES256 + своя запись — молчит", ibt04,
         lambda: Stand(own_lane_bearer()), False, None),
        ("IBT-04: RS256 + зеркало — молчит", ibt04,
         lambda: Stand(provider_lane_bearer()), False, None),
        ("IBT-04: симметричный HS256 — падает", ibt04,
         lambda: Stand(own_lane_bearer(header={"alg": "HS256"})),
         True, "ASYMMETRIC algorithm"),
        ("IBT-04: kid не опубликован ни одной записью — падает", ibt04,
         lambda: Stand(own_lane_bearer(header={"kid": "kid-nobody-publishes"})),
         True, "EXACTLY ONE of its records"),
        ("IBT-04: один kid в ОБЕИХ записях — падает", ibt04,
         lambda: Stand(own_lane_bearer(),
                       mirror={"keys": [dict(MIRROR_KEY, kid=OWN_KEY["kid"])]}),
         True, "EXACTLY ONE of its records"),
        ("IBT-04: запись объявляет ДРУГОЙ алгоритм — падает", ibt04,
         lambda: Stand(own_lane_bearer(header={"alg": "RS256"})),
         True, "SAME algorithm the Bearer header names"),
        ("IBT-04: своя запись переехала (404) — падает и называет адрес", ibt04,
         lambda: Stand(own_lane_bearer(), own_status=404), True, "status 200"),
        ("IBT-04: в записи приватный член ключа — падает", ibt04,
         lambda: Stand(own_lane_bearer(),
                       own={"keys": [dict(OWN_KEY, d="private-half-must-never-be-published")]}),
         True, "PUBLIC material only"),
        ("IBT-04: симметричный ключ в записи — падает", ibt04,
         lambda: Stand(own_lane_bearer(),
                       own={"keys": [{"kty": "oct", "kid": OWN_KEY["kid"], "alg": "HS256",
                                      "use": "sig", "k": "c2hhcmVkLXNlY3JldA"}]}),
         True, "ASYMMETRIC verification material"),

        # --- материал подделки (IBT-10) ---
        ("IBT-10: EC-материал своей записи — подделка строится, молчит", ibt10,
         lambda: Stand(own_lane_bearer()), False, None),
        ("IBT-10: RSA-модуль зеркала — подделка строится, молчит", ibt10,
         lambda: Stand(provider_lane_bearer()), False, None),
        ("IBT-10: у записи нет публичного материала — падает предусловием", ibt10,
         lambda: Stand(own_lane_bearer(),
                       own={"keys": [{"kty": "EC", "kid": OWN_KEY["kid"], "alg": "ES256",
                                      "use": "sig", "crv": "P-256"}]}),
         True, "facade material for its kid"),
    ]

    findings, ran, scripts_broken = [], 0, 0
    for name, folder, make_stand, must_fail, must_name in axes:
        with make_stand() as stand:
            failed, script_errors, fails = run_folder(stand, folder)
        ran += 1
        if failed < 0:
            findings.append(f"{name}: {fails[0]}")
            continue
        joined = " | ".join(fails)
        if script_errors:
            # НЕ ВЫПОЛНИЛОСЬ. Ни зелёное, ни красное: утверждения кейса не
            # исполнялись, поэтому об оси не известно ничего.
            scripts_broken += 1
            findings.append(
                f"{name}: скрипт кейса не исполнился ({script_errors}) — об этой оси не известно "
                f"НИЧЕГО: {joined[:300]}")
        elif must_fail and failed == 0:
            findings.append(f"{name}: дефект внесён, утверждений упало 0 — проверка не способна упасть")
        elif must_fail and must_name and must_name not in joined:
            findings.append(
                f"{name}: упало {failed}, но ни одно не назвало «{must_name}»; названо: {joined[:300]}")
        elif not must_fail and failed != 0:
            findings.append(
                f"{name}: законный вход, а упало {failed} — ложная находка: {joined[:300]}")
        mark = "СКРИПТ" if script_errors else ("RED " if failed else "GREEN")
        print(f"  {mark:6} упало={failed:<2} {name}")

    print(f"[token-facade-forms] осмотрено: осей {ran}, кейсов {len({a[1] for a in axes})}, "
          f"скриптов не исполнилось {scripts_broken}, находок {len(findings)}")
    if ran == 0:
        print("ПРЕДПОСЫЛКА НЕ ВЫПОЛНЕНА: не исполнилась ни одна ось — проверено НИЧЕГО",
              file=sys.stderr)
        return 2
    for f in findings:
        print(f"НАХОДКА: {f}", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
