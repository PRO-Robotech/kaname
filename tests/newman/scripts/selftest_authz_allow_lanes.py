#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ALLOW-полосы матрицы authz-deny СПОСОБНЫ УПАСТЬ — все четыре, и каждая называет отказ.

# Предмет

До issue #668 все 74 ALLOW-позиции матрицы iam утверждали одно и то же: «код не 403»
и «код не 16». Отрицание проходит на любом другом ответе, поэтому строка не отличала
исправную систему ни от одной поломки, кроме подписанной 403.

Теперь полос четыре, и каждая утверждает ПАРУ. Проба показывает по каждой: молчание
на здоровом ответе, падение на реальном дефекте с его именем в тексте, и — третьей
стороной — что ПРЕЖНЯЯ форма на том же дефекте ЗЕЛЁНАЯ.

| полоса | кейс                      | здоровый ответ            | инъекция (реальный дефект)            |
|--------|---------------------------|---------------------------|---------------------------------------|
| read   | AUTHZ-PRJ-GT-A1-PA1       | 200 + запрошенный ресурс  | 404 — грант отозван либо не доехал    |
| list   | AUTHZ-ACCT-LS-NOB         | 200 + конверт выдачи      | 503 — фильтр прав fail-closed         |
| op     | AUTHZ-PRJ-CR-A-AAA        | 200 + конверт Operation   | 200 + сам ресурс (нарушение ban #9)   |
| reject | AUTHZ-ACCT-UPFORM-OWN-AAA | 400 + code 3 + текст      | 200 + Operation — имя вне контракта   |
|        |                           |                           | принято, проверка снята               |
| op-710 | AUTHZ-ACCT-UP-OWN-AAA     | 200 + конверт Operation   | 400 — имя отвергнуто до Operation     |
| op-710 | AUTHZ-INV-A-AAA           | 200 + конверт Operation   | 400 — пара полей отвергнута до неё    |

Каждая инъекция выбрана НЕ-403 намеренно: прежняя форма ловила ровно 403, поэтому
отказом в правах ничего бы не различилось. Предмет обратный — показать полосы, на
которых прежняя форма была слепа.

# Полоса `reject` привязана к КОНТРОЛЮ ФОРМЫ, а не к строке матрицы (#710)

Прежде её образцом был `AUTHZ-ACCT-UP-OWN-AAA` — та самая строка, чей синхронный отказ
и был дефектом. Починив строку, проба потеряла бы образец вместе с предметом и краснела
бы не на дефекте, а на исчезновении собственной фикстуры. Образцом стал контроль формы
`AUTHZ-ACCT-UPFORM-OWN-AAA`: он живёт независимо — его предмет и есть отказ по телу.

# Инъекция «право снято» — отдельно и без третьей стороны

Задача #710 требует доказать, что полоса разрешения действительно проверяет разрешение:
у субъекта отняли право → кейс обязан покраснеть. Эта инъекция проверяется отдельным
проходом и БЕЗ сравнения с прежней формой — 403 ровно то единственное, что прежняя
форма и ловила, поэтому сравнение здесь ничего не сообщало бы.

# Поверхность шага берётся из самой коллекции (kaname#398)

Матрица authz-deny переадресована на собственный публичный фронт службы
(`address_own_front`), набор authz-sa-apitoken остался на крае. Какую поверхность
изображает подставной сервер, проба спрашивает у сгенерированной коллекции: страж
адреса в пред-скрипте шага (`gen._ENV_URL_MARK`) называет переменную фронта, шаг без
стража идёт по переменной своего адреса. Прежде проба подавала одну переменную края,
и после переадресации ЗДОРОВЫЙ ответ краснел отказом «ownRestBaseUrl is not set» —
доказательство того, что полосы способны упасть, пропало молча для её смысла.

Вторая переменная пары указывает на ДРУГОЙ подставной сервер. Он отвечает только
«не та поверхность» и считает обращения, поэтому чужая поверхность не может сойти за
здоровый ответ, а её счёт утверждается нулём. Что эта ось способна упасть, проба
показывает сама — контролем «поверхность перепутана» на полосе `read`.

# Чем это слабее прогона против стенда — названо прямо

Исполняется НАСТОЯЩИЙ newman по НАСТОЯЩЕЙ сгенерированной коллекции, но ответы даёт
подставной сервер. Доказано: «утверждение различает эти два ответа». НЕ доказано:
«продукт на этом входе отвечает именно так» — это свойство продукта, и его
подтверждает прогон против поднятого стенда.

Запуск: python3 scripts/selftest_authz_allow_lanes.py   (стенд не нужен, newman нужен)
"""

from __future__ import annotations

import http.server
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402  — признак стража адреса и имя собственного фронта: один источник

ROOT = Path(__file__).resolve().parents[1]

# Две поверхности, между которыми набор выбирает адрес шага: край платформы и
# собственный публичный фронт службы. Имя второй — у генератора, копии здесь нет.
EDGE_VAR = "baseUrl"
SURFACE_VARS = (EDGE_VAR, gen.OWN_FRONT_VAR)
_URL_HOST_VAR = re.compile(r"^\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
# Текст латиницей намеренно: тело уходит через json.dumps с экранированием, и
# кириллица доехала бы до текста падения экранированными кодами символов.
WRONG_SURFACE_TOKEN = "WRONG surface"
_WRONG_SURFACE = (421, {"code": 13,
                        "message": "selftest: request reached the " + WRONG_SURFACE_TOKEN +
                                   " - the collection addresses this step to another front",
                        "details": []})
COLLECTION = ROOT / "collections" / "authz-deny.postman_collection.json"
# Второй набор с теми же полосами. Он НЕ «такой же по аналогии» — его помощник живёт
# своей копией в cases/authz-sa-apitoken.py, поэтому и проверяется отдельно: паритет,
# принятый на веру, ровно тем и опасен (см. data-integrity.md §«Межсервисное намерение»).
SA_COLLECTION = ROOT / "collections" / "authz-sa-apitoken.postman_collection.json"
SEED_NETWORK_A1 = "net00000000000000001"

PROJECT_A1 = "prj00000000000000001"
ACCOUNT_A = "acc00000000000000001"

_OK_PROJECT = {"id": PROJECT_A1, "accountId": ACCOUNT_A, "name": "selftest"}
_OK_ACCOUNTS = {"accounts": [{"id": ACCOUNT_A, "name": "selftest"}], "nextPageToken": ""}
_OK_OPERATION = {"id": "iop00000000000000001", "description": "selftest", "done": False,
                 "metadata": {"projectId": PROJECT_A1}}
_OK_NAME_REJECT = {"code": 3,
                   "message": "Illegal argument name: must match ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$",
                   "details": []}

# Реальные дефекты — все НЕ-403, то есть ровно те, что прежняя форма не видела.
_MISS = {"code": 5, "message": "Project " + PROJECT_A1 + " not found", "details": []}
_UNAVAILABLE = {"code": 14, "message": "authorization service unavailable", "details": []}
_SYNC_RESOURCE = {"id": PROJECT_A1, "accountId": ACCOUNT_A, "name": "selftest"}

# Полосы второго набора: тот же вид ответов, но ресурс — сеть vpc, а идентификатор
# операции несёт префикс `enp` (ids.PrefixOperationVPC), не iam-шный `iop`.
_OK_NETWORK = {"id": SEED_NETWORK_A1, "projectId": PROJECT_A1, "name": "selftest"}
_OK_NETWORKS = {"networks": [_OK_NETWORK], "nextPageToken": ""}
_OK_VPC_OPERATION = {"id": "enp00000000000000001", "description": "selftest", "done": False,
                     "metadata": {"networkId": SEED_NETWORK_A1}}
_NETWORK_MISS = {"code": 5, "message": "Network " + SEED_NETWORK_A1 + " not found", "details": []}
_SYNC_NETWORK = dict(_OK_NETWORK)

# Прежняя форма утверждения — воспроизведена ДОСЛОВНО. Снята из cases/authz-deny.py
# коммитом issue #668.
LEGACY_ALLOW_ASSERTS = [
    "pm.test('[LEGACY] ALLOW: not 403', () => pm.expect(pm.response.code, "
    "'unexpected 403: ' + pm.response.text()).to.not.equal(403));",
    "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
    "pm.test('[LEGACY] ALLOW: not Unauthenticated (16)', () => pm.expect(_j && _j.code, "
    "JSON.stringify(_j)).to.not.equal(16));",
]

# Ответы, которыми ALLOW-строки #710 обязаны отвечать, и дефект, который #710 описывает.
_OK_ACCOUNT_OPERATION = {"id": "iop00000000000000002", "description": "selftest", "done": False,
                         "metadata": {"accountId": ACCOUNT_A}}
_OK_INVITE_OPERATION = {"id": "iop00000000000000003", "description": "selftest", "done": False,
                        "metadata": {"accountId": ACCOUNT_A, "userId": "usr00000000000000001"}}
# Дефект #710 дословно: владелец отверг ТЕЛО синхронно, до Operation, — заявленный
# предмет строки (право обновить аккаунт / право приглашать) не исполнялся вовсе.
_INVITE_PAIR_REJECT = {"code": 3,
                       "message": "Illegal argument project_id: required when role_id is set",
                       "details": []}
# «Право снято»: край отвечает отказом в правах на том же запросе.
_DENIED = {"code": 7, "message": "permission denied", "details": []}

# lane → (префикс кейса, здоровый ответ, ответ-дефект, что обязано прозвучать в падении)
LANES = {
    "read":   ("AUTHZ-PRJ-GT-A1-PA1",   (200, _OK_PROJECT),     (404, _MISS),        "not found"),
    "list":   ("AUTHZ-ACCT-LS-NOB",     (200, _OK_ACCOUNTS),    (503, _UNAVAILABLE), "authorization service unavailable"),
    "op":     ("AUTHZ-PRJ-CR-A-AAA",    (200, _OK_OPERATION),   (200, _SYNC_RESOURCE), PROJECT_A1),
    # Образец полосы `reject` — КОНТРОЛЬ ФОРМЫ, а не починенная строка матрицы: он
    # переживает починку предмета, потому что его предмет и есть отказ по телу (#710).
    "reject": ("AUTHZ-ACCT-UPFORM-OWN-AAA", (400, _OK_NAME_REJECT), (200, _OK_OPERATION), "iop00000000000000001"),
    # Две строки, ради которых заведена #710. Инъекция — их собственное прежнее
    # поведение: синхронный отказ по телу вместо конверта Operation.
    "op-acct-710": ("AUTHZ-ACCT-UP-OWN-AAA", (200, _OK_ACCOUNT_OPERATION),
                    (400, _OK_NAME_REJECT), "Illegal argument name"),
    "op-inv-710":  ("AUTHZ-INV-A-AAA", (200, _OK_INVITE_OPERATION),
                    (400, _INVITE_PAIR_REJECT), "required when role_id is set"),
}

# Инъекция «право снято» — та, которую требует #710: полоса разрешения обязана
# краснеть, когда разрешения нет. Третьей стороны (прежней формы) здесь НЕТ намеренно:
# 403 — ровно то единственное, что прежняя форма ловила, и сравнение было бы вакуумным.
RIGHT_REMOVED = {
    "acct-up": "AUTHZ-ACCT-UP-OWN-AAA",
    "invite":  "AUTHZ-INV-A-AAA",
}

SA_LANES = {
    "sa-read": ("AUTHZ-SA-NET-GT-A1", (200, _OK_NETWORK),       (404, _NETWORK_MISS), "not found"),
    "sa-list": ("AUTHZ-SA-NET-LS-A1", (200, _OK_NETWORKS),      (503, _UNAVAILABLE),  "authorization service unavailable"),
    "sa-op":   ("AUTHZ-SA-NET-CR-A1", (200, _OK_VPC_OPERATION), (200, _SYNC_NETWORK), SEED_NETWORK_A1),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    reply = (200, {})
    hits = 0

    def log_message(self, *_args):
        return

    def _reply(self):
        return _Handler.reply

    def _send(self):
        type(self).hits += 1
        code, payload = self._reply()
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        return self._send()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        return self._send()

    def do_PATCH(self):  # noqa: N802
        return self.do_POST()


class _WrongSurfaceHandler(_Handler):
    """Вторая поверхность пары: любое обращение сюда — находка пробы, а не ответ кейсу."""

    hits = 0

    def _reply(self):
        return _WRONG_SURFACE


def _surface(folder: str, collection: Path) -> str:
    """Переменная поверхности, на которую уходят шаги кейса, — по коллекции, а не по памяти.

    Страж адреса (`gen.require_env_url`) ставит признак первой строкой своего блока и
    переписывает адрес шага на названную переменную; шаг без стража уходит по
    переменной, с которой начинается его адрес.
    """
    coll = json.loads(collection.read_text())
    found: set[str] = set()
    for item in coll["item"]:
        if item["name"] != folder:
            continue
        for step in item.get("item", []):
            guarded = {line[len(gen._ENV_URL_MARK):].split()[0]
                       for event in step.get("event", []) if event.get("listen") == "prerequest"
                       for line in event["script"]["exec"] if line.startswith(gen._ENV_URL_MARK)}
            if not guarded:
                m = _URL_HOST_VAR.match(step["request"]["url"]["raw"])
                guarded = {m.group(1) if m else step["request"]["url"]["raw"]}
            found |= guarded
    if len(found) != 1 or not found <= set(SURFACE_VARS):
        sys.exit(f"selftest: шаги кейса {folder!r} адресуются к {sorted(found)}, а проба "
                 f"изображает ровно одну поверхность из {list(SURFACE_VARS)} — предпосылка "
                 f"сломана, вердикта нет")
    return found.pop()


def _folder(prefix: str, collection: Path = COLLECTION) -> str:
    coll = json.loads(collection.read_text())
    for item in coll["item"]:
        if item["name"].startswith(prefix + " "):
            return item["name"]
    sys.exit(f"selftest: кейса {prefix} нет в коллекции — предпосылка пробы сломана, "
             f"молчание ничего не доказывает")


def _legacy_collection(dst: Path, folder: str, collection: Path = COLLECTION) -> Path:
    coll = json.loads(collection.read_text())
    patched = 0
    for item in coll["item"]:
        if item["name"] != folder:
            continue
        for step in item.get("item", []):
            events = [e for e in step.get("event", []) if e.get("listen") != "test"]
            events.append({"listen": "test",
                           "script": {"type": "text/javascript",
                                      "exec": list(LEGACY_ALLOW_ASSERTS)}})
            step["event"] = events
            patched += 1
    if patched != 1:
        sys.exit(f"selftest: шаг кейса {folder!r} не найден однозначно (найдено {patched}) — "
                 f"третья сторона инъекции не построена, вердикт недействителен")
    dst.write_text(json.dumps(coll))
    return dst


def _run(collection: Path, folder: str, surface: str, urls: dict, report: Path) -> dict:
    """Прогнать кейс: подставной сервер стоит на `surface`, вторая поверхность — на чужом."""
    surfaces = [arg for var in SURFACE_VARS
                for arg in ("--env-var", f"{var}={urls['right' if var == surface else 'wrong']}")]
    subprocess.run(
        ["newman", "run", str(collection), "--folder", folder,
         *surfaces,
         "--env-var", f"projectA1Id={PROJECT_A1}",
         "--env-var", "projectA2Id=prj00000000000000003",
         "--env-var", "projectB1Id=prj00000000000000002",
         "--env-var", f"accountAId={ACCOUNT_A}",
         "--env-var", "accountBId=acc00000000000000002",
         "--env-var", f"existingProjectId={PROJECT_A1}",
         "--env-var", "existingProjectCrossId=prj00000000000000002",
         "--env-var", "jwtProjectAdminA1=selftest-token",
         "--env-var", "jwtAccountAdminA=selftest-token",
         "--env-var", "jwtAccountAdminB=selftest-token",
         "--env-var", "jwtInvitee=selftest-token",
         "--env-var", "jwtPureNoBindings=selftest-token",
         "--env-var", "jwtBootstrap=selftest-token",
         "--env-var", "jwtSAA=selftest-token",
         "--env-var", "jwtSAB=selftest-token",
         "--env-var", "apiTokenA=selftest-token",
         "--env-var", f"seedNetworkA1Id={SEED_NETWORK_A1}",
         "--reporters", "json", "--reporter-json-export", str(report),
         "--timeout-request", "5000"],
        capture_output=True, check=False, text=True, timeout=300)
    if not report.exists():
        sys.exit("selftest: newman не оставил отчёта — это «не выполнилось», а не вердикт")
    run = json.loads(report.read_text())["run"]
    return {"assertions": run["stats"]["assertions"],
            "failures": [f.get("error", {}).get("message", "") for f in run.get("failures", [])]}


def main() -> int:
    if shutil.which("newman") is None:
        print("selftest: newman не установлен — проба НЕ ИСПОЛНЕНА (это не зелёный вердикт)")
        return 2

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    wrong = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WrongSurfaceHandler)
    urls = {"right": f"http://127.0.0.1:{server.server_address[1]}",
            "wrong": f"http://127.0.0.1:{wrong.server_address[1]}"}
    for srv in (server, wrong):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    problems: list[str] = []
    print(f"selftest ALLOW-полос матрицы iam — полос {len(LANES) + len(SA_LANES)} "
          f"в двух наборах, плюс {len(RIGHT_REMOVED)} проверки «право снято»")
    with tempfile.TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        lanes = [(COLLECTION, lane, spec) for lane, spec in LANES.items()]
        lanes += [(SA_COLLECTION, lane, spec) for lane, spec in SA_LANES.items()]
        for collection, lane, (prefix, healthy, broken, token) in lanes:
            folder = _folder(prefix, collection)
            surface = _surface(folder, collection)
            strays = _WrongSurfaceHandler.hits

            _Handler.reply = healthy
            ok = _run(collection, folder, surface, urls, tmpd / f"{lane}-ok.json")
            _Handler.reply = broken
            bad = _run(collection, folder, surface, urls, tmpd / f"{lane}-bad.json")
            legacy = _legacy_collection(tmpd / f"{lane}-legacy.json", folder, collection)
            _Handler.reply = broken
            leg = _run(legacy, folder, surface, urls, tmpd / f"{lane}-legacy-report.json")
            strays = _WrongSurfaceHandler.hits - strays

            print(f"  [{lane}] {prefix}  (поверхность {surface})")
            print(f"      здоровый ответ  : утверждений {ok['assertions']['total']}, "
                  f"упало {ok['assertions']['failed']}")
            print(f"      дефект          : утверждений {bad['assertions']['total']}, "
                  f"упало {bad['assertions']['failed']}")
            for f in bad["failures"]:
                print(f"          падение: {f}")
            print(f"      прежняя форма   : утверждений {leg['assertions']['total']}, "
                  f"упало {leg['assertions']['failed']}  ← ЗЕЛЕНО НА ДЕФЕКТЕ (предмет #668)")

            if ok["assertions"]["total"] == 0:
                problems.append(f"[{lane}] на здоровом ответе не исполнилось НИ ОДНОГО "
                                f"утверждения — «ноль находок» здесь означает «ноль прочитанного»")
            if ok["assertions"]["failed"] != 0:
                problems.append(f"[{lane}] на ЗДОРОВОМ ответе кейс краснеет: {ok['failures']}. "
                                f"Такое утверждение краснеет всегда, и его краснота на дефекте "
                                f"ничего не значит")
            if bad["assertions"]["failed"] == 0:
                problems.append(f"[{lane}] на ДЕФЕКТЕ кейс зелёный — утверждение неспособно "
                                f"упасть по своей причине")
            elif not any(token in f for f in bad["failures"]):
                problems.append(f"[{lane}] кейс упал, но текст падения НЕ НАЗЫВАЕТ дефект "
                                f"({token!r}): {bad['failures']}")
            if leg["assertions"]["total"] == 0:
                problems.append(f"[{lane}] прежняя форма не исполнила НИ ОДНОГО утверждения — "
                                f"её зелень означала бы «не проверяли», а не «не увидела дефект»")
            if leg["assertions"]["failed"] != 0:
                problems.append(f"[{lane}] прежняя форма на дефекте ПОКРАСНЕЛА "
                                f"({leg['failures']}) — значит предмет issue #668 воспроизведён "
                                f"неверно и вывод об усилении не обоснован")
            if strays != 0:
                problems.append(f"[{lane}] обращений к чужой поверхности {strays} — кейс ушёл "
                                f"не на {surface}, и его ответы давал не тот фронт")

        # «Право снято» — инъекция, которую требует #710. Здоровый ответ уже проверен
        # выше (полосы op-*-710), поэтому здесь спрашивается ровно одно: краснеет ли
        # строка, когда край отвечает отказом в правах, и называет ли она отказ.
        for lane, prefix in RIGHT_REMOVED.items():
            folder = _folder(prefix)
            surface = _surface(folder, COLLECTION)
            strays = _WrongSurfaceHandler.hits
            _Handler.reply = (403, _DENIED)
            denied = _run(COLLECTION, folder, surface, urls, tmpd / f"{lane}-denied.json")
            strays = _WrongSurfaceHandler.hits - strays
            print(f"  [право снято] {prefix}  (поверхность {surface})")
            print(f"      403 отказ       : утверждений {denied['assertions']['total']}, "
                  f"упало {denied['assertions']['failed']}")
            for f in denied["failures"]:
                print(f"          падение: {f}")
            if denied["assertions"]["total"] == 0:
                problems.append(f"[право снято/{lane}] не исполнилось НИ ОДНОГО утверждения — "
                                f"молчание здесь означает «не проверяли»")
            if denied["assertions"]["failed"] == 0:
                problems.append(f"[право снято/{lane}] кейс ЗЕЛЁНЫЙ при отказе в правах — "
                                f"полоса разрешения не проверяет разрешение (предмет #710)")
            elif not any("permission denied" in f for f in denied["failures"]):
                problems.append(f"[право снято/{lane}] кейс упал, но текст падения не называет "
                                f"отказ в правах: {denied['failures']}")
            if strays != 0:
                problems.append(f"[право снято/{lane}] обращений к чужой поверхности {strays} — "
                                f"отказ в правах давал не тот фронт")

        # Контроль оси поверхности: здоровый ответ, поданный на ЧУЖУЮ переменную пары,
        # обязан покраснеть и назвать поверхность. Без него нулевой счёт чужой
        # поверхности выше неотличим от сервера, до которого не доходит ничего.
        prefix, healthy = LANES["read"][0], LANES["read"][1]
        folder = _folder(prefix)
        swapped = next(v for v in SURFACE_VARS if v != _surface(folder, COLLECTION))
        strays = _WrongSurfaceHandler.hits
        _Handler.reply = healthy
        mixed = _run(COLLECTION, folder, swapped, urls, tmpd / "surface-swapped.json")
        strays = _WrongSurfaceHandler.hits - strays
        print(f"  [поверхность перепутана] {prefix}  (подставной сервер на {swapped})")
        print(f"      здоровый ответ  : утверждений {mixed['assertions']['total']}, "
              f"упало {mixed['assertions']['failed']}, обращений к чужой поверхности {strays}")
        for f in mixed["failures"]:
            print(f"          падение: {f}")
        if strays == 0:
            problems.append("[поверхность перепутана] до чужой поверхности не дошло ни одного "
                            "запроса — контроль не построен, нулевой счёт выше ничего не значит")
        if mixed["assertions"]["failed"] == 0:
            problems.append("[поверхность перепутана] кейс ЗЕЛЁНЫЙ на чужой поверхности — "
                            "проба неспособна заметить, что ответ дал не тот фронт")
        elif not any(WRONG_SURFACE_TOKEN in f for f in mixed["failures"]):
            problems.append(f"[поверхность перепутана] кейс упал, но текст падения не называет "
                            f"поверхность: {mixed['failures']}")

    server.shutdown()
    wrong.shutdown()

    if problems:
        print("\nselftest: FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nselftest: OK — все полосы обоих наборов различают здоровый ответ и дефект, "
          "называют дефект в тексте падения, прежняя форма не видела ни одного из них, "
          "строки #710 краснеют при снятом праве, каждый кейс получил ответы своей "
          "поверхности, а перепутанная поверхность краснеет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
