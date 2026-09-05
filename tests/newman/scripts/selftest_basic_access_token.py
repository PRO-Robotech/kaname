#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: сквозной кейс базового удостоверения ЧИТАЕТ ИСХОД и СПОСОБЕН УПАСТЬ.

# Предмет

Во всём сквозном прогоне не было НИ ОДНОГО зелёного утверждения, читающего
секрет из успешного ответа (задача #1253). Пока положительного прохода нет,
утверждения кейса не проверены ничем: то, которое не совпало бы ни при каком
ответе, выглядит точно так же, как исправное. Ровно так и случилось — образец
формы ждал разделитель после префикса, которого продукт не чеканит.

Прогон против поднятого стенда это закрывает, но требует стенда. Здесь — то,
что доказуемо без него: НАСТОЯЩИЙ newman по НАСТОЯЩЕЙ порождённой коллекции,
ответы даёт подставной край.

# Чем это отличается от «выписать ответ руками»

Секрет в законном ответе НЕ выписан: его чеканит код продукта — программа
`scripts/credsecretmint` зовёт `ids.NewID` и `credsecret.Mint`, те же вызовы,
что стоят на пути выдачи. Вычислить такое значение на стороне пробы нельзя:
в нём контрольная сумма, и своя её реализация стала бы второй копией предиката
формы — тем самым, что уже разошлось молча.

Поэтому зелёное здесь означает: утверждение о форме СОВПАЛО со значением,
отчеканенным продуктом.

# Пара на каждой оси

Законный ответ обязан пройти МОЛЧА; внесённый дефект обязан УПАСТЬ и назвать
себя. Одной стороны не хватает ни там, ни там: утверждение, ослабленное до
тождественно истинного, зеленеет на законном входе точно так же.

| ось                              | законный вход              | инъекция                                  |
|----------------------------------|----------------------------|-------------------------------------------|
| форма секрета                    | чеканка продукта           | разделитель после префикса (тот дефект)   |
| вид назван                       | секрет вида `uoc`          | секрет вида `soc` в ответе о `uoc`        |
| секрет без ключевого материала   | пустые поля ключа          | ответ дополнительно несёт закрытый ключ   |
| срок назван всегда               | `expiresAt` непуст         | `expiresAt` пуст                          |
| строка называет своё удостоверение | id из строки = token.id  | ответ называет другое удостоверение       |
| живой секрет ПРОХОДИТ            | край принимает             | край отвергает живой секрет               |
| испорченный ОТВЕРГАЕТСЯ          | край отвергает             | край принимает испорченную строку         |
| секрет показан один раз          | операция без секрета       | операция перечитывается вместе с секретом |
| отзыв доходит до предъявления    | после отзыва отказ         | после отзыва край продолжает принимать    |

# Чем это слабее прогона против стенда — названо прямо

Доказано: «утверждения кейса различают эти входы» и «образец формы совпадает со
значением продукта». НЕ доказано: «продукт на стенде отвечает именно так» — это
свойство продукта, и его подтверждает только прогон против поднятого стенда.

# Пол вердикта и его собственное доказательство

«Упавших ноль» вердиктом не является: ноль приходит и от полосы, где нечего
было исполнять. Поэтому здесь пол — отчёт получен, утверждения ИСПОЛНЕНЫ,
запросы отвечены, скрипт не отказал, — и он сам есть утверждение, обязанное
уметь падать. Его доказательство (`--self-test`) идёт ПЕРВЫМ действием каждого
запуска, а не отдельной строкой конвейера: строку снимают молча, а вызывающего
по построению снять нельзя, не сняв сам производитель, — того держит гейт
дерева `internal/repohygiene` `TestBasicCredentialFormProofIsProducedByARun`.

Запуск (стенда не нужно; нужны newman и go):

    python3 scripts/selftest_basic_access_token.py

Только доказательство пола — ни newman, ни go, ни коллекции не требует:

    python3 scripts/selftest_basic_access_token.py --self-test

Коды возврата: 0 — свойство держится; 1 — находки; 2 — предпосылка не выполнена
(нет newman, нет go, нет коллекции, ни одна ось не исполнилась — то есть проба
не проверила НИЧЕГО и обязана сказать это отдельно от «находок нет»).
"""

from __future__ import annotations

import http.server
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COLLECTION = ROOT / "collections" / "basic-access-token.postman_collection.json"
REPO_ROOT = ROOT.parents[3]
# Служба несёт СВОЙ модуль, поэтому путь чеканки называется ОТНОСИТЕЛЬНО его
# корня, а go зовётся с `-C`. Прежняя форма — путь от корня монорепо — отказывала
# на каждом прогоне: «main module (github.com/PRO-Robotech/kacho) does not
# contain package …/services/iam/tests/newman/scripts/credsecretmint», и отказ
# приходил ПРЕДПОСЫЛКОЙ, то есть выглядел несозданным условием, а не сломанным
# путём.
MINT_MODULE_DIR = REPO_ROOT / "services" / "iam"
MINT_PKG = "./tests/newman/scripts/credsecretmint"

CASE_PREFIX = "IAM-BAT-SECRET-LIFECYCLE-OK"
USER_ID = "usr0000000000000bat0"
BOOT_BEARER = "bootstrap-bearer-for-selftest"
ISSUE_OP_ID = "iop0000000000000bat1"
REVOKE_OP_ID = "iop0000000000000bat2"
CRED_KIND = "CREDENTIAL_KIND_SECRET"
EXPIRES_AT = "2026-12-01T00:00:00Z"


def mint(prefix: str = "uoc") -> tuple[str, str]:
    """Удостоверение, ОТЧЕКАНЕННОЕ КОДОМ ПРОДУКТА.

    Вызов, а не повторение: контрольная сумма — часть формы, и своя её
    реализация здесь была бы копией предиката, ради снятия которой всё и
    затевалось.
    """
    out = subprocess.run(
        ["go", "run", "-C", str(MINT_MODULE_DIR), MINT_PKG, "-prefix", prefix],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600)
    if out.returncode != 0:
        raise SystemExit(
            f"ПРЕДПОСЫЛКА: чеканка продуктом не состоялась (rc={out.returncode}):\n{out.stderr}")
    got = json.loads(out.stdout.strip())
    return got["credentialId"], got["secret"]


class Stand:
    """Подставной край: выдача, предъявление, чтение операции, отзыв.

    Ведёт состояние отзыва — иначе «после отзыва отказ» проверялось бы на крае,
    который отвергает всегда, и утверждение зеленело бы, ничего не значив.
    """

    def __init__(self, *, credential_id: str, secret: str,
                 answered_secret: str | None = None,
                 key_material: bool = False,
                 expires_at: str = EXPIRES_AT,
                 answered_credential_id: str | None = None,
                 reject_live: bool = False,
                 accept_tampered: bool = False,
                 operation_carries_secret: bool = False,
                 revoke_reaches_presentation: bool = True):
        self.credential_id = credential_id
        self.secret = secret
        # Что край КЛАДЁТ в ответ. По умолчанию — то же, что принимает; ось
        # формы разводит эти две величины.
        self.answered_secret = secret if answered_secret is None else answered_secret
        self.answered_credential_id = answered_credential_id or credential_id
        self.key_material = key_material
        self.expires_at = expires_at
        self.reject_live = reject_live
        self.accept_tampered = accept_tampered
        self.operation_carries_secret = operation_carries_secret
        self.revoke_reaches_presentation = revoke_reaches_presentation
        self.revoked = False
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):  # тишина: вывод судит python, а не сервер
                pass

            def _send(self, code: int, body: dict):
                raw = json.dumps(body, ensure_ascii=False).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _issue_response(self, *, with_secret: bool) -> dict:
                resp = {
                    "secret": outer.answered_secret if with_secret else "",
                    "token": {
                        "id": outer.answered_credential_id,
                        "credentialKind": CRED_KIND,
                        "expiresAt": outer.expires_at,
                    },
                }
                if outer.key_material:
                    resp["privateKeyPem"] = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"
                    resp["publicKeyPem"] = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
                    resp["algorithm"] = "ES256"
                return {"id": ISSUE_OP_ID, "done": True, "metadata": {}, "response": resp}

            def do_POST(self):
                if self.path.endswith("/tokens"):
                    return self._send(200, self._issue_response(with_secret=True))
                return self._send(404, {"code": 5, "message": "Not Found"})

            def do_DELETE(self):
                if "/tokens/" in self.path:
                    outer.revoked = True
                    return self._send(200, {"id": REVOKE_OP_ID, "done": True, "metadata": {}})
                return self._send(404, {"code": 5, "message": "Not Found"})

            def do_GET(self):
                path = self.path.split("?")[0]
                if path == f"/operations/{ISSUE_OP_ID}":
                    # Перечитывание операции выдачи: секрет в ней жить не должен.
                    return self._send(200, self._issue_response(
                        with_secret=outer.operation_carries_secret))
                if path == f"/operations/{REVOKE_OP_ID}":
                    return self._send(200, {"id": REVOKE_OP_ID, "done": True, "metadata": {}})
                if path == "/iam/v1/me":
                    got = (self.headers.get("Authorization") or "").replace("Bearer ", "", 1)
                    if got == outer.secret:
                        if outer.reject_live:
                            return self._send(401, {"code": 16, "message": "token validation failed"})
                        if outer.revoked and outer.revoke_reaches_presentation:
                            return self._send(401, {"code": 16, "message": "credential revoked"})
                        return self._send(200, {"subject": USER_ID, "userId": USER_ID,
                                                "email": "", "displayName": "",
                                                "systemAdmin": False, "clusterViewer": True,
                                                "accounts": [], "checkedAt": EXPIRES_AT})
                    if got == BOOT_BEARER:
                        return self._send(200, {"subject": "bootstrap", "userId": "",
                                                "accounts": []})
                    if outer.accept_tampered:
                        # Полоса, не РАЗБИРАЮЩАЯ удостоверение: смотрит на вид и
                        # пропускает. Ровно то, что обязан ловить парный шаг.
                        return self._send(200, {"subject": USER_ID, "userId": USER_ID,
                                                "accounts": []})
                    return self._send(401, {"code": 16, "message": "token validation failed"})
                return self._send(404, {"code": 5, "message": "Not Found"})

        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()
        self._srv.server_close()


def folder_named(prefix: str) -> str:
    col = json.loads(COLLECTION.read_text())
    for item in col["item"]:
        if item["name"].startswith(prefix):
            return item["name"]
    raise SystemExit(f"ПРЕДПОСЫЛКА: в коллекции нет кейса {prefix}")


class Outcome:
    """Исход одной полосы — ШЕСТЬ величин, а не одна.

    Числа берутся из `run.stats`, а НЕ пересчитываются обходом
    `run.executions`: массив расходится со сводкой в обе стороны, и занижение
    выглядит как улучшение.

    Отказы скрипта и безответные запросы считаются ОТДЕЛЬНО и никогда не
    вычитаются из вердикта: newman пишет исключение тест-скрипта в
    `testScripts`, а не в `assertions.failed`, поэтому полоса с неразобранным
    скриптом отчитывается нулём упавших. Это третья категория исхода — «не
    выполнилось».
    """

    def __init__(self) -> None:
        self.report = False        # отчёт вообще получен
        self.executions = 0        # запросов исполнено
        self.requests_failed = 0   # из них БЕЗ ОТВЕТА
        self.assertions = 0        # утверждений исполнено
        self.failed = 0            # из них упавших
        self.script_errors = 0     # отказов скрипта / пред-скрипта
        self.texts: list[str] = []

    @property
    def passed(self) -> int:
        return self.assertions - self.failed

    @property
    def silent(self) -> bool:
        """Отчёт есть, а утверждений в нём НЕТ — отдельная категория.

        Ноль упавших при нуле исполненных неотличим от прохода по одному лишь
        счётчику отказов: `passed = total - failed` даёт ноль, и полоса
        отчитывается «зелёной», не проверив ничего.
        """
        return self.report and self.assertions == 0

    def caught(self) -> bool:
        """Инъекция ПОЙМАНА: что-то исполнилось и на этом упало."""
        return self.assertions > 0 and (self.failed > 0 or self.script_errors > 0)

    def clean(self) -> bool:
        """Законный вход ПРОШЁЛ: исполнилось, ответило и не упало.

        Пол обязателен. Без него «упавших 0» приходит и от полосы, где нечего
        было исполнять, — а предикат задачи #1253 требует ЗЕЛЁНОГО утверждения,
        то есть исполненного и совпавшего, а не отсутствия красного.
        """
        return (self.report and self.assertions > 0 and self.failed == 0
                and self.script_errors == 0 and self.requests_failed == 0)

    def line(self) -> str:
        return (f"запросов {self.executions} (без ответа {self.requests_failed}) · "
                f"утверждений {self.assertions} (упало {self.failed}) · "
                f"отказов скрипта {self.script_errors}")


def run_folder(stand: Stand, folder: str) -> Outcome:
    """Гоняет кейс против подставного края и возвращает ШЕСТЬ величин исхода."""
    res = Outcome()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        base = f"http://127.0.0.1:{stand.port}"
        cmd = [
            "newman", "run", str(COLLECTION), "--folder", folder,
            "--env-var", f"baseUrl={base}",
            "--env-var", f"internalBaseUrl={base}",
            "--env-var", f"userAAAId={USER_ID}",
            "--env-var", "runId=selftest",
            "--env-var", f"jwtBootstrap={BOOT_BEARER}",
            "--reporters", "json", "--reporter-json-export", str(out),
            "--timeout-request", "8000",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if not out.exists():
            res.texts.append("НЕТ ОТЧЁТА — прогон не состоялся")
            return res
        res.report = True
        rep = json.loads(out.read_text())
        run = rep.get("run", {})
        for f in run.get("failures", []):
            err = f.get("error", {}) or {}
            if err.get("test"):
                res.texts.append(err["test"])
            else:
                res.script_errors += 1
                res.texts.append("СКРИПТ НЕ ИСПОЛНИЛСЯ: " + str(err.get("message", "")))
        stats = run.get("stats", {})
        res.script_errors += int(stats.get("testScripts", {}).get("failed", 0))
        res.script_errors += int(stats.get("prerequestScripts", {}).get("failed", 0))
        res.assertions = int(stats.get("assertions", {}).get("total", 0))
        res.failed = int(stats.get("assertions", {}).get("failed", 0))
        res.requests_failed = int(stats.get("requests", {}).get("failed", 0))
        # Запросы считаются ПО СВОДКЕ, а не обходом массива исполнений:
        # массив расходится со сводкой в обе стороны, и занижение выглядит
        # как улучшение (`e2e-flow.md` §1).
        res.executions = int(stats.get("requests", {}).get("total", 0))
        return res


def outcome_from_stats(stats: dict, *, report: bool = True,
                       failures: list[str] | None = None) -> Outcome:
    """Исход, собранный из сводки, — без newman.

    Нужен самопроверке ниже: способность ПОЛА упасть доказывается на
    синтетической сводке, а не подъёмом подставного края.
    """
    res = Outcome()
    res.report = report
    if not report:
        return res
    res.assertions = int(stats.get("assertions", 0))
    res.failed = int(stats.get("failed", 0))
    res.requests_failed = int(stats.get("requests_failed", 0))
    res.executions = int(stats.get("requests", 0))
    res.script_errors = int(stats.get("script_errors", 0))
    res.texts = list(failures or [])
    return res


def self_test() -> int:
    """Доказательство ПОЛА в обе стороны — стенда и newman не требует.

    Пол («законный вход обязан быть исполнен, а не только не упасть») сам есть
    утверждение о дереве, и утверждение это обязано уметь падать. Проверять его
    настоящим прогоном нельзя: чтобы получить отчёт с нулём утверждений, нужна
    коллекция, которой в дереве нет и заводить которую ради пробы значило бы
    завести вторую копию предмета.

    Каждая ось названа парой: вход, на котором свойство обязано ДЕРЖАТЬСЯ, и
    вход, на котором оно обязано ОТКАЗАТЬ. Односторонняя проба зеленела бы на
    предикате, отвергающем всё.
    """
    green = {"assertions": 23, "failed": 0, "requests": 9,
             "requests_failed": 0, "script_errors": 0}
    axes = [
        # (имя, исход, ожидание: clean, silent, caught)
        ("законный вход исполнен и не упал",
         outcome_from_stats(green), True, False, False),
        ("ОТЧЁТ С НУЛЁМ УТВЕРЖДЕНИЙ — не зелёное и не красное",
         outcome_from_stats({**green, "assertions": 0, "requests": 0}), False, True, False),
        ("отчёта нет вовсе — прогон не состоялся",
         outcome_from_stats(green, report=False), False, False, False),
        ("упавшее утверждение — не проход",
         outcome_from_stats({**green, "failed": 1}), False, False, True),
        ("отказ скрипта — не проход, хотя упавших ноль",
         outcome_from_stats({**green, "script_errors": 1}), False, False, True),
        ("безответный запрос — не проход, хотя упавших ноль",
         outcome_from_stats({**green, "requests_failed": 1}), False, False, False),
        ("инъекция поймана: исполнилось И упало",
         outcome_from_stats({**green, "failed": 4}), False, False, True),
        ("инъекция на пустом отчёте ловлей НЕ считается",
         outcome_from_stats({**green, "assertions": 0, "failed": 0, "requests": 0}),
         False, True, False),
        # ОТКАЗ СКРИПТА ПРИ НУЛЕ УТВЕРЖДЕНИЙ — «не выполнилось», а НЕ ловля.
        #
        # Ось добавлена ПО НАХОДКЕ ИНЪЕКЦИИ, а не по замыслу: `caught()`,
        # ослабленный до «упало ИЛИ отказал скрипт» — то есть потерявший
        # требование «что-то исполнилось», — проходил все прежние восемь осей
        # МОЛЧА. Ни одна из них не подавала отказ вместе с нулём утверждений,
        # поэтому требование «исполнилось И упало» было объявлено, но не
        # проверено ничем: самопроверка пола сама имела форму без содержания.
        #
        # Вход реален, а не выдуман ради оси: отказ пред-скрипта newman пишет в
        # `prerequestScripts.failed`, тогда как `assertions.total` остаётся
        # нулём — шаг не дошёл НИ ДО ОДНОГО утверждения. Сказать про такую
        # полосу «инъекция поймана» не о чем: она не исполнялась.
        #
        # Пары `assertions=0, failed=1` здесь нет намеренно: упавших не бывает
        # больше исполненных, и синтетика такого состояния утверждала бы о
        # входе, которого newman не производит.
        ("отказ скрипта при НУЛЕ утверждений — «не выполнилось», а не ловля",
         outcome_from_stats({**green, "assertions": 0, "failed": 0,
                             "requests": 1, "script_errors": 1}),
         False, True, False),
    ]

    findings = []
    for name, got, want_clean, want_silent, want_caught in axes:
        for what, have, want in (("clean", got.clean(), want_clean),
                                 ("silent", got.silent, want_silent),
                                 ("caught", got.caught(), want_caught)):
            if have != want:
                findings.append(f"{name}: {what} = {have}, ожидалось {want}")

    print(f"самопроверка пола: осей {len(axes)} · утверждений {len(axes) * 3} · "
          f"находок {len(findings)}")
    if not axes:
        print("ПРЕДПОСЫЛКА: осей ноль — самопроверка не проверила ничего")
        return 2
    if findings:
        print("\nНАХОДКИ:")
        for f in findings:
            print("  •", f)
        return 1
    print("самопроверка: OK — пол отличает исполненное от неисполненного в обе стороны")
    return 0


def main() -> int:
    # ПОЛ ДОКАЗЫВАЕТСЯ ТЕМ ЖЕ ЗАПУСКОМ, который производит зелёное утверждение.
    #
    # Самопроверка ниже — утверждение о том, что вердикт этого прогона вообще
    # что-то значит: «упавших ноль» приходит и от полосы, где нечего было
    # исполнять. Отдельной строкой в конвейере она была бы вторым местом об
    # одном предмете и снималась бы молча — ровно тот класс, ради которого
    # заведена задача #1253: проверка, которую никто не зовёт, ничего не
    # производит, и её зелёное существует только в чужой голове.
    #
    # Здесь у неё вызывающий ПО ПОСТРОЕНИЮ: снять его нельзя, не сняв сам
    # производитель, а того держит гейт дерева `internal/repohygiene`
    # `TestBasicCredentialFormProofIsProducedByARun`. Цена — доли секунды:
    # самопроверка не требует ни newman, ни go, ни коллекции, поэтому стоит
    # ПЕРЕД проверками предпосылок и краснеет даже там, где прогона не будет.
    rc = self_test()
    if rc != 0:
        print("\nПОЛ САМОПРОВЕРКИ НЕ ДЕРЖИТСЯ — вердикт прогона ниже был бы "
              "недействителен: он не отличил бы «исполнено и совпало» от "
              "«не исполнялось вовсе»")
        return rc

    if not shutil.which("newman"):
        print("ПРЕДПОСЫЛКА: newman не установлен — проба не проверила ничего")
        return 2
    if not shutil.which("go"):
        print("ПРЕДПОСЫЛКА: go не установлен — чеканить секрет нечем")
        return 2
    if not COLLECTION.exists():
        print(f"ПРЕДПОСЫЛКА: нет коллекции {COLLECTION} — сперва scripts/gen.py")
        return 2

    folder = folder_named(CASE_PREFIX)
    cred_id, secret = mint("uoc")
    _, foreign_secret = mint("soc")

    findings: list[str] = []
    outcomes: list[Outcome] = []
    executed = 0

    # ── ЗАКОННЫЙ ВХОД: обязан пройти МОЛЧА И НЕ ВПУСТУЮ ────────────────────
    #
    # «Упавших ноль» вердиктом не является: ноль приходит и от полосы, где
    # нечего было исполнять. Измерено на синтетической коллекции с ПУСТОЙ
    # папкой того же имени — прежняя редакция печатала «зелёных утверждений 0 —
    # форма совпала, предъявление прошло, отзыв дошёл», то есть утверждала
    # ровно то, чего не проверяла. Предикат задачи #1253 требует ЗЕЛЁНОГО
    # утверждения, а не отсутствия красного, поэтому здесь пол: отчёт получен,
    # утверждения исполнены, запросы отвечены, скрипт не отказал.
    with Stand(credential_id=cred_id, secret=secret) as st:
        legal = run_folder(st, folder)
    executed += 1
    outcomes.append(legal)
    if legal.silent:
        findings.append(
            "ЗАКОННЫЙ ВХОД: ОТЧЁТ С НУЛЁМ УТВЕРЖДЕНИЙ — это «не выполнилось», а не "
            f"зелёное, и в успех оно не засчитывается ({legal.line()}). "
            "Производитель зелёного утверждения о форме не произвёл ни одного")
    elif not legal.clean():
        findings.append(
            f"ЗАКОННЫЙ ВХОД НЕ ПРОШЁЛ: {legal.line()}\n    "
            + "\n    ".join(legal.texts))
    else:
        print(f"законный вход: зелёных утверждений {legal.passed} из {legal.assertions} — "
              f"секрет отчеканен продуктом ({secret[:14]}…), форма совпала, "
              f"предъявление прошло, отзыв дошёл")

    # ── ИНЪЕКЦИИ: каждая обязана УПАСТЬ ────────────────────────────────────
    injections = [
        ("форма: разделитель после префикса — тот самый исторический дефект",
         dict(answered_secret=secret[:6] + cred_id[:3] + "_" + cred_id[3:] +
              secret[6 + len(cred_id):])),
        ("вид: в ответе о персональном токене секрет служебной учётки",
         dict(answered_secret=foreign_secret)),
        ("ответ вида SECRET дополнительно несёт закрытый ключ",
         dict(key_material=True)),
        ("срок не назван — «бессрочный» секрет",
         dict(expires_at="")),
        ("строка называет ДРУГОЕ удостоверение, чем ответ",
         dict(answered_credential_id="uoc00000000000000000")),
        ("край отвергает ЖИВОЙ секрет — полоса секрета не работает вовсе",
         dict(reject_live=True)),
        ("край ПРИНИМАЕТ испорченную строку — удостоверение не разбирается",
         dict(accept_tampered=True)),
        ("операция выдачи перечитывается ВМЕСТЕ с секретом — показан не один раз",
         dict(operation_carries_secret=True)),
        ("отзыв не доходит до предъявления — контроль действует только на выдаче",
         dict(revoke_reaches_presentation=False)),
    ]
    for name, kw in injections:
        with Stand(credential_id=cred_id, secret=secret, **kw) as st:
            got = run_folder(st, folder)
        executed += 1
        outcomes.append(got)
        if got.silent:
            findings.append(
                f"ИНЪЕКЦИЯ НЕ ИСПОЛНЯЛАСЬ ({name}): отчёт с нулём утверждений "
                f"({got.line()}) — это «не выполнилось», и «не поймана» здесь сказать "
                "не о чем")
        elif not got.caught():
            findings.append(
                f"ИНЪЕКЦИЯ НЕ ПОЙМАНА ({name}): {got.line()} — кейс не различает этот вход")
        else:
            said = next((t for t in got.texts), "(без текста)")
            print(f"инъекция поймана: {name} → упало {got.failed}; первое: {said[:120]}")

    # ── ВЕРДИКТ ПО ЧИСЛАМ, а не по слову. Шесть величин, и каждая отдельно:
    # «не выполнилось» не вычитается из вердикта и не зачитывается в успех.
    silent = sum(1 for o in outcomes if o.silent)
    no_report = sum(1 for o in outcomes if not o.report)
    print(f"\nперепись: полос исполнено {executed} из {1 + len(injections)} "
          f"(законный вход 1 + инъекций {len(injections)}) · "
          f"запросов {sum(o.executions for o in outcomes)} · "
          f"утверждений {sum(o.assertions for o in outcomes)} · "
          f"упавших {sum(o.failed for o in outcomes)} · "
          f"безответных запросов {sum(o.requests_failed for o in outcomes)} · "
          f"отчётов с нулём утверждений {silent} · без отчёта {no_report} · "
          f"находок {len(findings)}")
    if executed <= 1:
        print("ПРЕДПОСЫЛКА: ни одна инъекция не исполнилась — проба не проверила ничего")
        return 2
    if findings:
        print("\nНАХОДКИ:")
        for f in findings:
            print("  •", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else main())
