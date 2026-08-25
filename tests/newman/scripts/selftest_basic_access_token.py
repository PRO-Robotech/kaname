#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

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

Запуск (стенда не нужно; нужны newman и go):

    python3 scripts/selftest_basic_access_token.py

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
MINT_PKG = "./services/iam/tests/newman/scripts/credsecretmint"

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
        ["go", "run", MINT_PKG, "-prefix", prefix],
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


def run_folder(stand: Stand, folder: str) -> tuple[int, int, list[str]]:
    """Гоняет кейс против подставного края.

    Возвращает (упавших утверждений, отказов СКРИПТА, тексты).

    Отказы скрипта считаются ОТДЕЛЬНО и никогда не вычитаются из вердикта:
    newman пишет исключение тест-скрипта в `testScripts`, а НЕ в
    `assertions.failed`, поэтому кейс с неразобранным скриптом отчитывается
    нулём упавших. Это третья категория исхода — «не выполнилось».
    """
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
        passed = int(stats.get("assertions", {}).get("total", 0)) - \
            int(stats.get("assertions", {}).get("failed", 0))
        fails.append(f"__passed__={passed}")
        return int(stats.get("assertions", {}).get("failed", 0)), script_errors, fails


def main() -> int:
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
    executed = 0

    # ── ЗАКОННЫЙ ВХОД: обязан пройти МОЛЧА ─────────────────────────────────
    with Stand(credential_id=cred_id, secret=secret) as st:
        failed, script_errors, texts = run_folder(st, folder)
    executed += 1
    passed = next((t.split("=")[1] for t in texts if t.startswith("__passed__=")), "?")
    if failed != 0 or script_errors != 0:
        findings.append(
            f"ЗАКОННЫЙ ВХОД НЕ ПРОШЁЛ: упавших утверждений {failed}, отказов скрипта "
            f"{script_errors}\n    " + "\n    ".join(t for t in texts if not t.startswith("__")))
    else:
        print(f"законный вход: зелёных утверждений {passed} — секрет отчеканен продуктом "
              f"({secret[:14]}…), форма совпала, предъявление прошло, отзыв дошёл")

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
            failed, script_errors, texts = run_folder(st, folder)
        executed += 1
        if failed <= 0 and script_errors <= 0:
            findings.append(
                f"ИНЪЕКЦИЯ НЕ ПОЙМАНА ({name}): упавших утверждений {failed}, "
                f"отказов скрипта {script_errors} — кейс не различает этот вход")
        else:
            said = next((t for t in texts if not t.startswith("__")), "(без текста)")
            print(f"инъекция поймана: {name} → упало {failed}; первое: {said[:120]}")

    print(f"\nперепись: осей исполнено {executed} (законный вход 1 + инъекций "
          f"{len(injections)}), находок {len(findings)}")
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
    sys.exit(main())
