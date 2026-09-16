#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПРЕДПОЛЁТ ПРОГОНА: годен ли посев, которым собираются гонять.

ПРЕДМЕТ. Посев автономного стенда пишет в окружение предъявителей и `runId`
ОДИН раз; прогонщик их не обновляет. Отсюда два отказа, ни один из которых не
является вердиктом о продукте, и оба по тексту неотличимы от дефекта:

  1. ПРЕДЪЯВИТЕЛЬ ИСТЁК. Срок удостоверений посева — 15 минут (замер на живом
     стенде: `exp − iat` у всех девяти предъявителей 900 с). Повтор позже даёт
     СПЛОШНОЙ 401 с текстом `credential is not accepted` — тем же, каким служба
     отвечает на подделку и на отозванное. Отладка читает его как дефект рубежа;
  2. ПОСЕВ УЖЕ ИЗРАСХОДОВАН. Коллекции создают ресурсы с именем от `{{runId}}`
     (замер: 28 коллекций из 40 читают `runId`, у `authz-deny` 37 вхождений), а
     `runId` пишет посев и больше никто. Повтор без уборки ловит
     `ALREADY_EXISTS`, похожий на дефект уникальности.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — посев годен ЛИБО его в окружении нет вовсе (тогда проверять нечего, и
         это сказано словами: «нет» и «не смотрели» ведут в разные места);
   75  — УСЛОВИЕ НЕ СОЗДАНО: предъявитель отвергнут фронтом либо фронт не
         отвечает. Вердикта о дереве нет НИ ОДНОГО, и гнать коллекции незачем;
    2  — сам предполёт не смог исполниться (нет файла окружения, он не
         разбирается). Это не вердикт ни о посеве, ни о дереве.

ПОЧЕМУ ИЗРАСХОДОВАННЫЙ ПОСЕВ — ПРЕДУПРЕЖДЕНИЕ, А НЕ ОТКАЗ. Повтор ЧИТАЮЩЕЙ
коллекции на том же посеве законен и обычен; отказ на нём был бы порогом,
срабатывающим на штатном состоянии, а такой порог перестают читать вместе с
настоящими находками. Требуется не запретить повтор, а НАЗВАТЬ причину до первой
коллекции — тогда `ALREADY_EXISTS` перестаёт быть загадкой.

ГОДНОСТЬ СПРАШИВАЕТСЯ У ФРОНТА, А НЕ ВЫЧИСЛЯЕТСЯ ИЗ `exp`. Разбор срока сам по
себе сказал бы про подпись и про отзыв ничего: отозванное удостоверение не
истекло, а принято не будет. Спрашивается то же, что спросит первая коллекция.

САМОПРОВЕРКА — `--self-test`: поддельный фронт отвечает по очереди принятием,
отказом рубежа и молчанием; рядом мир без посева и мир с израсходованным
посевом. Каждая сторона своим кодом.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import ssl
import sys
import urllib.error
import urllib.request

RC_OK = 0
RC_UNMET = 75
RC_BROKEN = 2

# Ключ адреса СОБСТВЕННОГО фронта. Его пишет посев; нет его — значит окружение
# не от автономного стенда, и предмета у предполёта нет.
OWN_FRONT_KEY = "ownRestBaseUrl"
# Предъявитель, которым спрашивается годность. Бутстрап выбран потому, что его
# куёт посев ПЕРВЫМ и от него зависят остальные: истёк он — истекли все.
PROBE_CREDENTIAL_KEY = "jwtBootstrap"
# Путь, которым спрашивается годность: чтение, ничего не создающее. Мутация
# здесь оставила бы след от предполёта в данных прогона.
PROBE_PATH = "/iam/v1/accounts?pageSize=1"
# Текст отказа рубежа — часть контракта (`internal/presentedcred/reader.go`).
# Сверяется дословно: рубеж отвечает им и на подделку, и на отозванное, и на
# истёкшее, а «401» сам по себе приходит и от отсутствия предъявителя вовсе.
REFUSAL_TEXT = "credential is not accepted"


def load_env(path: pathlib.Path) -> dict[str, str]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    return {v["key"]: str(v.get("value", "")) for v in doc.get("values", [])}


def ask_front(base: str, token: str, ca: str | None, cert: str | None,
              key: str | None, timeout: float = 10.0) -> tuple[int, str]:
    """(код HTTP либо 0 при отсутствии ответа, тело либо причина)."""
    ctx = None
    if base.startswith("https://"):
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        if cert and key:
            ctx.load_cert_chain(cert, key)
        # Имя в сертификате стенда — `localhost`; сверка имени остаётся включённой.
    req = urllib.request.Request(base.rstrip("/") + PROBE_PATH,
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4096).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ssl.SSLError) as e:
        return 0, str(e)


def stamp_path(env_path: pathlib.Path) -> pathlib.Path:
    return env_path.with_name(env_path.name + ".consumed")


def read_stamp(path: pathlib.Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def preflight(env_path: pathlib.Path, stems: list[str], ca: str | None,
              cert: str | None, key: str | None,
              ask=ask_front) -> tuple[int, list[str]]:
    say: list[str] = []
    try:
        env = load_env(env_path)
    except (OSError, ValueError) as e:
        return RC_BROKEN, [f"ПРЕДПОЛЁТ НЕ ИСПОЛНЕН: окружение {env_path} не прочитано: {e}"]

    base = env.get(OWN_FRONT_KEY, "")
    token = env.get(PROBE_CREDENTIAL_KEY, "")
    run_id = env.get("runId", "")
    if not base or not token:
        say.append(
            f"предполёт: посева автономного стенда в окружении НЕТ "
            f"({OWN_FRONT_KEY}={'есть' if base else 'нет'}, "
            f"{PROBE_CREDENTIAL_KEY}={'есть' if token else 'нет'}) — "
            f"годность проверять нечем, и это НЕ «проверено и годно»")
        return RC_OK, say

    code, body = ask(base, token, ca, cert, key)
    if code == 0:
        say.append(
            f"УСЛОВИЕ НЕ СОЗДАНО: собственный фронт {base} не ответил ({body}). "
            f"Вердикта о дереве нет ни одного: коллекции не гонялись")
        return RC_UNMET, say
    if code == 401 and REFUSAL_TEXT in body:
        say.append(
            f"УСЛОВИЕ НЕ СОЗДАНО: предъявитель посева ОТВЕРГНУТ фронтом "
            f"({REFUSAL_TEXT}). Срок удостоверений посева — 15 минут; повтор "
            f"позже даёт СПЛОШНОЙ 401 тем же текстом, каким служба отвечает на "
            f"подделку, и это не дефект рубежа. Лекарство: пересеять — "
            f"`KANAME_HOOK_TOKEN=… python3 tests/authz-fixtures/seed_own_stand.py`")
        return RC_UNMET, say
    say.append(f"предполёт: предъявитель посева ПРИНЯТ фронтом {base} (код {code})")

    # ИЗРАСХОДОВАННЫЙ ПОСЕВ — ПРЕДУПРЕЖДЕНИЕ. Повтор читающей коллекции законен;
    # запрет на нём был бы порогом, срабатывающим на штатном состоянии.
    stamp = read_stamp(stamp_path(env_path))
    if run_id and stamp.get("runId") == run_id:
        before = stamp.get("stems") or []
        repeat = sorted(set(stems) & set(before))
        say.append(
            f"предполёт: ЭТОТ ПОСЕВ УЖЕ ИЗРАСХОДОВАН прогоном (runId {run_id}; "
            f"тогда гонялись: {', '.join(sorted(before)) or '—'}). Коллекции "
            f"создают ресурсы с именем от runId, поэтому повтор БЕЗ уборки "
            f"ловит ALREADY_EXISTS — это след прошлого прогона, а не дефект "
            f"уникальности. Повторно гоняются: "
            f"{', '.join(repeat) or 'ни одной из прежних'}. "
            f"Лекарство: пересеять")
    if run_id:
        merged = sorted(set(stamp.get("stems") or []) | set(stems))
        try:
            stamp_path(env_path).write_text(
                json.dumps({"runId": run_id, "stems": merged}), encoding="utf-8")
        except OSError as e:
            say.append(f"предполёт: отметку об израсходовании записать не удалось ({e}) — "
                       f"следующий повтор причину НЕ НАЗОВЁТ")
    return RC_OK, say


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--env", required=False,
                    default="environments/local.postman_environment.json")
    ap.add_argument("--stem", action="append", default=[])
    ap.add_argument("--ssl-extra-ca-certs", default=None)
    ap.add_argument("--ssl-client-cert", default=None)
    ap.add_argument("--ssl-client-key", default=None)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    rc, say = preflight(pathlib.Path(args.env), args.stem,
                        args.ssl_extra_ca_certs, args.ssl_client_cert,
                        args.ssl_client_key)
    for line in say:
        print(line, file=sys.stderr if rc == RC_UNMET else sys.stdout)
    return rc


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


def self_test() -> int:
    import tempfile

    print("seed_preflight: доказательство способности упасть")
    accepted = (200, '{"accounts":[]}')
    refused = (401, '{"code":16,"message":"credential is not accepted"}')
    silent = (0, "Connection refused")

    def world(tmp: pathlib.Path, name: str, values: dict[str, str]) -> pathlib.Path:
        p = tmp / f"{name}.json"
        p.write_text(json.dumps(
            {"values": [{"key": k, "value": v} for k, v in values.items()]}),
            encoding="utf-8")
        return p

    seeded = {OWN_FRONT_KEY: "https://localhost:9098",
              PROBE_CREDENTIAL_KEY: "eyJhbGciOiJSUzI1NiJ9.e30.x",
              "runId": "rid1"}

    with tempfile.TemporaryDirectory(prefix="preflight-proof-") as td:
        tmp = pathlib.Path(td)

        # Ось 1: предъявитель принят — код 0, и это сказано словами.
        p = world(tmp, "ok", seeded)
        rc, say = preflight(p, ["a"], None, None, None,
                            ask=lambda *a, **k: accepted)
        _c("принятый предъявитель — код 0", rc == RC_OK, f"код {rc}")
        _c("и это названо принятием", any("ПРИНЯТ" in s for s in say), f"{say}")

        # Ось 2: ОДИН факт против близнеца выше — фронт отвергает предъявителя.
        p = world(tmp, "refused", seeded)
        rc, say = preflight(p, ["a"], None, None, None,
                            ask=lambda *a, **k: refused)
        _c("отвергнутый предъявитель — код 75, а НЕ 0 и не 1", rc == RC_UNMET, f"код {rc}")
        _c("и названы срок посева и лекарство",
           any("15 минут" in s and "seed_own_stand.py" in s for s in say), f"{say}")

        # Ось 3: фронт молчит — тоже третий исход, но причина ДРУГАЯ.
        p = world(tmp, "silent", seeded)
        rc, say = preflight(p, ["a"], None, None, None,
                            ask=lambda *a, **k: silent)
        _c("молчащий фронт — код 75", rc == RC_UNMET, f"код {rc}")
        _c("и причина названа неответом, а не отказом рубежа",
           any("не ответил" in s for s in say)
           and not any(REFUSAL_TEXT in s for s in say), f"{say}")

        # Ось 4: ЗАКОННЫЙ БЛИЗНЕЦ — посева в окружении нет вовсе. Это не отказ, и
        # молчание здесь было бы неотличимо от «проверено и годно».
        p = world(tmp, "unseeded", {"baseUrl": "http://localhost:18080"})
        rc, say = preflight(p, ["a"], None, None, None,
                            ask=lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("фронт спрашивать было нечем")))
        _c("окружение без посева — код 0", rc == RC_OK, f"код {rc}")
        _c("и сказано, что проверять было НЕЧЕМ",
           any("посева автономного стенда в окружении НЕТ" in s for s in say), f"{say}")

        # Ось 5: ИЗРАСХОДОВАННЫЙ ПОСЕВ — предупреждение, а не отказ, и причина
        # ALREADY_EXISTS названа ДО первой коллекции.
        p = world(tmp, "twice", seeded)
        rc1, _ = preflight(p, ["iam-role"], None, None, None,
                           ask=lambda *a, **k: accepted)
        rc2, say2 = preflight(p, ["iam-role"], None, None, None,
                              ask=lambda *a, **k: accepted)
        _c("первый прогон на свежем посеве — молчит про израсходование",
           rc1 == RC_OK, f"код {rc1}")
        _c("второй прогон — код 0 (повтор чтения законен), а НЕ отказ",
           rc2 == RC_OK, f"код {rc2}")
        _c("и причина ALREADY_EXISTS названа ДО первой коллекции",
           any("ALREADY_EXISTS" in s and "ИЗРАСХОДОВАН" in s for s in say2), f"{say2}")
        _c("и названо, какая коллекция повторяется",
           any("iam-role" in s for s in say2), f"{say2}")

        # Ось 5б: ЗАКОННЫЙ БЛИЗНЕЦ — ПЕРЕСЕЯЛИ, и `runId` другой. Предупреждения
        # быть не должно: иначе оно срабатывало бы на штатном состоянии.
        p2 = world(tmp, "reseeded", {**seeded, "runId": "rid2"})
        # Отметка от прежнего посева лежит рядом со СВОИМ окружением, поэтому
        # берём отметку того же имени: мир отличается ОДНИМ фактом — runId.
        stamp_path(p2).write_text(json.dumps({"runId": "rid1", "stems": ["iam-role"]}),
                                  encoding="utf-8")
        rc3, say3 = preflight(p2, ["iam-role"], None, None, None,
                              ask=lambda *a, **k: accepted)
        _c("после пересева — код 0 и НИ СЛОВА про израсходование",
           rc3 == RC_OK and not any("ИЗРАСХОДОВАН" in s for s in say3), f"{rc3} {say3}")

        # Ось 6: окружения нет вовсе — это не вердикт о посеве, свой код.
        rc4, say4 = preflight(tmp / "нет-такого.json", ["a"], None, None, None,
                              ask=lambda *a, **k: accepted)
        _c("нечитаемое окружение — код 2, а НЕ 0 и не 75", rc4 == RC_BROKEN, f"код {rc4}")
        _c("и сказано, что предполёт НЕ ИСПОЛНЕН",
           any("НЕ ИСПОЛНЕН" in s for s in say4), f"{say4}")

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: отвергнутый предъявитель и молчащий фронт дают ТРЕТИЙ исход с "
          "разными причинами, отсутствие посева — не отказ, а израсходованный посев "
          "называет ALREADY_EXISTS до первой коллекции и молчит после пересева.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
