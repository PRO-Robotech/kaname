#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ЧИСТКА ОТЧЁТА ПРОГОНА ПЕРЕД ВЫКЛАДЫВАНИЕМ В АРТЕФАКТ ПУБЛИЧНОГО РЕПОЗИТОРИЯ.

ПРЕДМЕТ И ЦЕНА, КОТОРАЯ УЖЕ УПЛАЧЕНА. Артефакт прогона публичного репозитория
скачивается кем угодно по ссылке и живёт до истечения срока хранения. Машинный
отчёт newman несёт ОКРУЖЕНИЕ ПРОГОНА ЦЕЛИКОМ — то есть все удостоверения,
которые посев в него записал. Артефакт `own-front-newman-report` (53 104 байта)
нёс 51 вхождение строк вида JWT, включая четыре посеянных предъявителя; он удалён
руками, но производил его КОД, и правило публичных артефактов не про срок
годности удостоверения, а про то, что выложенное ОПУБЛИКОВАНО.

ВЫБОР: ЧИСТКА, А НЕ СВОДКА. Сводка (выложить только `summary.txt`) дешевле и
безопаснее by construction, но теряет РАЗБОР ПАДЕНИЙ — тело ответа, код, текст
утверждения, — а артефакт затем и нужен, что на красном по сводке не починить
ничего. Чистка дороже ровно тем, что обязана знать ВСЕ формы, в которых отчёт
несёт удостоверение. Поэтому она устроена не перечнем позиций, а ОБХОДОМ ВСЕГО
документа: неизвестная форма покрывается построением, а не списком.

ФОРМЫ ЗАМЕРЕНЫ, А НЕ ПРЕДПОЛОЖЕНЫ — ИХ СЕМЬ. Замер: синтетический прогон newman
6.2.2 с маркерами в каждой позиции (окружение · заголовок запроса · заголовок
ответа · тело запроса · параметр адреса · тело ответа · литерал в скрипте) и
обход отчёта с печатью пути каждого вхождения:

    newman run col.json -e env.json --reporters json \
      --reporter-json-export report.json
    # затем обход report.json с печатью json-пути каждого маркера

  1 `environment.values[].value` и `globals.values[].value` — окружение целиком:
    и то, что записал посев, и то, что дописали скрипты коллекции;
  2 `run.executions[].request.header[].value` — `Authorization`,
    `X-Kacho-Hook-Token`, `X-Api-Token` КАЖДОГО запроса;
  3 `run.executions[].response.header[].value` — `Set-Cookie` каждого ответа;
  4 `request.body.raw` — ТРИ позиции на один запрос
    (`collection.item[]`, `run.executions[].item`, `run.executions[].request`);
  5 `request.url.query[].value` и `url.raw` — удостоверение в параметре адреса;
  6 `run.executions[].response.stream` — ТЕЛО ОТВЕТА БАЙТОВЫМ МАССИВОМ
    (`{"type":"Buffer","data":[123,34,…]}`). Это самая опасная форма: ТЕКСТОВЫЙ
    ГРЕП ЕЁ НЕ ВИДИТ ВООБЩЕ. Замер «51 вхождение» получен текстовым предикатом,
    значит он НЕ СЧИТАЛ тела ответов — утечка была шире названного числа;
  7 `collection.item[].event[].script.exec[]` — литерал, вписанный в скрипт
    коллекции (и его копия в `run.executions[].item`).

ЧТО ОСТАЁТСЯ. Имена ключей, имена заголовков, пути запросов, коды, тексты
утверждений, числа и времена — то есть РАЗБОР ПАДЕНИЯ. Чистка, съедающая имя
ключа, неотличима от удаления файла, и проба требует обратного прямо.

ИСХОДЫ:
    0  — вычищено, и ОСТАТОК ПРОВЕРЕН: повторный обход выхода не нашёл ничего;
    1  — остаток найден (чистка неполна) либо обход пуст: «ноль находок» при
         нулевом прочитанном неотличимо от чистого файла.

ОСТАТОК НАЗЫВАЕТСЯ ПУТЁМ, А НЕ ЗНАЧЕНИЕМ. Отказ, печатающий недочищенное
удостоверение, публикует его в журнал прогона — то есть туда же, откуда его
убирали.

САМОПРОВЕРКА — `--self-test`: по одной оси на каждую из семи форм, законный
близнец рядом (идентификатор, адрес, текст утверждения обязаны выжить), пустой
обход обязан дать отказ.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# ── ПРЕДИКАТ ФОРМЫ ЗНАЧЕНИЯ ──────────────────────────────────────────────────
#
# Два независимых предиката, объединённых: по ФОРМЕ значения и по ИМЕНИ ключа.
# Ни один не покрывает другого. Форма ловит удостоверение в позиции без имени
# (тело ответа, текст утверждения); имя ловит секрет, у которого формы нет вовсе
# — общий секрет хука `stand-hook-secret-0123456789` не отличим от слова.
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")
PEM_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                    re.DOTALL)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")

# Имя ключа/заголовка/параметра, чьё значение есть удостоверение. Регистр не
# значим: заголовки приходят и `Authorization`, и `authorization`.
SECRET_NAME_RE = re.compile(
    r"(?i)(jwt|token|secret|password|passwd|apikey|api[-_]?key|assertion|"
    r"credential|bearer|authorization|privatekey|private[-_]?key|keypem|"
    r"key[-_]?pem|cookie|signature|clientsecret)")

REDACTED = "«ВЫРЕЗАНО ПЕРЕД ПУБЛИКАЦИЕЙ»"


def shaped_credential(text: str) -> str | None:
    """Форма значения выдаёт удостоверение? Возвращает имя формы или None."""
    if JWT_RE.search(text):
        return "вид JWT"
    if PEM_RE.search(text):
        return "приватный ключ PEM"
    if BEARER_RE.search(text):
        return "предъявление Bearer"
    return None


def scrub_text(text: str) -> tuple[str, int]:
    """Вырезать удостоверения ИЗ ТЕКСТА, оставив остальное. (текст, сколько)."""
    n = 0

    def sub(pattern: "re.Pattern[str]", src: str) -> str:
        nonlocal n

        def one(m: "re.Match[str]") -> str:
            nonlocal n
            n += 1
            return REDACTED
        return pattern.sub(one, src)

    out = sub(PEM_RE, text)
    out = sub(JWT_RE, out)
    out = sub(BEARER_RE, out)
    return out, n


class Census:
    """Перепись обхода. Печатается ВСЕГДА: «ноль вырезанного» обязано быть
    отличимо от «ноль прочитанного»."""

    def __init__(self) -> None:
        self.nodes = 0
        self.strings = 0
        self.buffers = 0
        self.redacted_by_name = 0
        self.redacted_by_shape = 0
        self.files = 0

    @property
    def redacted(self) -> int:
        return self.redacted_by_name + self.redacted_by_shape


def _walk(node: object, key_hint: str | None, c: Census) -> object:
    """ПЕРВАЯ РЕДАКЦИЯ: чистится ТОЛЬКО окружение прогона (форма 1).

    Написано так намеренно и ненадолго: перечень позиций — ровно тот способ,
    которым чистка расходится с newman молча. Самопроверка ниже требует все семь
    замеренных форм, значит эта редакция обязана быть КРАСНОЙ по шести из семи.
    """
    c.nodes += 1
    if isinstance(node, dict):
        out: dict = {}
        for k, v in node.items():
            if k == "values" and isinstance(v, list):
                vals = []
                for item in v:
                    c.nodes += 1
                    if isinstance(item, dict) and isinstance(item.get("key"), str):
                        c.strings += 1
                        if SECRET_NAME_RE.search(item["key"]) and item.get("value"):
                            c.redacted_by_name += 1
                            item = dict(item, value=REDACTED)
                    vals.append(item)
                out[k] = vals
            else:
                out[k] = _walk(v, None, c)
        return out
    if isinstance(node, list):
        return [_walk(v, key_hint, c) for v in node]
    if isinstance(node, str):
        c.strings += 1
    return node


def redact_document(doc: object, c: Census) -> object:
    return _walk(doc, None, c)


# ── ПОВТОРНЫЙ ОБХОД ВЫХОДА: ОСТАТОК ИЩЕТСЯ, А НЕ ОБЕЩАЕТСЯ ──────────────────


def residue(node: object, path: str, found: list[str]) -> None:
    """Пути (НЕ значения!) мест, где удостоверение осталось."""
    if isinstance(node, dict):
        if node.get("type") == "Buffer" and isinstance(node.get("data"), list):
            try:
                raw = bytes(int(b) & 0xFF for b in node["data"]).decode("utf-8", "replace")
            except (TypeError, ValueError):
                raw = ""
            form = shaped_credential(raw)
            if form:
                found.append(f"{path}.stream[байтовый массив] — {form}")
            return
        for k, v in node.items():
            residue(v, f"{path}.{k}", found)
        return
    if isinstance(node, list):
        for i, v in enumerate(node):
            residue(v, f"{path}[{i}]", found)
        return
    if isinstance(node, str):
        form = shaped_credential(node)
        if form:
            found.append(f"{path} — {form} (длина {len(node)})")


# ── ФАЙЛЫ ────────────────────────────────────────────────────────────────────


def process(src: pathlib.Path, dst: pathlib.Path, c: Census) -> list[str]:
    """Вычистить один файл. Возвращает остаток (пути), найденный В ВЫХОДЕ."""
    c.files += 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.suffix == ".json":
        doc = json.loads(src.read_text(encoding="utf-8"))
        clean = redact_document(doc, c)
        dst.write_text(json.dumps(clean, ensure_ascii=False, indent=1), encoding="utf-8")
        found: list[str] = []
        residue(clean, src.name, found)
        return found
    # Текстовые выходы прогонщика (`.cli`, `summary.txt`, `coverage.txt`): у них
    # структуры нет, поэтому чистится текст. Греп по ним и был бы достаточен,
    # если бы у отчёта не было формы 6.
    raw = src.read_text(encoding="utf-8", errors="replace")
    clean, n = scrub_text(raw)
    c.strings += 1
    c.redacted_by_shape += n
    dst.write_text(clean, encoding="utf-8")
    found = []
    form = shaped_credential(clean)
    if form:
        found.append(f"{src.name} — {form}")
    return found


def run(src_dir: pathlib.Path, dst_dir: pathlib.Path) -> int:
    if not src_dir.is_dir():
        print(f"ОТКАЗ: {src_dir} не каталог — чистить нечего, и это НЕ «чисто»",
              file=sys.stderr)
        return 1
    files = sorted(p for p in src_dir.iterdir()
                   if p.is_file() and p.suffix in (".json", ".cli", ".txt", ".rc"))
    c = Census()
    leftovers: list[str] = []
    for f in files:
        leftovers += process(f, dst_dir / f.name, c)

    print("===== чистка отчёта прогона перед публикацией =====")
    print(f"файлов прочитано:        {c.files}")
    print(f"узлов обойдено:          {c.nodes}")
    print(f"строк осмотрено:         {c.strings}")
    print(f"байтовых массивов:       {c.buffers}")
    print(f"вырезано по имени ключа: {c.redacted_by_name}")
    print(f"вырезано по форме:       {c.redacted_by_shape}")
    print(f"ВСЕГО вырезано:          {c.redacted}")
    print(f"выход:                   {dst_dir}")

    if not c.files or not c.strings:
        print("ОТКАЗ: обход пуст — прочитано ноль строк. «Ничего не нашлось» здесь "
              "означает «ничего не читалось», и выкладывать вывод нельзя.",
              file=sys.stderr)
        return 1
    if leftovers:
        print(f"ОТКАЗ: в ВЫХОДЕ осталось {len(leftovers)} удостоверени(й) — "
              f"чистка неполна, выкладывать нельзя. Ниже ПУТИ, не значения: "
              f"печатать недочищенное значило бы опубликовать его в журнал.",
              file=sys.stderr)
        for p in leftovers[:40]:
            print(f"  · {p}", file=sys.stderr)
        return 1
    print("ЧИСТО: повторный обход выхода не нашёл ни одного удостоверения "
          "(включая тела ответов в байтовой форме).")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


# Маркеры вида JWT: настоящая форма, а не слово. Первая часть обязана начинаться
# на `eyJ` — это base64url от `{"`, то есть форма, а не совпадение.
def _jwt(mark: str) -> str:
    return f"eyJhbGciOiJSUzI1NiJ9.{mark}xxxxxxxx.sigsigsig"


def _report(mark_env: str, mark_reqh: str, mark_resh: str, mark_body: str,
            mark_query: str, mark_stream: str, mark_script: str) -> dict:
    """Отчёт формы newman 6.2.2 — позиции взяты ЗАМЕРОМ (см. шапку файла)."""
    return {
        "collection": {"item": [{
            "name": "probe",
            "event": [{"listen": "prerequest", "script": {"exec": [
                f"pm.environment.set('minted', '{_jwt(mark_script)}');"]}}],
            "request": {"body": {"mode": "raw", "raw": '{"assertion":"' + _jwt(mark_body) + '"}'},
                        "url": {"query": [{"key": "access_token", "value": _jwt(mark_query)}]}},
        }]},
        "environment": {"values": [
            {"key": "ownRestBaseUrl", "value": "https://localhost:9098"},
            {"key": "jwtAccountAdminA", "value": _jwt(mark_env)},
            {"key": "apiTokenA", "value": "kt_plain_secret_value_no_shape"},
            {"key": "accountAId", "value": "acc0123456789abcdefgh"},
        ]},
        "globals": {"values": []},
        "run": {
            "stats": {"assertions": {"total": 2, "failed": 1}},
            "failures": [{"error": {"test": "иам возвращает 200",
                                    "message": "expected 200 got 401"}}],
            "executions": [{
                "item": {"name": "probe", "event": [{"listen": "prerequest", "script": {
                    "exec": [f"pm.environment.set('minted', '{_jwt(mark_script)}');"]}}]},
                "request": {
                    "method": "GET",
                    "header": [{"key": "Authorization", "value": f"Bearer {_jwt(mark_reqh)}"},
                               {"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"assertion":"' + _jwt(mark_body) + '"}'},
                    "url": {"raw": f"https://localhost:9098/iam/token?access_token={_jwt(mark_query)}",
                            "path": ["iam", "token"],
                            "query": [{"key": "access_token", "value": _jwt(mark_query)}]},
                },
                "response": {
                    "code": 401,
                    "status": "Unauthorized",
                    "responseTime": 12,
                    "header": [{"key": "Set-Cookie", "value": f"session={_jwt(mark_resh)}; Path=/"},
                               {"key": "Content-Type", "value": "application/json"}],
                    "stream": {"type": "Buffer", "data": list(
                        ('{"accessToken":"' + _jwt(mark_stream) + '"}').encode("utf-8"))},
                },
                "assertions": [{"assertion": "иам возвращает 200", "error": None}],
            }],
        },
    }


def self_test() -> int:
    import tempfile
    print("redact-newman-report: доказательство способности упасть")
    marks = ("ENVV", "REQH", "RESH", "BODY", "QUER", "STRM", "SCRP")
    doc = _report(*marks)

    with tempfile.TemporaryDirectory(prefix="redact-proof-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        (src / "kaname-own-rest-front.json").write_text(
            json.dumps(doc), encoding="utf-8")
        (src / "kaname-own-rest-front.cli").write_text(
            "GET /iam/v1/accounts\n"
            f"  Authorization: Bearer {_jwt('CLIT')}\n"
            "  1 assertion failed\n", encoding="utf-8")
        (src / "summary.txt").write_text(
            "kaname-own-rest-front  requests=23 assertions=58 failed=0\n",
            encoding="utf-8")
        rc = run(src, dst)
        _c("чистка прошла и остатка не нашла (код 0)", rc == 0)

        text = (dst / "kaname-own-rest-front.json").read_text(encoding="utf-8")
        out = json.loads(text)

        # ── ОДНА ОСЬ НА КАЖДУЮ ИЗ СЕМИ ЗАМЕРЕННЫХ ФОРМ ───────────────────────
        forms = (
            ("1 окружение (`environment.values[].value`)", "ENVV"),
            ("2 заголовок запроса (`request.header[].value`)", "REQH"),
            ("3 заголовок ответа (`response.header[].value`)", "RESH"),
            ("4 тело запроса (`request.body.raw`, три позиции)", "BODY"),
            ("5 параметр адреса (`url.query[].value` и `url.raw`)", "QUER"),
            ("6 тело ответа БАЙТОВЫМ МАССИВОМ (`response.stream`)", "STRM"),
            ("7 литерал в скрипте коллекции (`event[].script.exec[]`)", "SCRP"),
        )
        for label, mark in forms:
            _c(f"форма {label}: удостоверения в выходе НЕТ",
               mark not in text, f"маркер {mark} остался в выходе")

        # Форма 6 отдельно: она невидима ТЕКСТОВОМУ предикату, значит проверять
        # её текстом выхода недостаточно — надо декодировать массив.
        stream = out["run"]["executions"][0]["response"]["stream"]
        decoded = bytes(stream["data"]).decode("utf-8", "replace") \
            if isinstance(stream, dict) and stream.get("type") == "Buffer" else str(stream)
        _c("форма 6: и в ДЕКОДИРОВАННОМ массиве его нет",
           "STRM" not in decoded and shaped_credential(decoded) is None, decoded[:120])

        # ── ИМЯ КЛЮЧА ОБЯЗАНО ОСТАТЬСЯ: иначе чистка = удаление файла ────────
        names = [v["key"] for v in out["environment"]["values"]]
        _c("имена ключей окружения остались все четыре",
           names == ["ownRestBaseUrl", "jwtAccountAdminA", "apiTokenA", "accountAId"],
           f"{names}")
        hdr = [h["key"] for h in out["run"]["executions"][0]["request"]["header"]]
        _c("имена заголовков запроса остались", hdr == ["Authorization", "Content-Type"], f"{hdr}")

        # ── СЕКРЕТ БЕЗ ФОРМЫ — ловится ПО ИМЕНИ, а не по виду значения ───────
        api = next(v for v in out["environment"]["values"] if v["key"] == "apiTokenA")
        _c("секрет без формы вырезан ПО ИМЕНИ ключа",
           "plain_secret_value" not in json.dumps(api, ensure_ascii=False), f"{api}")

        # ── ЗАКОННЫЕ БЛИЗНЕЦЫ: разбор падения обязан ВЫЖИТЬ ─────────────────
        acc = next(v for v in out["environment"]["values"] if v["key"] == "accountAId")
        _c("идентификатор ресурса выжил (он не удостоверение)",
           acc["value"] == "acc0123456789abcdefgh", f"{acc}")
        _c("адрес фронта выжил",
           out["environment"]["values"][0]["value"] == "https://localhost:9098")
        _c("код и текст ответа выжили",
           out["run"]["executions"][0]["response"]["code"] == 401
           and out["run"]["executions"][0]["response"]["status"] == "Unauthorized")
        _c("текст упавшего утверждения выжил",
           out["run"]["failures"][0]["error"]["message"] == "expected 200 got 401")
        _c("путь запроса выжил",
           out["run"]["executions"][0]["request"]["url"]["path"] == ["iam", "token"])
        _c("числа прогона выжили",
           out["run"]["stats"]["assertions"] == {"total": 2, "failed": 1})

        # ── ТЕКСТОВЫЙ ВЫХОД ПРОГОНЩИКА ТОЖЕ ЧИСТИТСЯ ────────────────────────
        cli = (dst / "kaname-own-rest-front.cli").read_text(encoding="utf-8")
        _c("в текстовом выводе прогонщика удостоверения нет", "CLIT" not in cli, cli)
        _c("а строка про упавшее утверждение в нём осталась",
           "1 assertion failed" in cli, cli)

    # ── ОСЬ: ОСТАТОК ЛОВИТСЯ, А НЕ ОБЕЩАЕТСЯ ────────────────────────────────
    #
    # Инъекция в сам предикат: если форма значения предикату неизвестна, отказ
    # обязан наступить на ПОВТОРНОМ обходе выхода, а не быть объявлен зелёным.
    with tempfile.TemporaryDirectory(prefix="redact-residue-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        (src / "r.json").write_text(json.dumps(
            {"run": {"executions": [{"leftover": _jwt("LEFT")}]}}), encoding="utf-8")
        saved = globals()["JWT_RE"]
        globals()["JWT_RE"] = re.compile(r"\bZZZ_NEVER_MATCHES_ZZZ\b")
        try:
            rc = run(src, dst)
        finally:
            globals()["JWT_RE"] = saved
        _c("предикат ослеплён — отказ по ОСТАТКУ, а не зелёное", rc == 1)

    # ── ОСЬ: ПУСТОЙ ОБХОД — ОТКАЗ, А НЕ «ЧИСТО» ────────────────────────────
    with tempfile.TemporaryDirectory(prefix="redact-empty-") as td:
        tmp = pathlib.Path(td)
        src, dst = tmp / "out", tmp / "out-public"
        src.mkdir()
        rc = run(src, dst)
        _c("пустой каталог — код 1, а НЕ «чисто»", rc == 1)
        rc = run(tmp / "нет-такого", dst)
        _c("каталога нет — код 1, а НЕ «чисто»", rc == 1)

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: все семь замеренных форм вычищены (включая байтовый массив "
          "тела ответа, невидимый текстовому грепу), имена ключей и разбор падения "
          "выжили, ослеплённый предикат отвергается по остатку, пустой обход — отказ.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--in", dest="src", default="tests/newman/out")
    ap.add_argument("--out", dest="dst", default="tests/newman/out-public")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.src), pathlib.Path(args.dst))


if __name__ == "__main__":
    sys.exit(main())
