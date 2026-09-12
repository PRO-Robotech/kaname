#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ДОЛГ СКВОЗНОГО НАБОРА, НАЗВАННЫЙ ЧИСЛОМ: что на автономном стенде НЕ гоняется.

ПРЕДМЕТ. Автономный стенд поднимает службу и её базу без края платформы, её
сервисов и достижимого поставщика удостоверений. Сквозной набор при этом
адресуется почти целиком к КРАЮ, и край — не транспорт: он производит проверяемые
свойства. Значит прогон здесь покрывает НЕ ВСЁ, и разница обязана быть напечатана
ЧИСЛОМ по каждой позиции — иначе зелёный шаг читается шире сделанного, а это брак
независимо от того, сколько сделано.

РАЗРЕЗ ВЫВОДИТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ ВТОРЫМ СПИСКОМ. Поверхность коллекции читается
из неё самой — по переменным адреса, которые её шаги действительно используют, — а
препятствия из того, какие ключи окружения она читает и пусты ли они в шаблоне.
Выписанный перечень разошёлся бы с деревом молча и разошёлся бы в одну сторону:
новая коллекция в него просто не попала бы.

ПЕЧАТАЮТСЯ ОБЕ ВЕЛИЧИНЫ. «Гоняется здесь N» без «не гоняется M» скрывает ровно тот
случай, ради которого перепись и делается.

ИСХОДЫ:
    0  — перепись напечатана (долг — не отказ: он именно объявляется);
    1  — перепись беспредметна: коллекций либо шаблона окружения нет, разбор дал
         ноль. «Ноль находок» здесь означало бы «ноль прочитанного».

САМОПРОВЕРКА — `--self-test`: синтетическое дерево, где коллекция БЕЗ препятствий
обязана попасть в «гоняется», с препятствием — в «не гоняется», а пустой обход
обязан дать отказ.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

VAR_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
GET_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")
CFG_RE = re.compile(r"pm\.environment\.get\(\s*['\"]([A-Za-z_][A-Za-z0-9_]*BaseUrl)['\"]")

# Переменные адреса КРАЯ ПЛАТФОРМЫ. Их производитель — чужой стенд; наведение их
# на собственный фронт службы запрещено гейтом набора, и запрет верен: те же
# кейсы, тот же зелёный отчёт, проверено РАЗНОЕ.
EDGE_VARS = frozenset({"baseUrl", "internalBaseUrl", "externalBaseUrl"})
# Переменные адреса СОБСТВЕННЫХ фронтов службы — единственная поверхность,
# которую автономный стенд производит сам.
OWN_VARS = frozenset({"ownRestBaseUrl", "ownInternalRestBaseUrl"})
# Поверхности, которые служба поднимает, но чей ОТВЕТ зависит от недостижимого
# соседа: зеркало набора ключей и полоса docker-токена.
NEIGHBOUR_VARS = frozenset({"iamJwksBaseUrl", "iamRegistryTokenBaseUrl",
                            "providerPublicBaseUrl", "registryDataPlaneBaseUrl"})
# Предъявитель, которого машинный посев не производит: он требует ЧЕЛОВЕКА.
CEREMONY_PREFIXES = ("jwtHuman", "ceremony")


def collections(newman: pathlib.Path) -> list[pathlib.Path]:
    return sorted((newman / "collections").glob("*.postman_collection.json"))


def template_keys(newman: pathlib.Path) -> tuple[set[str], set[str]]:
    """(все ключи шаблона, ключи с ПУСТЫМ значением)."""
    path = newman / "environments" / "local.postman_environment.template.json"
    if not path.is_file():
        return set(), set()
    doc = json.loads(path.read_text(encoding="utf-8"))
    allk, empty = set(), set()
    for v in doc.get("values", []):
        allk.add(v["key"])
        if not str(v.get("value", "")):
            empty.add(v["key"])
    return allk, empty


def used_keys(text: str) -> set[str]:
    return set(VAR_RE.findall(text)) | set(GET_RE.findall(text))


def surface_of(text: str, keys: set[str]) -> str:
    """Поверхность коллекции: чей производитель отвечает на её запросы."""
    addressed = set(CFG_RE.findall(text)) | (keys & (EDGE_VARS | OWN_VARS | NEIGHBOUR_VARS))
    if addressed & OWN_VARS:
        return "служба (собственный REST-фронт)"
    if addressed & EDGE_VARS or "baseUrl" in keys:
        return "край платформы"
    if addressed & NEIGHBOUR_VARS:
        return "служба + недостижимый сосед"
    return "не определена"


def blockers(surface: str, keys: set[str], empty: set[str],
             seed_present: bool) -> list[str]:
    out = []
    if surface == "край платформы":
        out.append("нужен край платформы (его производитель — чужой стенд)")
    need = sorted(k for k in keys if k in empty and k != "runId")
    ceremony = [k for k in need if k.startswith(CEREMONY_PREFIXES)]
    machine = [k for k in need if k not in ceremony]
    if ceremony:
        out.append(f"нужен ЧЕЛОВЕЧЕСКИЙ предъявитель ({len(ceremony)}: "
                   f"{', '.join(ceremony[:3])}{'…' if len(ceremony) > 3 else ''})")
    if machine and not seed_present:
        out.append(f"нужен машинный посев ({len(machine)} удостоверени(й)/id: "
                   f"{', '.join(machine[:3])}{'…' if len(machine) > 3 else ''})")
    return out


def run(newman: pathlib.Path) -> int:
    cols = collections(newman)
    allk, empty = template_keys(newman)
    if not cols:
        print(f"ОТКАЗ: в {newman/'collections'} не прочитано ни одной коллекции — "
              f"перепись беспредметна, а не пуста.", file=sys.stderr)
        return 1
    if not allk:
        print(f"ОТКАЗ: шаблона окружения нет — препятствия вывести не из чего.",
              file=sys.stderr)
        return 1

    seed_dir = newman.parent / "authz-fixtures"
    seed_scripts = sorted(p for p in seed_dir.iterdir()
                          if p.is_file() and p.suffix in (".sh", ".py")
                          and p.name != "principal_pairings.py") if seed_dir.is_dir() else []
    seed_present = bool(seed_scripts)

    runnable, blocked = [], []
    by_surface: dict[str, int] = {}
    by_blocker: dict[str, int] = {}
    for col in cols:
        text = col.read_text(encoding="utf-8")
        keys = used_keys(text)
        surface = surface_of(text, keys)
        by_surface[surface] = by_surface.get(surface, 0) + 1
        # Имя коллекции — БЕЗ приставки формата: `Path.stem` снимает только `.json`,
        # оставляя `.postman_collection`, и перепись читалась бы шумом.
        stem = col.name[: -len(".postman_collection.json")]
        bl = blockers(surface, keys, empty, seed_present)
        if bl:
            blocked.append((stem, surface, bl))
            for b in bl:
                head = b.split(" (")[0]
                by_blocker[head] = by_blocker.get(head, 0) + 1
        else:
            runnable.append((stem, surface))

    print("===== сквозной набор на АВТОНОМНОМ стенде: что гоняется, а что нет =====")
    print(f"коллекций в дереве: {len(cols)}")
    print(f"  гоняется здесь:    {len(runnable)}")
    print(f"  НЕ гоняется здесь: {len(blocked)}")
    print()
    print("по поверхности (чей производитель отвечает):")
    for s, n in sorted(by_surface.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {s}")
    print()
    print("по препятствию (одна коллекция может иметь несколько):")
    for b, n in sorted(by_blocker.items(), key=lambda kv: -kv[1]):
        print(f"  {n:3d}  {b}")
    print()
    print(f"посев общих фикстур: {'есть' if seed_present else 'ОТСУТСТВУЕТ'} "
          f"({len(seed_scripts)} скрипт(ов) в {seed_dir.name}/)")
    print()
    if runnable:
        print("ГОНЯЕТСЯ ЗДЕСЬ:")
        for stem, surface in runnable:
            print(f"  · {stem} — {surface}")
        print()
    print("НЕ ГОНЯЕТСЯ ЗДЕСЬ (по каждой позиции — причина):")
    for stem, surface, bl in blocked:
        print(f"  · {stem} [{surface}]")
        for b in bl:
            print(f"      — {b}")
    print()
    print("ЧТО ЭТОТ ДОЛГ ЗНАЧИТ, СКАЗАНО ПРЯМО:")
    print("  · прогон автономного стенда проверяет свойства, чей производитель —")
    print("    САМА служба (её фронты, их непроницаемость, рубеж, разбор доступа,")
    print("    честный отказ при недостижимом соседе). Список — stand-assert.py;")
    print("  · свойства КРАЯ платформы здесь не проверяются вовсе и остаются")
    print("    предметом её конвейера;")
    print("  · полоса личности `own` (внешнего поставщика нет ВООБЩЕ) сегодня")
    print("    НЕ ПОДНИМАЕТСЯ: страж посадки отказывает и называет причины. Стенд")
    print("    идёт на полосе `external` с ОБЪЯВЛЕННЫМ, но недостижимым")
    print("    поставщиком — см. врезку в .github/scripts/stand-own.sh.")
    return 0


# ─────────────────────────── доказательство инъекцией ────────────────────────

_F: list[str] = []


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if not ok:
        _F.append(label)
        if detail:
            print(f"       {detail}")


def _mk(tmp: pathlib.Path, cols: dict[str, str], tmpl: dict[str, str]) -> pathlib.Path:
    newman = tmp / "tests" / "newman"
    (newman / "collections").mkdir(parents=True, exist_ok=True)
    (newman / "environments").mkdir(parents=True, exist_ok=True)
    for name, body in cols.items():
        (newman / "collections" / f"{name}.postman_collection.json").write_text(
            body, encoding="utf-8")
    (newman / "environments" / "local.postman_environment.template.json").write_text(
        json.dumps({"values": [{"key": k, "value": v} for k, v in tmpl.items()]}),
        encoding="utf-8")
    return newman


def self_test() -> int:
    import io
    import contextlib
    import tempfile
    print("newman-suite-debt: доказательство способности упасть")
    with tempfile.TemporaryDirectory(prefix="debt-proof-") as td:
        tmp = pathlib.Path(td)

        # Ось 1: пустой обход — ОТКАЗ, а не «долга нет».
        empty = _mk(tmp / "empty", {}, {"baseUrl": "http://x"})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = run(empty)
        _c("ноль коллекций — код 1, а НЕ 0", rc == 1, buf.getvalue()[-200:])
        _c("и отказ называет беспредметность", "беспредметна" in buf.getvalue())

        # Ось 2: коллекция БЕЗ препятствий обязана попасть в «гоняется».
        own = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}}}]}')
        t2 = _mk(tmp / "own", {"own-only": own},
                 {"ownRestBaseUrl": "https://localhost:9098", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(t2)
        out = buf.getvalue()
        _c("коллекция без препятствий — код 0", rc == 0)
        _c("она в «гоняется здесь»", "гоняется здесь:    1" in out, out[:400])
        _c("и её поверхность названа службой", "собственный REST-фронт" in out)

        # Ось 3: ЗАКОННЫЙ БЛИЗНЕЦ — та же коллекция, но читает пустой ключ посева.
        own2 = ('{"item":[{"name":"s","request":{"url":{"raw":"{{ownRestBaseUrl}}/x"}},'
                '"event":[{"listen":"test","script":{"exec":['
                '"pm.environment.get(\'jwtAccountAdminA\')"]}}]}]}')
        t3 = _mk(tmp / "own-seeded", {"own-seeded": own2},
                 {"ownRestBaseUrl": "https://localhost:9098", "jwtAccountAdminA": "",
                  "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t3)
        out = buf.getvalue()
        _c("та же коллекция с пустым ключом посева — в «НЕ гоняется»",
           "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа посевом", "машинный посев" in out, out[:600])

        # Ось 4: коллекция края попадает в «не гоняется» с причиной про край.
        edge = ('{"item":[{"name":"s","request":{"url":{"raw":"{{baseUrl}}/iam/v1/x"}}}]}')
        t4 = _mk(tmp / "edge", {"edge-only": edge}, {"baseUrl": "http://x", "runId": ""})
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(t4)
        out = buf.getvalue()
        _c("коллекция края — в «НЕ гоняется»", "НЕ гоняется здесь: 1" in out, out[:400])
        _c("и причина названа краем", "нужен край платформы" in out)

        # Ось 5: ОБЕ величины печатаются всегда — и когда вторая ноль.
        _c("печатаются обе величины, а не только одна",
           "гоняется здесь:" in out and "НЕ гоняется здесь:" in out)

    print()
    if _F:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_F)} — {', '.join(_F)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: пустой обход отвергается, поверхность и препятствия выводятся из "
          "коллекции, а законный близнец (тот же адрес, но пустой ключ посева) уезжает "
          "в другую половину переписи.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--newman", default=str(ROOT / "tests" / "newman"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return run(pathlib.Path(args.newman))


if __name__ == "__main__":
    sys.exit(main())
