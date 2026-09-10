#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Перепись посевной идентичности — предикат §0.1 приёмки
`seed-identity-names-its-own-service.md`.

ЭТО ПЕРЕПИСЬ, А НЕ ГЕЙТ. Он ничего не роняет и никого не судит: он печатает
числа, на которые ссылается §0.2, и объём осмотренного, которым «ноль находок»
отличается от «ноль прочитанного». Единственный ненулевой исход — ОТКАЗ по
беспредметности (код 2), когда мерить оказалось нечего.

ЕДИНИЦА СЧЁТА — вхождение литерала посевной идентичности в ОТСЛЕЖИВАЕМОМ файле,
счёт от длинного написания к короткому (`kacho-system.admin` не пересчитывается
вторично как `kacho-system`), с адъюдикацией по КОНТЕКСТУ СТРОКИ.

ПОЧЕМУ ОН ЛЕЖИТ ЗДЕСЬ, А НЕ В `services/iam/scripts/`. Замер одним фактом:
заготовка из шести литералов, положенная под `services/iam/scripts/`, двигает
ЧУЖУЮ ведомость остатка (полоса «имя объекта»: найдено 638 → 644, файлов
226 → 227, гейт краснеет); она же под каталогом приёмок не двигает ничего.
Различие одно — путь. Литералы поиска неотличимы от посева по форме, а этот
файл несёт их больше заготовки, то есть сдвиг был бы только крупнее. Под каталогом
приёмок он изъят по приставке (`kanamenameresidue.go`, `kanameApprovedAcceptanceDir`)
и ведомость не двигает. Изъятие здесь ЗАКОННО и по существу, а не по удобству:
дерево уже признаёт этот довод для проб — «имя названо как предмет проверки»
(`kanamemigratorshowcase.go`). Ведомость чужая (`#2553`), и эта приёмка её
не правит.

ПОРЯДОК ВЁДЕР НЕСУЩИЙ — вхождение попадает в ПЕРВОЕ подошедшее, и порядок
объявлен здесь, потому что он и есть спорная часть:

  1. граница  — путь под каталогом приёмок: вердикт приёмки привязан к
                отпечатку, поэтому её текст объявлен границей, а не остатком.
                Граница стоит ПЕРВОЙ, и это замер, а не вкус: на ревизии замера
                оба порядка дают дословно одно (зонт 31·16, граница 40·6), а
                после посадки приёмки только этот оставляет ведро зонта
                неподвижным — её собственная проза о личности зонта есть текст
                приёмки, а не остаток имени;
  2. зонт     — литерал принадлежит личности, которую выдаёт ЗОНТ платформы;
                предмет службы он не называет ни в одном контексте (§0.4);
  3. ns       — строка несёт признак пространства имён кластера; написание
                `kacho-system` бывает и аккаунтом, и пространством имён, и
                РАЗДЕЛЯЕТ их только контекст строки. Предмет `#2553`;
  4. манифест — файл манифеста модуля, строка не комментарий: цитата имени
                аккаунта чужим продуктом — посев, а не проза;
  5. поверхн. — путь под поверхностью Kaname (перечень читается ИЗ ДЕРЕВА);
  6. прочее   — остальное: имя предмета вне поверхности службы.

ЧЕГО ОН НЕ ДЕЛАЕТ. Он не сводит свою единицу с единицей держателя ведомости
остатка: тот считает вхождения сегмента `kacho` по полосам ПОСЛЕ границ и
после прощения, здесь считаются литералы целиком. Расхождение названо в §0.1
и снимается П4, а не этим файлом.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# Литералы, от ДЛИННОГО к короткому. Порядок несущий: он и есть правило
# «длинное написание не пересчитывается вторично как короткое».
#
# `kacho-bootstrap-grant` в перечень НЕ входит намеренно: единственное его
# вхождение — проза соседней приёмки о том, что имя УШЛО. Оно называет
# снятое, а не посеянное.
LITERALS = (
    "kacho-bootstrap-operator",
    "kacho-bootstrap-seeder",
    "kacho-bootstrap-admin",
    "kacho-bootstrap-soc",
    "kacho-system.viewer",
    "kacho-system.admin",
    "kacho-system",
    "kacho-root",
)

# Личности, которые выдаёт ЗОНТ платформы, а не служба (§0.4).
UMBRELLA = frozenset({"kacho-bootstrap-operator", "kacho-bootstrap-seeder"})

# Признаки пространства имён кластера в СТРОКЕ (§0.4, пограничный случай).
NS_MARKS = ("/ns/", "namespace", ".svc")

ACCEPTANCE_DIR = "services/iam/docs/engineering/acceptance/"

# Откуда читается поверхность Kaname. Перечень объявлен в дереве ОДИН раз;
# копия здесь была бы вторым местом об одном предмете и разошлась бы молча.
SURFACE_DECL = "internal/repohygiene/kanamenameresidue.go"
SURFACE_BLOCK = re.compile(r"var KanameSurface = \[\]string\{(.*?)\n\}", re.S)

BUCKETS = (
    "ПРЕДМЕТ: поверхность",
    "ПРЕДМЕТ: манифесты",
    "ПРЕДМЕТ: прочее",
    "остаётся: ns",
    "остаётся: зонт",
    "граница: приёмки",
)


class Refusal(Exception):
    """Мерить нечего — исход, который не выдаётся ни за зелёное, ни за красное."""


def _git(args: list[str]) -> bytes:
    done = subprocess.run(["git", *args], capture_output=True)
    if done.returncode != 0:
        raise Refusal(f"git {' '.join(args)}: {done.stderr.decode('utf-8', 'replace').strip()}")
    return done.stdout


def tracked(rev: str | None) -> list[str]:
    out = _git(["ls-files", "-z"] if rev is None else ["ls-tree", "-r", "-z", "--name-only", rev])
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def blob(path: str, rev: str | None) -> bytes:
    if rev is None:
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return b""
    return subprocess.run(["git", "cat-file", "blob", f"{rev}:{path}"], capture_output=True).stdout


def surface_roots(rev: str | None) -> list[str]:
    """Поверхность Kaname — ИЗ ДЕРЕВА. Не прочиталась — отказ, а не умолчание."""
    src = blob(SURFACE_DECL, rev).decode("utf-8", "replace")
    if not src:
        raise Refusal(f"{SURFACE_DECL} не прочитан — поверхность неизвестна")
    block = SURFACE_BLOCK.search(src)
    if block is None:
        raise Refusal(f"в {SURFACE_DECL} не найдено объявление KanameSurface")
    roots = re.findall(r'"([^"]+)"', block.group(1))
    if not roots:
        raise Refusal(f"объявление KanameSurface в {SURFACE_DECL} пусто")
    return roots


def scan_line(line: str) -> list[str]:
    """Непересекающийся проход слева направо: длинное написание съедает короткое."""
    found: list[str] = []
    i = 0
    while i < len(line):
        for lit in LITERALS:
            if line.startswith(lit, i):
                found.append(lit)
                i += len(lit)
                break
        else:
            i += 1
    return found


def bucket(literal: str, line: str, path: str, roots: list[str]) -> str:
    if path.startswith(ACCEPTANCE_DIR):
        return "граница: приёмки"
    if literal in UMBRELLA:
        return "остаётся: зонт"
    if any(mark in line.lower() for mark in NS_MARKS):
        return "остаётся: ns"
    if path.endswith("manifest.yaml") and not line.lstrip().startswith("#"):
        return "ПРЕДМЕТ: манифесты"
    if any(path == r or path.startswith(r + "/") for r in roots):
        return "ПРЕДМЕТ: поверхность"
    return "ПРЕДМЕТ: прочее"


def main() -> int:
    ap = argparse.ArgumentParser(description="перепись посевной идентичности (предикат §0.1)")
    ap.add_argument("--rev", default=None,
                    help="ревизия замера; без неё — рабочее дерево")
    args = ap.parse_args()

    try:
        files = tracked(args.rev)
        roots = surface_roots(args.rev)
    except Refusal as why:
        print(f"ОТКАЗ: {why}", file=sys.stderr)
        return 2

    hits = {b: 0 for b in BUCKETS}
    seen: dict[str, set[str]] = {b: set() for b in BUCKETS}
    per_root = {r: 0 for r in roots}
    read = binary = 0

    for path in files:
        data = blob(path, args.rev)
        if b"\0" in data[:8000]:
            binary += 1
            continue
        read += 1
        for r in roots:
            if path == r or path.startswith(r + "/"):
                per_root[r] += 1
        if b"kacho-" not in data:
            continue
        for line in data.decode("utf-8", "replace").splitlines():
            if "kacho-" not in line:
                continue
            for lit in scan_line(line):
                b = bucket(lit, line, path, roots)
                hits[b] += 1
                seen[b].add(path)

    print(f"ревизия: {args.rev or 'рабочее дерево'}")
    print(f"осмотрено: в индексе {len(files)} · прочитано {read} · двоичных {binary}")
    for r in roots:
        print(f"  поверхность {r}: файлов {per_root[r]}")

    # Предпосылка переписи, проверяемая ею самой: пустой обход и каталог
    # поверхности без единого файла — ОТКАЗ, а не тихий ноль. Иначе переезд
    # каталога сузил бы популяцию молча.
    if read == 0:
        print("ОТКАЗ: обход пуст — вердикт беспредметен", file=sys.stderr)
        return 2
    empty = [r for r, n in per_root.items() if n == 0]
    if empty:
        print(f"ОТКАЗ: каталог поверхности без файлов: {', '.join(empty)}", file=sys.stderr)
        return 2

    print()
    for b in BUCKETS:
        print(f"{b:<22} {hits[b]:>4} · {len(seen[b]):>3} ф.")
    subject_b = [b for b in BUCKETS if b.startswith("ПРЕДМЕТ")]
    print()
    print(f"{'ПРЕДМЕТ всего':<22} {sum(hits[b] for b in subject_b):>4} · "
          f"{len(set().union(*(seen[b] for b in subject_b))):>3} ф.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
