#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Держатель РАСХОЖДЕНИЯ вендоренного слоя: копия не правится молча.

ПРЕДМЕТ. Общий слой генератора (`tests/newman/kacholib/`) и вердиктный слой
(`tests/newman/scripts/{assert-suites-green.sh,coverage.py,exec-coverage.py,…}`)
живут в дереве платформы `PRO-Robotech/kacho` и служат там СЕМИ наборам. Набор
службы доступа — восьмой, и он уехал в отдельный репозиторий, где подъём по
дереву за общим слоем не достаёт корня монорепо BY CONSTRUCTION. Без слоя
прогонщик, генератор и сверщик кейсов отказывают ПЕРВОЙ СТРОКОЙ — до любого
обращения к стенду.

Поэтому слой здесь ВЕНДОРЕН, то есть скопирован. Копия без держателя расходится
с оригиналом МОЛЧА, и это уже случилось однажды в обратную сторону: платформа
сняла у помощника приём перечня имён, измерив «вызывающих ноль» ПО СВОЕМУ дереву,
тогда как вызывающий жил здесь. Ни один прогон ни одной стороны покраснеть не мог
— каждая была права о своём дереве.

ЧТО ИМЕННО ЭТА ПРОБА ДЕРЖИТ, И ЧЕГО НЕ ДЕРЖИТ. Держит ДВЕ вещи, обе машинно:

  1. КОПИЮ НЕ ПРАВЯТ МОЛЧА. Отпечаток каждого файла записан; правка файла без
     правки записи роняет пробу с именем файла. Это и есть «нельзя незаметно»:
     править можно, не заметив — нельзя.
  2. РАЗЛИЧИЕ С ОРИГИНАЛОМ ПЕРЕЧИСЛЕНО СТРОКА В СТРОКУ. Запись несёт каждую
     подстановку дословно: что стояло в оригинале, что стоит здесь и ПОЧЕМУ.
     Проба применяет их в ОБРАТНУЮ сторону и требует, чтобы восстановленный текст
     совпал с отпечатком оригинала. Значит «в копии появилось что-то ещё» — не
     стиль, а красное.

НЕ держит: что оригинал не ушёл вперёд. Узнать это можно только имея дерево
платформы рядом, а его в этом репозитории нет и не должно быть — вся суть
выноса службы в том, что её прогон не есть функция чужой ревизии. Поэтому сверка
с оригиналом — ПО РУЧКЕ `KANAME_VENDOR_UPSTREAM=<каталог дерева платформы>`, и
перепись НА КАЖДОМ прогоне называет, сверялась она или нет: «сверено 0» никогда
не должно читаться как «сверено».

ИСХОДЫ:
    0 — все файлы на месте, отпечатки сходятся, различие ровно объявленное;
    1 — находка (отпечаток разошёлся · файла нет · в копии незаявленное различие ·
        вендоренный файл без записи);
    2 — беспредметно: записи нет либо она пуста. Это НЕ «ноль находок».

Самопроверка способности упасть — `vendor_provenance_injection_test.py`
(инъекция по каждой оси с законным близнецом).

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py`. Состав он
собирает ОБХОДОМ дерева по образцу `tests/newman/scripts/*_test.py` и НИ ОДИН
файл проб по имени не называет, поэтому отдельного шага в конвейере файл не
требует. Код возврата при этом доезжает до вердикта шага.
"""

import hashlib
import json
import os
import pathlib
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
SUITE = SCRIPTS.parent
RECORD = SUITE / "vendor-provenance.json"

# Каталог, который целиком вендорен: КАЖДЫЙ его файл обязан иметь запись. Для
# вердиктного слоя такого требования нет — рядом с вендоренными файлами в
# `scripts/` лежат свои, и требовать записи от них значило бы объявить своим
# чужое.
WHOLLY_VENDORED_DIR = SUITE / "kacholib"

# Расширения, по которым в целиком-вендоренном каталоге ищутся файлы. Кэш
# интерпретатора (`__pycache__`) — не файл дерева.
VENDORED_SUFFIXES = (".py", ".sh")

findings: list[str] = []


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def restore_upstream(text: str, rewrites: list[dict], where: str) -> str:
    """Восстановление ОРИГИНАЛА из копии по объявленным подстановкам.

    Замена идёт ПО ТЕКСТУ, а не по номеру строки: номер сдвигается многострочной
    подстановкой, и адресация номером была бы верна ровно до второй правки в том
    же файле. Требуется РОВНО ОДНО вхождение — иначе непонятно, какое из них
    объявлено, и вердикт стал бы свойством порядка.
    """
    for rw in rewrites:
        local, upstream = rw["local"], rw["upstream"]
        n = text.count(local)
        if n != 1:
            findings.append(
                f"{where}: объявленная подстановка (строка {rw['line']} оригинала) "
                f"встречается в копии {n} раз, а не один — восстановить оригинал "
                f"нечем, и различие копии не доказано")
            return ""
        text = text.replace(local, upstream, 1)
    return text


def main() -> int:
    if not RECORD.is_file():
        print(f"БЕСПРЕДМЕТНО: записи вендоринга нет по адресу {RECORD}.", file=sys.stderr)
        print("Это НЕ «ноль находок»: вердикта о копиях нет вовсе.", file=sys.stderr)
        return 2
    try:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"БЕСПРЕДМЕТНО: запись вендоринга нечитаема: {exc}", file=sys.stderr)
        return 2

    entries = record.get("files") or []
    if not entries:
        print("БЕСПРЕДМЕТНО: запись вендоринга не называет ни одного файла — "
              "проверять нечего, и в успех это не засчитывается.", file=sys.stderr)
        return 2

    upstream_dir = os.environ.get("KANAME_VENDOR_UPSTREAM", "").strip()
    upstream_root = pathlib.Path(upstream_dir) if upstream_dir else None

    seen, bytes_read, rewrites_total, compared = 0, 0, 0, 0
    identical = 0
    listed: set[str] = set()

    for entry in entries:
        rel = entry.get("path", "")
        listed.add(rel)
        # Запись адресует пути от КОРНЯ репозитория; корень выводится из
        # положения этого файла, а не из текущего каталога: пробу зовут откуда
        # угодно, и путь, выведенный из cwd, был бы свойством того, ОТКУДА позвали.
        path = SCRIPTS.parents[2] / rel
        if not path.is_file():
            findings.append(f"{rel}: запись вендоринга называет файл, которого в дереве НЕТ")
            continue
        seen += 1
        blob = path.read_bytes()
        bytes_read += len(blob)
        got = hashlib.sha256(blob).hexdigest()
        want = entry.get("local_sha256", "")
        if got != want:
            findings.append(
                f"{rel}: отпечаток копии разошёлся с записью "
                f"(в дереве {got[:12]}…, в записи {want[:12]}…). Копию правили, "
                f"а запись — нет: значит различие с оригиналом больше не перечислено")
            continue

        rewrites = entry.get("rewrites") or []
        rewrites_total += len(rewrites)
        if not rewrites:
            identical += 1
        restored = restore_upstream(blob.decode("utf-8"), rewrites, rel)
        if restored == "":
            continue
        restored_sha = hashlib.sha256(restored.encode("utf-8")).hexdigest()
        if restored_sha != entry.get("upstream_sha256", ""):
            findings.append(
                f"{rel}: снятие объявленных подстановок НЕ восстанавливает оригинал "
                f"({restored_sha[:12]}… против {entry.get('upstream_sha256','')[:12]}…). "
                f"В копии есть различие, которого запись не называет")

        if upstream_root is not None:
            up = upstream_root / rel
            if not up.is_file():
                findings.append(f"{rel}: KANAME_VENDOR_UPSTREAM задан, но файла оригинала там нет: {up}")
            else:
                compared += 1
                if sha256_of(up) != entry.get("upstream_sha256", ""):
                    findings.append(
                        f"{rel}: ОРИГИНАЛ УШЁЛ ВПЕРЁД — отпечаток в дереве платформы "
                        f"не равен записанному. Копию надо подтянуть, а подстановки "
                        f"перечислить заново")

    # Целиком вендоренный каталог: файл без записи держателя не имеет.
    if WHOLLY_VENDORED_DIR.is_dir():
        for path in sorted(WHOLLY_VENDORED_DIR.rglob("*")):
            if not path.is_file() or path.suffix not in VENDORED_SUFFIXES:
                continue
            rel = str(path.relative_to(SCRIPTS.parents[2]))
            if rel not in listed:
                findings.append(
                    f"{rel}: файл лежит в целиком вендоренном каталоге и записи не имеет — "
                    f"его расхождение с оригиналом не держит ничто")
    else:
        findings.append(f"{WHOLLY_VENDORED_DIR}: каталога общего слоя нет — вендоринг не выполнен")

    print(f"перепись: файлов по записи {len(entries)} · прочитано {seen} · "
          f"байт {bytes_read} · подстановок объявлено {rewrites_total} · "
          f"побайтово равных оригиналу {identical} · "
          f"сверено с оригиналом {compared}"
          + ("" if upstream_root is not None
             else " (KANAME_VENDOR_UPSTREAM не задан — дерева платформы рядом нет)"))

    if seen == 0:
        print("БЕСПРЕДМЕТНО: не прочитано ни одного файла — «ноль находок» здесь "
              "означало бы «ноль прочитанного».", file=sys.stderr)
        return 2

    if findings:
        print(f"НАХОДОК {len(findings)}:", file=sys.stderr)
        for f in findings:
            print(f"  · {f}", file=sys.stderr)
        return 1

    print("ЧИСТО: копии сходятся с записью, различие с оригиналом ровно объявленное.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
