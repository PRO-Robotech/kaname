#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПРОИЗВОДИТЕЛЬ записи вендоринга: `tests/newman/vendor-provenance.json`.

ЗАЧЕМ ОН ЕСТЬ. Запись несёт отпечатки и перечень подстановок. Набранная руками,
она разошлась бы с файлами при первой же правке — и разошлась бы молча, потому
что руками сверяют то, что и правили. Запись ПОРОЖДАЕТСЯ: подтягиваешь копию из
дерева платформы — зовёшь этот скрипт, и отпечатки берутся из байтов, а не из
памяти.

ЧТО ОН НЕ ДЕЛАЕТ. Он не решает, какими быть подстановкам: перечень подстановок
переносится из прежней записи как есть, а их применимость проверяет держатель
(`vendor_provenance_test.py`) — снятие подстановок обязано восстановить оригинал.
Значит подтянутая копия, в которой прежняя подстановка больше не находится,
роняет держателя с именем файла, а не проезжает молча.

ЗАЧЕМ ОН ЛЕЖИТ В ДЕРЕВЕ, ЕСЛИ БЕЗ ДЕРЕВА ПЛАТФОРМЫ НЕ РАБОТАЕТ. Потому что
иначе у записи не было бы производителя вовсе, а «порождаемая запись» без
производителя — то же обещание без ответчика, которое корпус и ловит. Без
`--upstream` скрипт ОТКАЗЫВАЕТ явно, а не подставляет догадку.

Использование:
    python3 tests/newman/scripts/vendor_provenance_sync.py --upstream <каталог дерева платформы>
    python3 tests/newman/scripts/vendor_provenance_sync.py --upstream <…> --pull

`--pull` дополнительно КОПИРУЕТ файлы оригинала поверх местных и переприменяет
объявленные подстановки. Без него скрипт только пересчитывает отпечатки по тому,
что уже лежит в дереве.

ИСХОДЫ: 0 — запись обновлена; 1 — подстановка не применилась (при `--pull`);
2 — позван неверно либо дерева платформы по названному пути нет.
"""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]
RECORD = REPO / "tests/newman/vendor-provenance.json"


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--upstream", required=True,
                    help="каталог рабочей копии дерева платформы PRO-Robotech/kacho")
    ap.add_argument("--pull", action="store_true",
                    help="скопировать файлы оригинала поверх местных и переприменить подстановки")
    args = ap.parse_args()

    upstream = pathlib.Path(args.upstream).resolve()
    if not (upstream / "tests/newman/kacholib/gen_shared.py").is_file():
        print(f"ОТКАЗ: {upstream} не похож на дерево платформы — "
              f"tests/newman/kacholib/gen_shared.py там нет.", file=sys.stderr)
        return 2
    if not RECORD.is_file():
        print(f"ОТКАЗ: прежней записи нет ({RECORD}); перечень вендоренных файлов "
              f"и их подстановки брать негде.", file=sys.stderr)
        return 2

    record = json.loads(RECORD.read_text(encoding="utf-8"))
    rev = subprocess.run(["git", "-C", str(upstream), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()

    pulled, failed = 0, 0
    for entry in record["files"]:
        rel = entry["path"]
        up, lo = upstream / rel, REPO / rel
        if not up.is_file():
            print(f"ОТКАЗ: у оригинала нет файла {rel}", file=sys.stderr)
            return 2
        if args.pull:
            text = up.read_text(encoding="utf-8")
            for rw in entry["rewrites"]:
                if text.count(rw["upstream"]) != 1:
                    print(f"ОТКАЗ: {rel}: подстановка со строки {rw['line']} больше не "
                          f"применима к оригиналу — решите её судьбу вручную, "
                          f"а не отпечатком.", file=sys.stderr)
                    failed += 1
                    break
                text = text.replace(rw["upstream"], rw["local"], 1)
            else:
                lo.write_text(text, encoding="utf-8")
                pulled += 1
        blob = subprocess.run(["git", "-C", str(upstream), "rev-parse", f"HEAD:{rel}"],
                              capture_output=True, text=True, check=True).stdout.strip()
        entry["upstream_blob"] = blob
        entry["upstream_sha256"] = sha256_of(up)
        entry["local_sha256"] = sha256_of(lo)

    if failed:
        print(f"перепись: файлов {len(record['files'])} · подтянуто {pulled} · "
              f"неприменимых подстановок {failed} — запись НЕ обновлена", file=sys.stderr)
        return 1

    record["upstream"] = {"repo": "PRO-Robotech/kacho", "revision": rev}
    RECORD.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"перепись: файлов {len(record['files'])} · подтянуто {pulled} · "
          f"подстановок {sum(len(e['rewrites']) for e in record['files'])} · "
          f"ревизия оригинала {rev[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
