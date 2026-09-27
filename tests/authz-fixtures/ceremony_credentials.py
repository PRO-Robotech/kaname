#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ОБЪЯВЛЕНИЕ ВОЛНЫ ЦЕРЕМОНИИ В ДЕРЕВЕ СЛУЖБЫ (kaname#398).

ЧТО ОБЪЯВЛЕНО. Какие коллекции набора ждут ЧЕЛОВЕЧЕСКОГО предъявителя — его
машинный посев не выковывает ни при каком устройстве, — и где лежит посев,
который это условие СОЗДАЁТ. Читатели три, и все ищут этот файл по одному пути:

  * `tests/newman/scripts/run.sh` — вычитает перечень из общей волны, когда посев
    есть, и печатает долг, когда его нет;
  * `tests/newman/scripts/run-ceremony.sh` — волна: посев, перечень, прогон,
    вердикт числами;
  * эта же служба спрашивается переписью долга набора через общую функцию.

ПОЧЕМУ ПРЕДИКАТА ЗДЕСЬ НЕТ. «Ключ производит церемония» и «коллекция его ждёт»
уже решает перепись долга набора (`.github/scripts/newman-suite-debt.py`:
`is_ceremony_key`, `ceremony_need`) — с доводами по каждой форме имени и
законными близнецами. Объявление берёт ТУ ЖЕ функцию, а не пишет вторую: перечень
волны обязан быть равен перечню «нужна церемония» переписи, и второе место об
одном предмете разошлось бы с первым молча. Равенство держит проба рядом
(`ceremony_credentials_test.py`), и держит исходом, а не прочтением.

Прежнее объявление живёт в дереве платформы (`PRO-Robotech/kacho:tests/
authz-fixtures/ceremony_credentials.py`) и судит набор, которого там больше нет:
набор службы уехал отдельным продуктом 2026-09-12. Это не копия того файла —
одноимённость по построению, у каждого дерева свой предмет.

ЧТО ЗДЕСЬ СВОЁ — ТРИ ВЕЩИ:

  1. ПУТЬ ПОСЕВА. Имя подпадает под отбор посевов переписи (`seed_*.py`), поэтому
     приехавший посев перепись спросит, какие ключи он пишет и для какой
     поверхности (`--minted-keys`, `--minted-surface`) — как любой другой посев.
     Посев выковывает предъявителя входом человека через СВОЮ церемонию службы
     на посадке `own`: вход паролем → код авторизации → обмен на токен-эндпоинте
     (поверхность церемонии — kaname#423);
  2. ОСНОВАНИЕ (`--verify`). Запись «это производит только церемония» истинна,
     пока ни один МАШИННЫЙ посев ключ такой формы не пишет. Пишет — значит либо
     форма имени лжёт, либо посев подменяет человека машиной; оба — находка;
  3. ДОЛГ (`--debt`). Пока посева нет, волна своего условия создать не может, и
     это печатается числом и поимённо, с держателем каждой позиции по ведомости
     переписи, — а не молчанием.

ИСХОДЫ:
    0 — ответ дан (перечень, путь, «посев есть», долг) либо сверка чиста;
    1 — находка сверки, «посева нет» на `--seed-exists`, либо перечень вывелся
        ПУСТЫМ: «ни одной коллекции не нужна церемония» и «не прочитано ни одной
        коллекции» различаются текстом отказа;
    2 — перепись долга не загружается: без неё отвечать нечем, и молчать нельзя.

Использование:
    python3 ceremony_credentials.py --root . --suite tests/newman --stems
    python3 ceremony_credentials.py --root . --seed-path | --seed-exists
    python3 ceremony_credentials.py --root . --suite tests/newman --debt | --verify
    python3 ceremony_credentials.py --self-test
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parents[1]
DEFAULT_SUITE = "tests/newman"
FIXTURES = pathlib.Path("tests") / "authz-fixtures"
CENSUS = pathlib.Path(".github") / "scripts" / "newman-suite-debt.py"

# Посев, создающий условие волны. Его ещё нет — и это печатается долгом.
SEED_NAME = "seed_ceremony.py"

RC_FINDING = 1
RC_NO_CENSUS = 2


class NoCensus(Exception):
    """Перепись долга не загружается — отвечать нечем."""


def load_census(root: pathlib.Path):
    """Перепись загружается ПО ПУТИ из того же корня, который судится."""
    path = root / CENSUS
    if not path.is_file():
        raise NoCensus(f"переписи долга нет: {path}")
    spec = importlib.util.spec_from_file_location("newman_suite_debt_for_ceremony", path)
    if spec is None or spec.loader is None:
        raise NoCensus(f"перепись долга не загружается: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def seed_path(root: pathlib.Path) -> pathlib.Path:
    return root / FIXTURES / SEED_NAME


def wave(census, suite: pathlib.Path) -> dict[str, list[str]]:
    """Коллекции волны и ключи церемонии, которых каждая ждёт. Порядок — по имени."""
    need = census.ceremony_need(suite)
    return {stem: keys for stem, keys in sorted(need.items()) if keys}


def basis_findings(census, fixtures: pathlib.Path
                   ) -> tuple[list[str], int, int]:
    """Машинный посев не пишет ключ формы церемонии. → (находки, спрошено, ключей)."""
    findings: list[str] = []
    asked = named = 0
    for script in census.seed_scripts(fixtures):
        if script.name == SEED_NAME:
            continue  # производитель условия: писать эти ключи — его предмет
        rc, keys = census._ask(script, "--minted-keys")
        asked += 1
        if rc != 0:
            findings.append(f"посев {script.name} не ответил, какие ключи пишет (код {rc}) — "
                            f"основание объявления не проверено")
            continue
        named += len(keys)
        for key in keys:
            if census.is_ceremony_key(key):
                findings.append(
                    f"машинный посев {script.name} пишет ключ {key} формы ЦЕРЕМОНИИ: "
                    f"либо форма имени лжёт, либо посев подменяет человека машиной")
    return findings, asked, named


def cmd_stems(census, suite: pathlib.Path) -> int:
    stems = wave(census, suite)
    if not stems:
        print("перечень волны вывелся ПУСТЫМ: коллекции прочитаны, и ни одна не ждёт "
              "предъявителя церемонии — объявление без предмета", file=sys.stderr)
        return RC_FINDING
    for stem in stems:
        print(stem)
    return 0


def cmd_debt(census, root: pathlib.Path, suite: pathlib.Path) -> int:
    stems = wave(census, suite)
    seed = seed_path(root)
    print("[ceremony] ОТКРЫТЫЙ ДОЛГ: волна церемонии своего условия создать не может —")
    print(f"[ceremony]   посева нет: {seed.relative_to(root)}")
    print(f"[ceremony]   коллекций, которым нужен человеческий предъявитель: {len(stems)} "
          f"(выведено из дерева, не выписано)")
    by_holder: dict[str, list[str]] = {}
    for stem, keys in stems.items():
        print(f"[ceremony]     · {stem} — {', '.join(keys)}")
        holder = census.PRODUCER_LEDGER.get(stem, ("", "", ""))[2]
        m = census.HOLDER_REF_RE.match(holder)
        by_holder.setdefault(m.group(1) if m else "—", []).append(stem)
    print("[ceremony]   держатель по ведомости переписи:")
    for ref, held in sorted(by_holder.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"[ceremony]     · {ref}: {len(held)}")
    print("[ceremony]   предикат снятия: посев существует, перепись долга зачитывает его "
          "ключи, и волна")
    print("[ceremony]   `run-ceremony.sh` отчитывается по каждой коллекции перечня.")
    return 0


def cmd_verify(census, root: pathlib.Path, suite: pathlib.Path) -> int:
    need = census.ceremony_need(suite)
    stems = {s: k for s, k in need.items() if k}
    findings: list[str] = []
    if not stems:
        findings.append("ни одна прочитанная коллекция не ждёт предъявителя церемонии — "
                        "объявление без предмета")
    basis, asked, named = basis_findings(census, root / FIXTURES)
    findings += basis
    print(f"осмотрено: коллекций {len(need)} · ждут церемонии {len(stems)} · "
          f"машинных посевов спрошено {asked} · ключей ими названо {named} · "
          f"посев церемонии {'ЕСТЬ' if seed_path(root).is_file() else 'нет'}")
    if findings:
        print("НАХОДКА: объявление волны церемонии разошлось с деревом:")
        for f in findings:
            print(f"  · {f}")
        return RC_FINDING
    print("ЧИСТО: перечень непуст, и ни один машинный посев не пишет ключа церемонии")
    return 0


# ───────────────────────────── доказательство инъекцией ─────────────────────────

_FAILED: list[str] = []


def _check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _FAILED.append(label)


def _suite(base: pathlib.Path, cols: dict[str, str], tmpl: dict[str, str]) -> pathlib.Path:
    suite = base / "tests" / "newman"
    (suite / "collections").mkdir(parents=True)
    (suite / "environments").mkdir(parents=True)
    for stem, body in cols.items():
        (suite / "collections" / f"{stem}.postman_collection.json").write_text(
            json.dumps({"item": [{"request": {"url": body}}]}), encoding="utf-8")
    (suite / "environments" / "local.postman_environment.template.json").write_text(
        json.dumps({"values": [{"key": k, "value": v} for k, v in tmpl.items()]}),
        encoding="utf-8")
    return suite


def _seed(base: pathlib.Path, name: str, keys: list[str]) -> None:
    d = base / FIXTURES
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(
        "import sys\n"
        f"if '--minted-keys' in sys.argv: print({chr(10).join(keys)!r})\n"
        "if '--minted-surface' in sys.argv: print('служба (собственный REST-фронт)')\n",
        encoding="utf-8")


def self_test() -> int:
    census = load_census(DEFAULT_ROOT)
    tmpl = {"jwtHumanX": "", "jwtAdmin": "", "jwtAdminStepUp": "",
            "humanSlotUserId": "", "svaInviteeId": "", "jwtAccountAdminA": "",
            "runId": ""}
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        suite = _suite(base, {
            "brace-human": "{{jwtHumanX}}/x",
            "brace-machine": "{{jwtAccountAdminA}}/x",
            "get-stepup": "pm.environment.get('jwtAdminStepUp')",
            "get-plain": "pm.environment.get('jwtAdmin')",
            "human-id": "{{humanSlotUserId}}",
            "sva-invitee": "{{svaInviteeId}}",
            "self-written": "pm.environment.set('jwtHumanX', 'x'); {{jwtHumanX}}",
        }, tmpl)
        got = wave(census, suite)
        print("ось 1 — форма `{{…}}`")
        _check("предъявитель человека — в волне", "brace-human" in got, str(got))
        _check("машинный близнец — вне волны", "brace-machine" not in got, str(got))
        print("ось 2 — форма `environment.get(…)` и повышенный уровень")
        _check("`…StepUp` — в волне", "get-stepup" in got, str(got))
        _check("тот же ключ без `StepUp` — вне волны", "get-plain" not in got, str(got))
        print("ось 3 — идентификатор человека против похожего машинного имени")
        _check("`human…UserId` — в волне", "human-id" in got, str(got))
        _check("`svaInviteeId` — вне волны", "sva-invitee" not in got, str(got))
        print("ось 4 — ключ, который коллекция пишет САМА, не требование к стенду")
        _check("самозаписанный — вне волны", "self-written" not in got, str(got))
        print("ось 5 — перечень волны равен перечню переписи на том же дереве")
        need = {s for s, k in census.ceremony_need(suite).items() if k}
        _check("равенство множеств", set(got) == need, f"{sorted(got)} ≠ {sorted(need)}")

        print("ось 6 — основание: машинный посев с ключом церемонии")
        _seed(base, "seed_machine.py", ["jwtAccountAdminA", "jwtHumanX"])
        f, asked, _ = basis_findings(census, base / FIXTURES)
        _check("находка называет посев и ключ",
               any("seed_machine.py" in x and "jwtHumanX" in x for x in f), str(f))
        _check("посев спрошен", asked == 1, str(asked))
        _seed(base, "seed_machine.py", ["jwtAccountAdminA"])
        f, _, named = basis_findings(census, base / FIXTURES)
        _check("законный близнец — только машинные ключи: молчание", not f, str(f))
        _check("названные ключи посчитаны", named == 1, str(named))
        _seed(base, SEED_NAME, ["jwtHumanX", "jwtAdminStepUp"])
        f, asked, _ = basis_findings(census, base / FIXTURES)
        _check("посев церемонии пишет ключи церемонии — это его предмет: молчание",
               not f, str(f))
        _check("посев церемонии в основание не спрашивается", asked == 1, str(asked))

        print("ось 7 — «посев есть» следует за файлом")
        _check("файл есть — путь найден", seed_path(base).is_file(), str(seed_path(base)))
        (base / FIXTURES / SEED_NAME).unlink()
        _check("файла нет — путь не найден", not seed_path(base).is_file(), "")
        _check("имя посева подпадает под отбор переписи",
               pathlib.Path(SEED_NAME).match("seed_*.py"), SEED_NAME)

    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        print("ось 8 — пустой обход не есть ответ")
        empty = base / "tests" / "newman"
        (empty / "collections").mkdir(parents=True)
        try:
            census.ceremony_need(empty)
            _check("пустой набор — отказ", False, "ответ дан на пустом обходе")
        except ValueError as e:
            _check("пустой набор — отказ, и он называет непрочитанное",
                   "не прочитано" in str(e), str(e))
        suite = _suite(base / "b", {"only-machine": "{{jwtAccountAdminA}}"}, tmpl)
        _check("прочитано, но никто не ждёт — перечень пуст", not wave(census, suite), "")
        _check("и пустой перечень — находка, а не ответ",
               cmd_stems(census, suite) == RC_FINDING, "")

    if _FAILED:
        print(f"ПРОВАЛ: {len(_FAILED)} утверждени(й) не сошлось: {', '.join(_FAILED)}")
        return RC_FINDING
    print("ВСЕ утверждения сошлись: объявление различает каждую форму в обе стороны, "
          "и пустой обход отличим от пустого ответа.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=pathlib.Path, default=DEFAULT_ROOT)
    ap.add_argument("--suite", default=DEFAULT_SUITE)
    act = ap.add_mutually_exclusive_group(required=True)
    for flag in ("--stems", "--seed-path", "--seed-exists", "--debt", "--verify",
                 "--self-test"):
        act.add_argument(flag, action="store_true")
    a = ap.parse_args(argv)
    root = a.root.resolve()
    if a.seed_path:
        print(seed_path(root))
        return 0
    if a.seed_exists:
        return 0 if seed_path(root).is_file() else RC_FINDING
    try:
        if a.self_test:
            return self_test()
        census = load_census(root)
        suite = root / a.suite
        if a.stems:
            return cmd_stems(census, suite)
        if a.debt:
            return cmd_debt(census, root, suite)
        return cmd_verify(census, root, suite)
    except NoCensus as e:
        print(f"ОТКАЗ: {e} — перечень волны выводится ею, и без неё отвечать нечем",
              file=sys.stderr)
        return RC_NO_CENSUS
    except ValueError as e:
        print(f"ОТКАЗ: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
