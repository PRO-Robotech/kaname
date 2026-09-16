#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""go-test-verdict — читает `go test -json` со стдина и выносит ЧИСЛОВОЙ вердикт.

ИСХОДОВ ТРИ, и они не смешиваются:

  0 — ЗЕЛЁНЫЙ: обход непуст, отказов нет;
  1 — КРАСНЫЙ: упала проба либо пакет не собрался;
  2 — НЕ ВЫПОЛНИЛОСЬ: обход пуст — не осмотрено НИ ОДНОГО пакета, — либо
      оборван — пакет начат и не завершён. Это не успех: «ноль отказов» здесь
      означало бы «ноль прочитанного», а такой вердикт нельзя ни подтвердить,
      ни опровергнуть.

ЗАЧЕМ ПРОГОНЩИК, А НЕ ГОЛЫЙ `go test`. Голый печатает `ok` и на пакете, где
пробы ПРОШЛИ, и на пакете, где они все ПРОПУЩЕНЫ, и на пакете, где проб нет
вовсе. Три разных состояния под одним словом — и ни одного числа. Перепись
отвечает на вопрос, на который `ok` не отвечает: сколько прочитано.

ПРОПУСК — САМОСТОЯТЕЛЬНАЯ ВЕЛИЧИНА. Он не прибавляется к пройденным и не
вычитается из отказов: он печатается своим числом, чтобы рост пропусков был
виден раньше, чем кто-нибудь заметит, что гейт перестал что-либо утверждать.

ЕДИНИЦА СЧЁТА НАЗВАНА, потому что без неё числа несравнимы: проба — это
СОБЫТИЕ пробы, подпробы считаются наравне с родителями. В перечне упавших
печатаются только верхнеуровневые имена (родитель падает вслед за ребёнком,
поэтому перечень с подпробами был бы длиннее, но не содержательнее).

ТЕКСТ ОТКАЗА ПЕЧАТАЕТСЯ, А НЕ ТОЛЬКО ИМЯ. Шаг конвейера пишет весь поток
`go test` в файл, поэтому ничего, кроме этой переписи, в журнал задания не
попадает. Имя упавшей пробы без её вывода вынуждает ставить диагноз по имени:
так проба, упавшая под детектором гонок, читалась как «падает на чужом запросе
слияния», а `WARNING: DATA RACE` с координатами лежал в файле, который никто не
видел. Поэтому у каждой упавшей пробы печатается её вывод — той итерации,
которая упала. Отказ приходит в трёх формах, и каждая печатается своим текстом:

  — проба упала (событие `fail` пробы) — её вывод и вывод упавших подпроб;
  — пакет не собрался (`FailedBuild`) — вывод сборки этого пакета: он идёт
    в поток JSON-событиями `build-output`, а не строками «выше»;
  — пакет упал без упавшей пробы (предел времени, паника вне пробы) — вывод
    начатых и не завершённых проб и вывод самого пакета.

Вывод ОГРАНИЧЕН (первые и последние строки каждой пробы, общий предел), и
усечение называется числом: неполный текст обязан быть отличим от полного.
Усечённая середина остаётся только в самом потоке `go test -json`.

НЕ ВЫПОЛНИЛОСЬ — ОТДЕЛЬНЫЙ ИСХОД, а не зелёный. Пакет, начатый и не
завершённый ни проходом, ни отказом, означает оборванный поток (например, убит
сам `go test`): «отказов 0» на нём значит «досмотреть не успели». Такой прогон
получает код 2. Предел назван честно: пакет, который НЕ НАЧАЛСЯ, из потока не
виден вовсе, и этот прогонщик о нём ничего сказать не может.
"""

import collections
import json
import subprocess
import sys


# Предел текста отказа. Голова несёт первую находку (первый отчёт детектора
# гонок, первое утверждение, первую строку паники), хвост — строку исхода
# («--- FAIL», «race detected during execution of test»). Середина — повторы
# и стеки чужих горутин; она усекается, и усечение называется числом.
FAILURE_TEXT_HEAD = 80
FAILURE_TEXT_TAIL = 20
FAILURE_TEXT_TOTAL = 1000
FAILURE_LINE_CHARS = 400

# Строки разметки, которые `go test -json` добавляет сам (`-test.v=test2json`):
# они называют пробу, а не её отказ, и имя уже стоит в заголовке блока.
_FRAMING = ("=== RUN", "=== PAUSE", "=== CONT", "=== NAME")


def _clip_line(line):
    line = line.rstrip("\n")
    if len(line) > FAILURE_LINE_CHARS:
        return "%s …(обрезано %d симв.)" % (line[:FAILURE_LINE_CHARS],
                                             len(line) - FAILURE_LINE_CHARS)
    return line


def _failure_text(lines):
    """Строки блока с усечением середины; усечение названо числом."""
    lines = [_clip_line(l) for l in lines if not l.startswith(_FRAMING)]
    lines = [l for l in lines if l.strip()] or ["(проба не напечатала ничего)"]
    if len(lines) <= FAILURE_TEXT_HEAD + FAILURE_TEXT_TAIL:
        return lines
    cut = len(lines) - FAILURE_TEXT_HEAD - FAILURE_TEXT_TAIL
    return (lines[:FAILURE_TEXT_HEAD]
            + ["… пропущено строк: %d из %d …" % (cut, len(lines))]
            + lines[-FAILURE_TEXT_TAIL:])


def verdict(stream, out=sys.stdout):
    """Считает события `go test -json` и печатает перепись. Возвращает код исхода."""
    pkg = collections.Counter()
    test = collections.Counter()
    failed_top = []
    # Пакеты, у которых НЕ БЫЛО ни одного события пробы: либо пусты, либо не собрались.
    saw_test_event = set()
    seen_pkgs = set()
    started_pkgs = set()
    ended_pkgs = set()
    unparsable = 0

    # Вывод пробы копится С НАЧАЛА ЕЁ ИТЕРАЦИИ: при `-count>1` одно имя
    # исполняется многократно, и текст отказа — это текст упавшей итерации, а не
    # склейка всех.
    running = {}
    failed_runs = []  # (пакет, проба, строки) в порядке потока
    pkg_output = collections.defaultdict(list)
    build_output = collections.defaultdict(list)
    failed_pkgs = []  # (пакет, FailedBuild) в порядке потока

    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            # Сборка роняет НЕ-JSON в тот же поток. Строку считаем, но вердикта
            # по ней не выносим: её предмет назовёт событие `fail` пакета.
            unparsable += 1
            continue
        if not isinstance(event, dict):
            unparsable += 1
            continue

        action = event.get("Action")
        package = event.get("Package")
        name = event.get("Test")
        text = event.get("Output") or ""

        # Вывод сборки адресован ImportPath, а не пакету: пакет ссылается на
        # него полем FailedBuild своего события `fail`.
        if action == "build-output":
            if event.get("ImportPath"):
                build_output[event["ImportPath"]].append(text)
            continue

        if package:
            seen_pkgs.add(package)

        if name is None:
            if action == "start":
                started_pkgs.add(package)
            elif action == "output":
                pkg_output[package].append(text)
            elif action in ("pass", "fail", "skip"):
                pkg[action] += 1
                ended_pkgs.add(package)
                if action == "fail":
                    failed_pkgs.append((package, event.get("FailedBuild")))
            continue

        saw_test_event.add(package)
        key = (package, name)
        if action == "run":
            running[key] = []
        elif action == "output":
            if key in running:
                running[key].append(text)
            else:
                # Вывод, пришедший после исхода пробы (горутина пережила её):
                # принадлежит пакету, а не потерян.
                pkg_output[package].append(text)
        elif action in ("pass", "fail", "skip"):
            test[action] += 1
            lines = running.pop(key, [])
            if action == "fail":
                failed_runs.append((package, name, lines))
                if "/" not in name:
                    failed_top.append("%s :: %s" % (package, name))

    silent_pkgs = sorted(p for p in seen_pkgs if p not in saw_test_event)
    executed = test["pass"] + test["fail"]
    # Начаты и не завершены: так выглядит проба под пределом времени и под
    # паникой вне пробы — события `fail` у неё нет, есть только у пакета.
    interrupted = sorted(running.items())
    unterminated = sorted(started_pkgs - ended_pkgs)

    print("", file=out)
    print("=== ВЕРДИКТ ПРОГОНА (единица: событие пробы; подпробы считаются) ===", file=out)
    print("пакетов осмотрено : %d  (прошло %d · упало %d · без проб %d)"
          % (len(seen_pkgs), pkg["pass"], pkg["fail"], pkg["skip"]), file=out)
    print("проб исполнено    : %d" % executed, file=out)
    print("отказов           : %d" % test["fail"], file=out)
    print("ПРОПУЩЕНО         : %d  (в зачёт прохода НЕ идёт)" % test["skip"], file=out)
    if interrupted:
        print("проб оборвано     : %d  (начаты и не завершены)" % len(interrupted), file=out)
    if unterminated:
        print("пакетов оборвано  : %d  (начаты и не завершены)" % len(unterminated), file=out)
    if unparsable:
        print("не-JSON строк     : %d  (не события `go test -json`)" % unparsable, file=out)
    if silent_pkgs:
        print("пакетов без событий проб: %d" % len(silent_pkgs), file=out)

    if not seen_pkgs:
        print("", file=out)
        print("БЕСПРЕДМЕТНО: обход пуст — ни одного пакета не осмотрено.", file=out)
        print("Это не зелёный вердикт: спросить было не у кого.", file=out)
        return 2

    if test["fail"] or pkg["fail"]:
        print("", file=out)
        print("=== упавшие пробы верхнего уровня (%d) ===" % len(failed_top), file=out)
        for item in sorted(failed_top):
            print("   %s" % item, file=out)
        if pkg["fail"] and not test["fail"]:
            print("", file=out)
            print("Упали ПАКЕТЫ при нуле упавших проб: не собрались, оборваны пределом", file=out)
            print("времени либо упали вне проб. Их вывод — ниже; это отказ, а не пропуск.", file=out)
        _print_failure_text(out, failed_runs, failed_pkgs, interrupted,
                            pkg_output, build_output)
        print("", file=out)
        print("КРАСНЫЙ: отказов %d." % (test["fail"] or pkg["fail"]), file=out)
        return 1

    if unterminated:
        print("", file=out)
        print("=== пакеты начаты и не завершены (%d) ===" % len(unterminated), file=out)
        for item in unterminated:
            print("   %s" % item, file=out)
        print("", file=out)
        print("НЕ ВЫПОЛНИЛОСЬ: поток оборван — «отказов 0» здесь значит «досмотреть", file=out)
        print("не успели», а не «отказов нет». Это не зелёный вердикт.", file=out)
        return 2

    print("", file=out)
    print("ЗЕЛЁНЫЙ: отказов нет.", file=out)
    return 0


def _print_failure_text(out, failed_runs, failed_pkgs, interrupted, pkg_output, build_output):
    """Текст отказа: у каждой упавшей пробы и у каждого пакета, упавшего без неё."""
    blocks = []
    for package, name, lines in failed_runs:
        blocks.append(("%s :: %s" % (package, name), lines))
    pkgs_with_failed_test = {p for p, _, _ in failed_runs}
    for package, failed_build in failed_pkgs:
        if package in pkgs_with_failed_test:
            continue
        if failed_build:
            blocks.append(("%s [не собрался]" % package, build_output.get(failed_build, [])))
            continue
        for (ipkg, iname), lines in interrupted:
            if ipkg == package:
                blocks.append(("%s :: %s [начата и не завершена]" % (ipkg, iname), lines))
        blocks.append(("%s [вывод пакета]" % package, pkg_output.get(package, [])))

    print("", file=out)
    print("=== текст отказа (на пробу: первые %d и последние %d строк; всего до %d) ==="
          % (FAILURE_TEXT_HEAD, FAILURE_TEXT_TAIL, FAILURE_TEXT_TOTAL), file=out)
    printed = 0
    for i, (title, lines) in enumerate(blocks):
        text = _failure_text(lines)
        if printed and printed + len(text) > FAILURE_TEXT_TOTAL:
            print("", file=out)
            print("… текст ещё %d блоков не напечатан: исчерпан общий предел %d строк;"
                  % (len(blocks) - i, FAILURE_TEXT_TOTAL), file=out)
            print("  имена упавших — в перечне выше.", file=out)
            return
        print("", file=out)
        print("--- %s" % title, file=out)
        for l in text:
            print("    %s" % l, file=out)
        printed += len(text)


# --- самопроверка: доказательство инъекцией в обе стороны ---------------------
#
# Живёт ФЛАГОМ этого же файла, а не соседним: отдельный файл в перечень шагов
# конвейера не попал бы сам, то есть не исполнялся бы никогда.
#
# Инъекция меняет РОВНО ОДИН факт против положительного близнеца — иначе
# неизвестно, какой из двух дал красное.
def self_test():
    green = ('{"Action":"run","Package":"p","Test":"TestA"}\n'
             '{"Action":"pass","Package":"p","Test":"TestA"}\n'
             '{"Action":"pass","Package":"p"}\n')
    probes = 0
    failed = 0

    def run(want, title, payload):
        nonlocal probes, failed
        probes += 1
        buf = []

        class Sink:
            def write(self, s):
                buf.append(s)

            def flush(self):
                pass

        got = verdict(iter(payload.splitlines()), out=Sink())
        text = "".join(buf)
        if got != want:
            print("  ПРОВАЛ %s — ждали код %d, получили %d" % (title, want, got),
                  file=sys.stderr)
            failed += 1
            return ""
        print("  ok   %s (код %d)" % (title, got))
        return text

    print("=== прогонщик вердикта: доказательство инъекцией ===")

    # (−) ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ. Без него всё нижеследующее зеленело бы на
    # прогонщике, который краснеет всегда.
    run(0, "(−) зелёный прогон — зелёный", green)

    # (+) один факт против близнеца: проба упала.
    text = run(1, "(+) упавшая проба — красное", green.replace(
        '{"Action":"pass","Package":"p","Test":"TestA"}',
        '{"Action":"fail","Package":"p","Test":"TestA"}').replace(
        '{"Action":"pass","Package":"p"}', '{"Action":"fail","Package":"p"}'))
    # Диагностика — ЧАСТЬ свойства: находка, не назвавшая имени, посылает
    # читателя искать не там.
    if text and "TestA" not in text:
        print("  ПРОВАЛ (+) красное не назвало имени упавшей пробы", file=sys.stderr)
        failed += 1

    # (+) пакет не собрался: событие `fail` пакета БЕЗ единого события пробы.
    run(1, "(+) пакет не собрался — красное, хотя упавших проб ноль",
        '{"Action":"output","Package":"p","Output":"build failed\\n"}\n'
        '{"Action":"fail","Package":"p"}\n')

    # (+) обход пуст — БЕСПРЕДМЕТНО, а не «прошло».
    run(2, "(+) пустой обход — беспредметно, не зелёное", "")

    # (−) законный близнец пустого обхода: пакет есть, проб в нём нет.
    # Это НЕ беспредметность — пакет прочитан.
    run(0, "(−) пакет без проб — зелёное, обход не пуст",
        '{"Action":"pass","Package":"p"}\n')

    # (+) пропуск НЕ засчитывается проходом и печатается своим числом.
    text = run(0, "(−) пропущенная проба — не красное, но названа числом",
               '{"Action":"skip","Package":"p","Test":"TestA"}\n'
               '{"Action":"pass","Package":"p"}\n')
    if text and "ПРОПУЩЕНО         : 1" not in text:
        print("  ПРОВАЛ пропуск не попал в перепись отдельной величиной", file=sys.stderr)
        failed += 1
    if text and "проб исполнено    : 0" not in text:
        print("  ПРОВАЛ пропуск зачтён в исполненные", file=sys.stderr)
        failed += 1

    # (−) не-JSON строка сама по себе вердикта не меняет: её предмет назовёт
    # событие пакета. Иначе любая строка сборки красила бы зелёный прогон.
    run(0, "(−) не-JSON строка при зелёных событиях зелёного не меняет",
        "# github.com/x/y\n" + green)

    # --- текст отказа ------------------------------------------------------
    #
    # Пара близнецов различается ОДНИМ фактом — исходом пробы. Вывод у обоих
    # одинаков и взят из настоящего отказа под детектором гонок: именно его
    # прежний прогонщик не показывал, и диагноз ставился по имени.
    def ev(action, test=None, output=None, pkg="p", **extra):
        e = {"Action": action, "Package": pkg}
        if test is not None:
            e["Test"] = test
        if output is not None:
            e["Output"] = output
        e.update(extra)
        return json.dumps(e, ensure_ascii=False) + "\n"

    race_out = ("==================\n", "WARNING: DATA RACE\n",
                "Read at 0x00c000534198 by goroutine 131:\n",
                "      /src/p/a_test.go:213 +0x75\n",
                "    testing.go:1712: race detected during execution of test\n",
                "--- FAIL: TestA (0.00s)\n")

    def one(outcome):
        return (ev("start") + ev("run", "TestA") + ev("output", "TestA", "=== RUN   TestA\n")
                + "".join(ev("output", "TestA", o) for o in race_out)
                + ev(outcome, "TestA") + ev(outcome))

    text = run(1, "(+) упавшая проба — её текст отказа напечатан", one("fail"))
    for want in ("WARNING: DATA RACE", "/src/p/a_test.go:213",
                 "race detected during execution of test"):
        if text and want not in text:
            print("  ПРОВАЛ (+) текст отказа не напечатан: нет %r" % want, file=sys.stderr)
            failed += 1
    if text and "=== RUN" in text:
        print("  ПРОВАЛ (+) строка разметки напечатана как текст отказа", file=sys.stderr)
        failed += 1

    # (−) законный близнец: тот же вывод, проба ПРОШЛА — лишнего не печатается.
    text = run(0, "(−) прошедшая проба — её вывод не печатается", one("pass"))
    for unwanted in ("WARNING: DATA RACE", "текст отказа", "оборвано"):
        if text and unwanted in text:
            print("  ПРОВАЛ (−) зелёный прогон напечатал лишнее: %r" % unwanted, file=sys.stderr)
            failed += 1

    # (+) в красном прогоне печатается вывод УПАВШЕЙ, а не соседней прошедшей.
    text = run(1, "(+) вывод прошедшей соседки в красном прогоне не печатается",
               ev("run", "TestB") + ev("output", "TestB", "NEIGHBOUR-CHATTER\n")
               + ev("pass", "TestB") + one("fail"))
    if text and "NEIGHBOUR-CHATTER" in text:
        print("  ПРОВАЛ (+) напечатан вывод прошедшей пробы", file=sys.stderr)
        failed += 1

    # (+) `-count>1`: текст — упавшей итерации, а не склейка всех.
    text = run(1, "(+) при повторах печатается упавшая итерация",
               ev("run", "TestA") + ev("output", "TestA", "ITER-ONE\n") + ev("pass", "TestA")
               + ev("run", "TestA") + ev("output", "TestA", "ITER-TWO\n") + ev("fail", "TestA")
               + ev("fail"))
    if text and ("ITER-TWO" not in text or "ITER-ONE" in text):
        print("  ПРОВАЛ (+) текст не той итерации", file=sys.stderr)
        failed += 1

    # (+) подпроба: её отказ напечатан, вывод прошедшей подпробы — нет.
    text = run(1, "(+) текст упавшей подпробы напечатан",
               ev("run", "TestP") + ev("run", "TestP/ok") + ev("output", "TestP/ok", "CHILD-OK\n")
               + ev("pass", "TestP/ok") + ev("run", "TestP/bad")
               + ev("output", "TestP/bad", "    p_test.go:12: CHILD-FAILURE\n")
               + ev("fail", "TestP/bad") + ev("fail", "TestP") + ev("fail"))
    if text and ("CHILD-FAILURE" not in text or "CHILD-OK" in text):
        print("  ПРОВАЛ (+) подпроба: не тот текст", file=sys.stderr)
        failed += 1

    # (+) ограничение длины: голова и хвост целы, середина усечена и названа числом.
    long_run = (ev("run", "TestA")
                + "".join(ev("output", "TestA", "line-%03d\n" % i) for i in range(1, 301))
                + ev("fail", "TestA") + ev("fail"))
    text = run(1, "(+) длинный вывод усечён, усечение названо", long_run)
    if text and not ("line-001" in text and "line-300" in text and "line-150" not in text
                     and "пропущено строк: %d из 300" % (300 - FAILURE_TEXT_HEAD - FAILURE_TEXT_TAIL)
                     in text):
        print("  ПРОВАЛ (+) усечение не по пределу или не названо", file=sys.stderr)
        failed += 1

    # (+) длинная строка обрезается, обрезанное названо числом.
    text = run(1, "(+) длинная строка обрезана",
               ev("run", "TestA") + ev("output", "TestA", "x" * (FAILURE_LINE_CHARS + 600) + "\n")
               + ev("fail", "TestA") + ev("fail"))
    if text and "обрезано 600 симв." not in text:
        print("  ПРОВАЛ (+) длинная строка не обрезана", file=sys.stderr)
        failed += 1

    # (+) общий предел: сверх него текст не печатается, и это сказано.
    many = "".join(ev("run", "T%02d" % i)
                   + "".join(ev("output", "T%02d" % i, "l%d\n" % j) for j in range(100))
                   + ev("fail", "T%02d" % i) for i in range(15)) + ev("fail")
    text = run(1, "(+) общий предел исчерпан — сказано, сколько не напечатано", many)
    if text and "текст ещё 5 блоков не напечатан" not in text:
        print("  ПРОВАЛ (+) общий предел не соблюдён или не назван", file=sys.stderr)
        failed += 1

    # (+) пакет не собрался: вывод сборки идёт JSON-событиями по ImportPath.
    ip = "p [p.test]"
    text = run(1, "(+) пакет не собрался — напечатан вывод сборки",
               json.dumps({"ImportPath": ip, "Action": "build-output",
                           "Output": "p/a_test.go:5:28: undefined: undefinedThing\n"}) + "\n"
               + json.dumps({"ImportPath": ip, "Action": "build-fail"}) + "\n"
               + ev("start") + ev("fail", FailedBuild=ip))
    if text and "undefined: undefinedThing" not in text:
        print("  ПРОВАЛ (+) вывод сборки не напечатан", file=sys.stderr)
        failed += 1

    # (+) предел времени: у пробы нет события исхода, отказ — только у пакета.
    text = run(1, "(+) проба оборвана пределом времени — её вывод напечатан",
               ev("start") + ev("run", "TestSlow")
               + ev("output", "TestSlow", "panic: test timed out after 1s\n")
               + ev("output", None, "FAIL\tp\t1.004s\n") + ev("fail"))
    if text and not ("panic: test timed out" in text and "проб оборвано     : 1" in text):
        print("  ПРОВАЛ (+) оборванная проба не названа или её вывод не напечатан",
              file=sys.stderr)
        failed += 1

    # (+) поток оборван: пакет начат и не завершён — НЕ ВЫПОЛНИЛОСЬ, не зелёный.
    # Близнец (−) ниже отличается одним событием — исходом пакета.
    run(2, "(+) пакет начат и не завершён — не выполнилось",
        ev("start") + ev("run", "TestA") + ev("pass", "TestA"))
    run(0, "(−) тот же пакет завершён — зелёный",
        ev("start") + ev("run", "TestA") + ev("pass", "TestA") + ev("pass"))

    print("")
    print("go-test-verdict --self-test: проб исполнено %d, провалов %d" % (probes, failed))
    if probes == 0:
        print("ПРОВАЛ: ни одной пробы не исполнено", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(verdict(sys.stdin))
