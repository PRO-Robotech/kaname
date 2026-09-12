#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Держатель ПРОВЯЗКИ сверки: пин объявлен ОДИН раз, и конвейер сверку ТРЕБУЕТ.

ПРЕДМЕТ — НЕ содержимое копий (его держит `vendor_provenance_test.py`), а УСЛОВИЕ
её сверки с оригиналом. До 2026-09-12 условия не было вовсе: держатель печатал
«сверено с оригиналом 0» и выходил кодом 0, то есть ось «оригинал ушёл вперёд» в
конвейере не измерялась НИ РАЗУ при 14 файлах и 31 объявленной подстановке.
Починка держателя (код 3 вместо молчаливого 0) сама по себе ничего не измеряет:
она лишь ДАЁТ конвейеру возможность потребовать сверку. Требует её конвейер, и
вот это держит настоящая проба.

ЧТО ДЕРЖИТ, ПО ОСЯМ:

  1. ЗАПИСЬ НЕСЁТ ПИН В ГОДНОЙ ФОРМЕ: `upstream.repo` и `upstream.revision` из 40
     шестнадцатеричных знаков. Ревизия-тег или короткий хэш не годятся: тег
     переставляют, короткий хэш коллизует.
  2. ПИН ОБЪЯВЛЕН РОВНО В ОДНОМ МЕСТЕ. Второе объявление разошлось бы с первым
     МОЛЧА: копия сверялась бы с ревизией, из которой её не брали, и оба места
     были бы правы о своём. Предикат — перепись отслеживаемых файлов, несущих
     строку ревизии; их обязан быть ровно один, и это сама запись.
  3. КОНВЕЙЕР СВЕРКУ ТРЕБУЕТ: есть шаг, зовущий держателя с `--require-upstream`.
  4. ТОМУ ЖЕ ШАГУ ДАНО ДЕРЕВО — `KANAME_VENDOR_UPSTREAM` в его `env:` либо в
     тексте его `run:`. Требование без дерева даёт третий исход на каждом прогоне,
     то есть конвейер, который не зеленеет никогда, — и его отключат.
  5. ДЕРЕВО ВЫБИРАЕТСЯ ПО ПИНУ, А НЕ «ПОСЛЕДНЕЕ», И ПИН БЕРЁТСЯ ИЗ ЗАПИСИ.
     Шаг `actions/checkout` с `repository:` в ТОМ ЖЕ задании; и `repository`, и
     `ref` — ВЫРАЖЕНИЯ `${{ steps.<id>.outputs.… }}`, а шаг с этим `<id>` обязан
     ЧИТАТЬ запись (её путь стоит в его `run:`). Литерал вместо выражения и есть
     второе место объявления из оси 2; выражение, ссылающееся на шаг, который
     записи не читает, — то же второе место, лишь спрятанное за подстановкой.
  6. ВЫБОРКА ИДЁТ В ПОДКАТАЛОГ (`path:`) и СТОИТ РАНЬШЕ сверки. Выборка чужого
     дерева в корень затёрла бы рабочую копию службы, а выборка после сверки
     означала бы сверку с тем, чего ещё нет.
  7. КОД ДЕРЖАТЕЛЯ ДОЕЗЖАЕТ ДО ВЕРДИКТА ШАГА. Шаг сверки — РОВНО ОДНА команда без
     перехвата кода и без развилки, и сам он не под послаблением. Предикат белым
     списком, а не перечнем запрещённых написаний: одна команда под `bash -e`
     отдаёт код держателя BY CONSTRUCTION, а разбор оболочки на «в нужной ли ветке
     этот выход» был бы гаданием.
  8. ПОСЛАБЛЕНИЕ У ВЫБОРКИ СПАРЕНО С ТЕМ, КТО ЛОВИТ ОТКАЗ. `continue-on-error` у
     выборки чужого дерева защитимо ровно тем, что ниже стоит требующий сверки шаг,
     сам без послабления. Нет такого шага — послабление заведено, а не объяснено.

     ОСИ 7-8 ЗАВЕДЕНЫ 2026-09-12 ПО НАЗВАННОМУ ДЕФЕКТУ. Безобидность послабления
     держалась ОДНОЙ строкой `exit 1` в развилке шага сверки, и не держало её
     НИЧТО: снятие строки оставляло 18 утверждений из 18 зелёными, а третий исход
     снова становился неотличим от прохода. Развилка снята вместе с предметом:
     аннотация о несозданном условии живёт отдельным шагом, у которого нет
     падающего пути, поэтому замолчать чужой отказ ей нечем.

ПОЧЕМУ РАЗБОР ОПИСАНИЯ, А НЕ ПОИСК ПОДСТРОКИ. Строка `--require-upstream`
встречается и в комментариях — в этом файле, в шапке держателя, в объяснениях
самого процесса. Проверка подстрокой зеленела бы на СВОЁМ ЖЕ объяснении: это
ровно тот класс, который корпус ловит. Поэтому судятся узлы разобранного
описания, а её собственная способность упасть доказывается осью, где флаг стоит
ТОЛЬКО в комментарии.

ПОЧЕМУ РАЗБОР СВОЙ, А НЕ pyyaml. Пробу зовёт общий прогонщик проб, и третьего
исхода для гейта у него нет: любой ненулевой код он считает красным. Обязательная
зависимость означала бы КРАСНОЕ О ДЕРЕВЕ на машине, где её не поставили, — то есть
вердикт о дереве там, где вердикта нет вовсе. Прогонщик при этом ВЕНДОРЕН из дерева
платформы, и учить его третьему исходу отсюда нельзя. pyyaml остался КОНТРОЛЕМ: он
есть — свой разбор сверяется с ним по тем узлам, которые проба судит, и расхождение
есть НАХОДКА; его нет — вердикт остаётся, а несверенность названа в переписи.

ИСХОДЫ:
    0 — провязка на месте;
    1 — находка (в том числе: разборщики разошлись);
    2 — беспредметно: нет записи · нет описания процесса · описание несёт узел,
        которого этот разбор не знает (он ОТКАЗЫВАЕТСЯ УГАДЫВАТЬ — неверно
        прочитанное описание дало бы ложный вердикт) · обход не дал ни одного шага
        либо ни одного файла. Это НЕ «ноль находок».

Самопроверка способности упасть — `--self-test`: по каждой оси инъекция с
законным близнецом на синтетическом дереве вне репозитория. Её исходы ТРИ: 0 —
все утверждения сошлись; 1 — хотя бы одно нет; 2 — часть осей НЕ ИСПОЛНЯЛАСЬ
(три из них судят перепись по индексу git и без git предмета не имеют). Третий не
вычитается из вердикта и не идёт в зачёт прохода.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ: `.github/scripts/run-python-probes.py` — обходом дерева
по образцу `tests/newman/scripts/*_test.py`, без называния файла по имени. Её
`--self-test` зовётся отдельным шагом процесса, потому что прогонщик зовёт файл
без аргументов, и вердикту нельзя верить прежде доказательства.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]

WORKFLOW_REL = ".github/workflows/e2e-newman.yml"
RECORD_REL = "tests/newman/vendor-provenance.json"
HOLDER_NAME = "vendor_provenance_test.py"
REQUIRE_FLAG = "--require-upstream"
UPSTREAM_ENV = "KANAME_VENDOR_UPSTREAM"
CHECKOUT_ACTION = "actions/checkout"
CONTINUE_ON_ERROR = "continue-on-error"

# Написания, которыми код выхода перехватывают или подменяют. Список нужен НЕ как
# запрет форм, а как объяснение находки: сам предикат — «ровно одна команда».
SWALLOWERS = ("||", "&&", ";", "|", "exit ", "case ", "if ", "set +e", "rc=")
REVISION_FORM = re.compile(r"^[0-9a-f]{40}$")
STEP_OUTPUT = re.compile(r"\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.")

# Каталоги, куда обход за вторым объявлением не заходит: индекс git — не файл
# дерева, кэш интерпретатора тоже.
WALK_SKIP = {".git", "__pycache__", "node_modules"}


class Bespredmetno(Exception):
    """Условие не создано: судить нечего, и в успех это не засчитывается."""


def tracked_files(root: pathlib.Path) -> tuple[list[pathlib.Path], str]:
    """Состав для переписи второго объявления — по индексу git, с откатом на ФС.

    Для репозитория авторитет — версионный контроль: то же множество, что у CI на
    свежем checkout'е. В синтетическом дереве самопроверки git отсутствует (и, что
    важнее, обход вверх нашёл бы ЧУЖОЙ репозиторий), поэтому источник выбирается
    по совпадению корня, а не по тому, ответил ли git.
    """
    try:
        top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=60).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        top = ""
    if top and pathlib.Path(top).resolve() == root.resolve():
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, text=True, timeout=120, check=True).stdout
        return [root / n for n in out.split("\0") if n], "индекс git"
    found = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in WALK_SKIP]
        for f in files:
            found.append(pathlib.Path(dirpath) / f)
    return sorted(found), "обход файловой системы"


# ─────────────────────── СВОЙ РАЗБОР ОПИСАНИЯ ПРОЦЕССА ──────────────────────
#
# ПОЧЕМУ СВОЙ, А НЕ pyyaml. Пробу зовёт общий прогонщик проб, и третьего исхода
# для гейта у него НЕТ: любой ненулевой код он считает красным (`run_script` —
# «вердикт есть его код выхода»). Обязательная зависимость означала бы КРАСНОЕ О
# ДЕРЕВЕ на всякой машине, где её не поставили, — то есть вердикт о дереве там,
# где вердикта нет вовсе. Прогонщик при этом вендорен из дерева платформы
# (17 объявленных подстановок), и учить его третьему исходу отсюда нельзя.
#
# ПОЧЕМУ ЭТОМУ РАЗБОРУ МОЖНО ВЕРИТЬ — И ЧЕГО ОН НЕ ДЕЛАЕТ. Он покрывает ровно то
# подмножество, которым описаны процессы этого дерева: отображения по отступу,
# последовательности отображений и скаляров, блочный скаляр `|`, поточная
# последовательность `[a, b]`, кавычки, комментарии. Узел, которого он не знает
# (`>`, поточное отображение, якорь, тег, табуляция в отступе, многодокументный
# файл), даёт БЕСПРЕДМЕТНОСТЬ С ИМЕНЕМ УЗЛА — он отказывается угадывать, потому
# что неверный разбор здесь есть ложный вердикт о провязке.
#
# Замер на настоящем входе: 23 отслеживаемых описания YAML этого дерева; 9
# сошлись с pyyaml ЦЕЛИКОМ (все три описания процессов — среди них), 7 разбор
# отверг, назвав узел, 7 не смог прочитать сам pyyaml. РАСХОЖДЕНИЙ НОЛЬ.
# Предикат — ось «разборщики сверены» ниже: она гоняет оба по каждому
# отслеживаемому описанию процесса на КАЖДОМ прогоне и печатает число.

_BLOCK_HEAD = re.compile(r"^(?P<key>[^:]+):[ \t]*(?P<style>[|>])(?P<mod>[-+]?)\d*[ \t]*$")
_PACKED = "\x00"


def _drop_comment(line: str) -> str:
    """Снятие комментария ВНЕ кавычек: `#` начинает его в начале содержимого либо
    после пробела — иначе `a#b` и `url#frag` рвались бы посередине."""
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _split_flow(body: str) -> list[str]:
    items, depth, quote, cur = [], 0, None, []
    for ch in body:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        items.append("".join(cur))
    return items


def _scalar(text: str):
    s = text.strip()
    if s.startswith(_PACKED):
        return json.loads(s[1:])
    if s == "":
        return None
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        inner = s[1:-1]
        if s[0] == "'":
            return inner.replace("''", "'")
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    if s.startswith("[") and s.endswith("]"):
        return [_scalar(x) for x in _split_flow(s[1:-1])]
    if s[0] in "{&*!>|":
        raise Bespredmetno(
            f"узел «{s[:32]}» этим разбором не поддержан (поточное отображение, "
            f"якорь, тег или свёрнутый скаляр). Разбор отказывается угадывать: "
            f"неверно прочитанное описание дало бы ложный вердикт о провязке. "
            f"Выразите узел поддержанной формой либо научите разбор.")
    return s


def _key_split(text: str):
    """Раздел «ключ: значение» по двоеточию ВНЕ кавычек, за которым пробел или
    конец строки. Без этого элемент-скаляр («- "v[0-9]+…"») читался бы
    отображением, и разбор отказывал бы на законном входе."""
    if text.startswith(_PACKED):
        return None
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch == ":" and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i], text[i + 1:]
    return None


def _flatten(text: str) -> list[tuple[int, str]]:
    """Один проход: снять комментарии и пустые строки, развернуть дефис
    последовательности в свою строку, свернуть блочный скаляр в одну строку."""
    raw = text.splitlines()
    out: list[tuple[int, str]] = []
    i, n = 0, len(raw)
    while i < n:
        line = raw[i]
        if "\t" in line[: len(line) - len(line.lstrip(" \t"))]:
            raise Bespredmetno(f"строка {i + 1}: табуляция в отступе")
        if line.strip() in ("---", "..."):
            raise Bespredmetno(f"строка {i + 1}: многодокументный YAML не поддержан")
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        col = len(line) - len(line.lstrip(" "))
        while line[col:col + 2] == "- ":
            out.append((col, "-"))
            col += 2
            while col < len(line) and line[col] == " ":
                col += 1
        if line[col:].strip() == "-":
            out.append((col, "-"))
            i += 1
            continue
        content = _drop_comment(line[col:]).rstrip()
        head = _BLOCK_HEAD.match(content)
        if head:
            if head.group("style") == ">":
                raise Bespredmetno(
                    f"строка {i + 1}: свёрнутый блочный скаляр (>) этим разбором не "
                    f"поддержан — сворачивание строк здесь угадывалось бы. Возьмите "
                    f"блочный `|` либо научите разбор.")
            if head.group("mod") == "+":
                raise Bespredmetno(
                    f"строка {i + 1}: указатель «+» у блочного скаляра не поддержан")
            body, first = [], None
            i += 1
            while i < n:
                if not raw[i].strip():
                    body.append(None)
                    i += 1
                    continue
                bind = len(raw[i]) - len(raw[i].lstrip(" "))
                if bind <= col:
                    break
                if first is None:
                    first = bind
                body.append(raw[i][first:])
                i += 1
            while body and body[-1] is None:
                body.pop()
            joined = "\n".join("" if x is None else x for x in body)
            if head.group("mod") != "-" and joined:
                joined += "\n"
            out.append((col, head.group("key").rstrip() + ": " + _PACKED
                        + json.dumps(joined, ensure_ascii=False)))
            continue
        out.append((col, content))
        i += 1
    return out


def _node(lines, i, col):
    if lines[i][1] == "-":
        return _seq(lines, i, col)
    return _mapping(lines, i, col)


def _seq(lines, i, col):
    items = []
    while i < len(lines) and lines[i][0] == col and lines[i][1] == "-":
        i += 1
        if i < len(lines) and lines[i][0] > col:
            if lines[i][1] != "-" and _key_split(lines[i][1]) is None:
                items.append(_scalar(lines[i][1]))
                i += 1
            else:
                value, i = _node(lines, i, lines[i][0])
                items.append(value)
        else:
            items.append(None)
    return items, i


def _mapping(lines, i, col):
    out = {}
    while i < len(lines) and lines[i][0] == col:
        text = lines[i][1]
        if text == "-":
            break
        split = _key_split(text)
        if split is None:
            raise Bespredmetno(f"«{text[:48]}» — ни ключ, ни элемент последовательности")
        key, rest = split
        i += 1
        if rest.strip() == "":
            if i < len(lines) and lines[i][0] > col:
                out[_scalar(key)], i = _node(lines, i, lines[i][0])
            else:
                out[_scalar(key)] = None
        else:
            out[_scalar(key)] = _scalar(rest)
    return out, i


def _parse_workflow_lite(text: str) -> dict:
    lines = _flatten(text)
    if not lines:
        raise Bespredmetno("описание процесса пусто после снятия комментариев")
    value, rest = _node(lines, 0, lines[0][0])
    if rest != len(lines):
        raise Bespredmetno(
            f"разбор остановился на строке «{lines[rest][1][:48]}» (отступ "
            f"{lines[rest][0]}) — эта раскладка отступов не поддержана")
    if not isinstance(value, dict):
        raise Bespredmetno("корень описания процесса — не отображение")
    return value


# Ключи шага, по которым эта проба судит. Сверка разборщиков идёт по НИМ, а не по
# документу целиком: `on:` pyyaml читает логическим ИСТИНА (YAML 1.1), и
# расхождение имени ключа называло бы разошедшимся то, чего проба не судит.
JUDGED_KEYS = ("name", "id", "uses", "run", "env", "with", "continue-on-error")


def _flat(value):
    """Приведение к строкам: у pyyaml `true` — логическое, `30` — целое, пустое —
    None; у своего разбора всё строки. Сверять надо ЗНАЧЕНИЯ, а не типы."""
    if isinstance(value, dict):
        return {str(k): _flat(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_flat(v) for v in value]
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _projection(doc) -> list:
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return []
    rows = []
    for name in sorted(doc["jobs"], key=str):
        job = doc["jobs"][name]
        steps = job.get("steps") if isinstance(job, dict) else None
        rows.append((str(name), [
            None if not isinstance(st, dict) else {k: _flat(st.get(k)) for k in JUDGED_KEYS}
            for st in (steps or [])]))
    return rows


def _truthy(value) -> bool:
    return str(value).strip().lower() in ("true", "yes", "on", "1")


def load_workflow(root: pathlib.Path) -> tuple[dict, str, list[str]]:
    """Разобранное описание процесса, слово о сверке разборщиков и её находки."""
    path = root / WORKFLOW_REL
    if not path.is_file():
        raise Bespredmetno(f"описания процесса нет по адресу {path}")
    text = path.read_text(encoding="utf-8")
    doc = _parse_workflow_lite(text)
    if not isinstance(doc.get("jobs"), dict):
        raise Bespredmetno(f"{WORKFLOW_REL}: разобранное описание не несёт заданий")
    # ВТОРОЙ РАЗБОРЩИК — КОНТРОЛЬ, А НЕ ЗАВИСИМОСТЬ. Есть pyyaml — сверяем с ним
    # то, что судим; нет — вердикт остаётся, а НЕсверенность названа в переписи.
    findings: list[str] = []
    try:
        import yaml
    except ImportError:
        return doc, "сверка разборщиков НЕ ВЫПОЛНЕНА (pyyaml нет)", findings
    try:
        other = yaml.safe_load(text)
    except Exception as exc:                       # noqa: BLE001 — вердикт чужого
        findings.append(f"{WORKFLOW_REL}: pyyaml не смог прочитать описание ({exc}), "
                        f"а свой разбор смог — сверять разборщики нечем")
        return doc, "сверка разборщиков НЕ ВЫПОЛНЕНА (pyyaml отказал)", findings
    mine, theirs = _projection(doc), _projection(other)
    if mine != theirs:
        where = "состав заданий"
        for (na, sa), (nb, sb) in zip(mine, theirs):
            if na != nb:
                where = f"имя задания ({na} против {nb})"
                break
            if len(sa) != len(sb):
                where = f"задание «{na}»: шагов {len(sa)} против {len(sb)}"
                break
            for idx, (xa, xb) in enumerate(zip(sa, sb)):
                if xa != xb:
                    keys = [k for k in JUDGED_KEYS
                            if (xa or {}).get(k) != (xb or {}).get(k)]
                    where = f"задание «{na}», шаг {idx}, ключи {keys}"
                    break
            else:
                continue
            break
        findings.append(
            f"{WORKFLOW_REL}: РАЗБОРЩИКИ РАЗОШЛИСЬ на {where} — вердикту о провязке "
            f"верить нельзя, пока не известно, который из двух читает описание "
            f"неверно")
    return doc, "сверка разборщиков выполнена", findings


def judge(root: pathlib.Path) -> tuple[list[str], dict]:
    findings: list[str] = []

    record_path = root / RECORD_REL
    if not record_path.is_file():
        raise Bespredmetno(f"записи вендоринга нет по адресу {record_path}")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Bespredmetno(f"запись вендоринга нечитаема: {exc}") from exc

    upstream = record.get("upstream") or {}
    repo, revision = str(upstream.get("repo", "")), str(upstream.get("revision", ""))

    # ── ОСЬ 1: форма пина.
    if not repo:
        findings.append(f"{RECORD_REL}: запись не называет репозиторий оригинала "
                        f"(upstream.repo) — сверять не с чем")
    if not REVISION_FORM.match(revision):
        findings.append(
            f"{RECORD_REL}: ревизия оригинала «{revision or '—'}» не в форме полного "
            f"хэша (40 шестнадцатеричных знаков). Тег переставляют, короткий хэш "
            f"коллузирует — пин, который можно передвинуть, пином не является")

    # ── ОСЬ 2: пин объявлен ровно в одном месте.
    files, source = tracked_files(root)
    needle = revision.encode() if revision else b""
    carriers: list[str] = []
    scanned = 0
    if needle:
        for path in files:
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            scanned += 1
            if needle in blob:
                carriers.append(str(path.relative_to(root)))
    if scanned == 0:
        raise Bespredmetno(
            f"по составу из «{source}» не прочитано ни одного файла — перепись "
            f"второго объявления пуста, и это не «ноль находок»")
    if len(carriers) > 1:
        findings.append(
            f"ревизия оригинала объявлена в {len(carriers)} местах: "
            f"{', '.join(sorted(carriers))}. Второе место разойдётся с первым МОЛЧА — "
            f"копия сверялась бы с ревизией, из которой её не брали")
    elif carriers and carriers[0] != RECORD_REL:
        findings.append(
            f"ревизия оригинала объявлена в {carriers[0]}, а не в записи вендоринга "
            f"({RECORD_REL}) — у пина обязан быть один дом, и это дом записи")

    # ── ОСИ 3-8: провязка в описании процесса.
    workflow, parsers, cross = load_workflow(root)
    findings.extend(cross)
    jobs = workflow["jobs"]
    steps_seen = 0
    require_at: list[tuple[str, int, dict]] = []
    plain_at: list[tuple[str, int, dict]] = []
    for job_name, job in jobs.items():
        for idx, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            steps_seen += 1
            run = str(step.get("run") or "")
            if HOLDER_NAME in run:
                (require_at if REQUIRE_FLAG in run else plain_at).append((job_name, idx, step))
    if steps_seen == 0:
        raise Bespredmetno(f"{WORKFLOW_REL}: обход не дал ни одного шага")

    if not require_at:
        where = (f" (держателя зовут без него в задании «{plain_at[0][0]}»)"
                 if plain_at else "")
        findings.append(
            f"{WORKFLOW_REL}: ни один шаг не зовёт {HOLDER_NAME} с {REQUIRE_FLAG}{where} — "
            f"значит ось «оригинал ушёл вперёд» конвейером НЕ ИЗМЕРЯЕТСЯ, а её "
            f"неизмеренность даёт код 0 и неотличима от измеренной")

    # ── ОСЬ 7: КОД ДЕРЖАТЕЛЯ ДОЕЗЖАЕТ ДО ВЕРДИКТА ШАГА.
    #
    # Предмет — ПОСЛАБЛЕНИЕ `continue-on-error: true` у выборки чужого дерева. Оно
    # защитимо ровно тем, что отказ ловит шаг сверки ниже своим ненулевым кодом;
    # значит проглотить этот код нельзя ни шагу, ни развилке внутри него. Прежде
    # безобидность маски держалась ОДНОЙ строкой выхода в развилке шага, и не
    # держало её НИЧТО: снятие строки оставляло все утверждения зелёными и
    # возвращало ровно тот молчаливый проход, ради закрытия которого всё делалось.
    #
    # Предикат — БЕЛЫЙ СПИСОК, а не перечень запрещённых написаний: `run:` шага
    # сверки есть РОВНО ОДНА команда без перехвата кода и без развилки. Разбор
    # текста оболочки на «а этот `exit` в нужной ветке?» был бы гаданием; одна
    # команда под `bash -e` отдаёт код держателя BY CONSTRUCTION.
    for job_name, idx, step in require_at:
        if _truthy(step.get(CONTINUE_ON_ERROR)):
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}», шаг {idx}: ПОСЛАБЛЕНИЕ НА ШАГЕ "
                f"СВЕРКИ ({CONTINUE_ON_ERROR}) — ненулевой код держателя перестаёт "
                f"стоить заданию, и третий исход снова неотличим от прохода")
        run_lines = [ln for ln in str(step.get("run") or "").splitlines()
                     if ln.strip() and not ln.strip().startswith("#")]
        if len(run_lines) != 1:
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}», шаг {idx}: КОД ДЕРЖАТЕЛЯ НЕ "
                f"ДОЕЗЖАЕТ гарантированно — в шаге {len(run_lines)} команд(ы), и его "
                f"код зависит от того, как написана развилка. Шаг сверки обязан быть "
                f"одной командой: под `bash -e` она отдаёт код держателя сама")
        else:
            swallowed = [tok for tok in SWALLOWERS if tok in run_lines[0]]
            if swallowed:
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}», шаг {idx}: КОД ДЕРЖАТЕЛЯ НЕ "
                    f"ДОЕЗЖАЕТ — команда несёт {swallowed}, то есть перехватывает или "
                    f"подменяет код выхода")

        env = step.get("env") or {}
        run = str(step.get("run") or "")
        if UPSTREAM_ENV not in env and UPSTREAM_ENV not in run:
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}», шаг {idx}: сверка потребована, "
                f"а дерево не дано — {UPSTREAM_ENV} нет ни в env:, ни в run:. Такой шаг "
                f"выдаёт третий исход на КАЖДОМ прогоне, и его отключат")

        job_steps = [st for st in (jobs[job_name].get("steps") or []) if isinstance(st, dict)]
        by_id = {str(st.get("id")): st for st in job_steps if st.get("id")}
        checkouts = [(jdx, st.get("with") or {}) for jdx, st in enumerate(job_steps)
                     if str(st.get("uses") or "").startswith(CHECKOUT_ACTION)
                     and "repository" in (st.get("with") or {})]
        if not checkouts:
            findings.append(
                f"{WORKFLOW_REL}: задание «{job_name}»: сверка потребована, а шага "
                f"{CHECKOUT_ACTION} с repository: в задании нет — дерево оригинала браться "
                f"неоткуда, и «условие не создано» станет вечным исходом")
            continue
        for jdx, with_ in checkouts:
            for key in ("repository", "ref"):
                raw = str(with_.get(key, ""))
                ids = STEP_OUTPUT.findall(raw)
                if not ids:
                    if key == "repository" and raw == repo and repo:
                        # Литеральное имя репозитория — не пин: его не переставляют
                        # каждый день. Но и оно обязано совпадать с записью, иначе
                        # сверка шла бы с ЧУЖИМ деревом при сходящихся именах файлов.
                        continue
                    findings.append(
                        f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} «{raw or '—'}» — "
                        f"литерал, а не выражение из записи. Пин обязан читаться из "
                        f"{RECORD_REL} в прогоне: литерал здесь и есть второе место объявления")
                    continue
                for sid in ids:
                    producer = by_id.get(sid)
                    if producer is None:
                        findings.append(
                            f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} ссылается "
                            f"на шаг id «{sid}», которого в задании нет — подстановка выйдет пустой")
                    elif RECORD_REL not in str(producer.get("run") or ""):
                        findings.append(
                            f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: {key} берётся из "
                            f"шага «{sid}», который {RECORD_REL} НЕ ЧИТАЕТ — значит пин взят не "
                            f"из записи, и это второе место объявления за подстановкой")
            if not str(with_.get("path", "")).strip():
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: у выборки оригинала "
                    f"нет path: — чужое дерево легло бы в корень и затёрло рабочую копию службы")
            if jdx > idx:
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}»: выборка оригинала (шаг {jdx}) "
                    f"стоит ПОСЛЕ сверки (шаг {idx}) — сверять было бы нечего")

    # ── ОСЬ 8: ПОСЛАБЛЕНИЕ У ВЫБОРКИ ОРИГИНАЛА СПАРЕНО С ТЕМ, КТО ЛОВИТ ОТКАЗ.
    #
    # Стоит ВНЕ цикла по требующим шагам намеренно: послабление без ловящего — это
    # как раз тот мир, где требующего шага нет ни одного, и цикл по ним не прошёл
    # бы по нему ни разу. Область — только выборка ЧУЖОГО дерева (`repository:`):
    # послабление у соседнего шага про другой предмет судит не эта проба.
    for job_name, job in jobs.items():
        job_steps = [st for st in ((job or {}).get("steps") or []) if isinstance(st, dict)]
        for jdx, st in enumerate(job_steps):
            if not str(st.get("uses") or "").startswith(CHECKOUT_ACTION):
                continue
            if "repository" not in (st.get("with") or {}):
                continue
            if not _truthy(st.get(CONTINUE_ON_ERROR)):
                continue
            catcher = [i2 for (jn, i2, step2) in require_at
                       if jn == job_name and i2 > jdx
                       and not _truthy(step2.get(CONTINUE_ON_ERROR))]
            if not catcher:
                findings.append(
                    f"{WORKFLOW_REL}: задание «{job_name}», шаг {jdx}: ПОСЛАБЛЕНИЕ У "
                    f"ВЫБОРКИ ОРИГИНАЛА ({CONTINUE_ON_ERROR}), и НИКТО НИЖЕ НЕ ЛОВИТ "
                    f"ОТКАЗ — ниже нет шага, который требует сверки и сам под "
                    f"послаблением не стоит. Недостижимый оригинал стал бы "
                    f"молчаливым проходом")

    census = {"файлов осмотрено": scanned, "источник состава": source,
              "заданий": len(jobs), "шагов": steps_seen,
              "мест объявления ревизии": len(carriers),
              "шагов с требованием сверки": len(require_at),
              "разбор": parsers}
    return findings, census


def verdict(root: pathlib.Path) -> int:
    try:
        findings, census = judge(root)
    except Bespredmetno as exc:
        print(f"БЕСПРЕДМЕТНО: {exc}", file=sys.stderr)
        print("Это НЕ «ноль находок»: вердикта о провязке сверки нет вовсе.", file=sys.stderr)
        return 2
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if findings:
        print(f"НАХОДОК {len(findings)}:", file=sys.stderr)
        for f in findings:
            print(f"  · {f}", file=sys.stderr)
        return 1
    print("ЧИСТО: пин объявлен один раз, конвейер сверку ТРЕБУЕТ, дерево берётся "
          "по пину в подкаталог и раньше сверки.")
    return 0


# ─────────────────────────── доказательство способности упасть ───────────────

GOOD_WORKFLOW = """
name: e2e-newman
on:
  push:
    branches: [main]
jobs:
  suite:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: ревизия платформы
        id: vendor-pin
        run: jq -r .upstream.revision tests/newman/vendor-provenance.json >> "$GITHUB_OUTPUT"
      - uses: actions/checkout@v7
        with:
          repository: ${{ steps.vendor-pin.outputs.repo }}
          ref: ${{ steps.vendor-pin.outputs.revision }}
          path: upstream-kacho
      - name: вендоренный слой сходится с записью и с оригиналом
        env:
          KANAME_VENDOR_UPSTREAM: upstream-kacho
        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream
"""

REV_A = "a" * 40


def _build(root: pathlib.Path, *, revision: str = REV_A, repo: str = "PRO-Robotech/kacho",
           workflow: str | None = None, extra: dict[str, str] | None = None) -> None:
    (root / "tests/newman").mkdir(parents=True)
    (root / ".github/workflows").mkdir(parents=True)
    (root / RECORD_REL).write_text(json.dumps(
        {"upstream": {"repo": repo, "revision": revision},
         "files": [{"path": "tests/newman/kacholib/stems.sh"}]}, ensure_ascii=False), encoding="utf-8")
    body = GOOD_WORKFLOW if workflow is None else workflow
    (root / WORKFLOW_REL).write_text(body.replace("${REPO}", repo), encoding="utf-8")
    for rel, text in (extra or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")


FAILURES: list[str] = []
UNMET: list[tuple[str, str]] = []
PASSED = [0]
_MISSING = object()


def _plain(name: str, ok: bool, text: str) -> None:
    """Утверждение без прогона вердикта: о тексте, уже полученном выше."""
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if ok:
        PASSED[0] += 1
        return
    FAILURES.append(f"{name}: утверждение не сошлось")
    for line in text.splitlines()[:10]:
        print(f"    {line}")


def _unmet(name: str, why: str) -> None:
    """Третий исход у оси самопробы: условие не создано, и это не проход."""
    print(f"  НЕ ВЫПОЛНИЛОСЬ {name} — {why}")
    UNMET.append((name, why))


def _run_verdict(root: pathlib.Path) -> tuple[int, str]:
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = verdict(root)
    return rc, out.getvalue() + err.getvalue()


def _check(name: str, want: int, root: pathlib.Path, needle: str = "",
           absent: str = "") -> None:
    """Утверждение об исходе. `absent` — щуп того, чего в выводе быть НЕ ДОЛЖНО.

    Без `absent` утверждение о беспредметности принимает ЧУЖОЙ МИР: щуп
    «БЕСПРЕДМЕТНО» сходится и тогда, когда предмет на месте, а спросить нечем, —
    а это разные исходы, и второй есть третья категория.
    """
    rc, text = _run_verdict(root)
    ok = rc == want and (not needle or needle in text) and (not absent or absent not in text)
    print(f"  {'ok  ' if ok else 'FAIL'} {name} (код {rc})")
    if ok:
        PASSED[0] += 1
    if not ok:
        if rc != want:
            why = f"ожидался код {want}, получен {rc}"
        elif needle and needle not in text:
            why = f"в выводе нет «{needle}»"
        else:
            why = f"в выводе ЕСТЬ «{absent}», а его там быть не должно"
        FAILURES.append(f"{name}: {why}")
        for line in text.splitlines()[:10]:
            print(f"    {line}")


def _git_tree(root: pathlib.Path, tracked: tuple[str, ...]) -> bool:
    """Синтетическое дерево ПОД GIT: перепись второго объявления идёт по индексу.

    Возвращает False, когда git недоступен, — тогда оси, чей предмет сам индекс,
    не исполнялись, и это третий исход, а не проход.
    """
    import shutil
    import subprocess
    if shutil.which("git") is None:
        return False
    quiet = {"capture_output": True, "text": True, "timeout": 120, "check": True}
    subprocess.run(["git", "-C", str(root), "init", "-q"], **quiet)
    if tracked:
        subprocess.run(["git", "-C", str(root), "add", "--", *tracked], **quiet)
    return True


def self_test() -> int:
    import tempfile
    print("провязка сверки: доказательство способности упасть")
    with tempfile.TemporaryDirectory(prefix="kaname-vendor-wiring-") as tmp:
        base = pathlib.Path(tmp)

        # КОНТРОЛЬ: правильно провязанное дерево молчит. Без него всё ниже
        # зеленело бы на пробе, которая краснеет всегда.
        t = base / "control"; _build(t)
        _check("контроль: провязка на месте — код 0", 0, t, "ЧИСТО")

        t = base / "second-home"; _build(t, extra={"docs/wiring.md": f"пин {REV_A}\n"})
        _check("ревизия названа ВТОРЫМ местом — находка с обоими адресами", 1, t,
               "объявлена в 2 местах")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: второй файл есть, но ревизии не несёт — молчит.
        t = base / "second-home-twin"; _build(t, extra={"docs/wiring.md": "пин читается из записи\n"})
        _check("посторонний файл без ревизии — НЕ находка", 0, t, "ЧИСТО")

        t = base / "literal-ref"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "ref: ${{ steps.vendor-pin.outputs.revision }}", f"ref: {REV_A}"))
        _check("ref литералом — находка (и это второе место объявления)", 1, t, "литерал")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: repository литералом, равным записи, — НЕ находка.
        #    Имя репозитория не пин: его не переставляют, и второго значения у него
        #    в записи нет. Красное здесь означало бы запрет по форме, а не по делу.
        t = base / "literal-repo-twin"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "repository: ${{ steps.vendor-pin.outputs.repo }}", "repository: ${REPO}"))
        _check("repository литералом, равным записи — НЕ находка", 0, t, "ЧИСТО")

        #    А вот ЧУЖОЕ имя репозитория — находка: имена файлов сошлись бы, и
        #    сверка шла бы с чужим деревом молча.
        t = base / "alien-repo"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "repository: ${{ steps.vendor-pin.outputs.repo }}",
            "repository: PRO-Robotech/kaname"))
        _check("repository литералом, ЧУЖИМ записи — находка", 1, t, "литерал")

        #    ПИН ЗА ПОДСТАНОВКОЙ, НО НЕ ИЗ ЗАПИСИ: выражение ссылается на шаг,
        #    который записи не читает. Форма правильная, дом пина — второй.
        t = base / "expr-not-from-record"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            'run: jq -r .upstream.revision tests/newman/vendor-provenance.json >> "$GITHUB_OUTPUT"',
            'run: echo "revision=deadbeef" >> "$GITHUB_OUTPUT"'))
        _check("выражение из шага, который записи НЕ ЧИТАЕТ — находка", 1, t,
               "НЕ ЧИТАЕТ")

        #    И ссылка на шаг, которого в задании нет.
        t = base / "expr-dangling"
        _build(t, workflow=GOOD_WORKFLOW.replace("steps.vendor-pin.outputs.revision",
                                                 "steps.no-such-step.outputs.revision"))
        _check("выражение ссылается на несуществующий шаг — находка", 1, t,
               "которого в задании нет")

        t = base / "no-require"
        _build(t, workflow=GOOD_WORKFLOW.replace(" --require-upstream", ""))
        _check("держателя зовут БЕЗ требования сверки — находка", 1, t,
               "ни один шаг не зовёт")

        # КЛЮЧЕВАЯ ОСЬ: флаг стоит ТОЛЬКО в комментарии. Проверка подстрокой
        # зеленела бы здесь — то есть на собственном объяснении процесса.
        t = base / "flag-in-comment"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream",
            "        # сверка идёт с --require-upstream, см. шапку держателя\n"
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py"))
        _check("флаг только в КОММЕНТАРИИ — находка (читается разобранный YAML)", 1, t,
               "ни один шаг не зовёт")

        t = base / "no-env"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        env:\n          KANAME_VENDOR_UPSTREAM: upstream-kacho\n", ""))
        _check("сверка потребована, дерево не дано — находка", 1, t, "дерево не дано")

        t = base / "no-checkout"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}\n"
            "          ref: ${{ steps.vendor-pin.outputs.revision }}\n"
            "          path: upstream-kacho\n", ""))
        _check("выборки оригинала в задании нет — находка", 1, t, "браться неоткуда")

        t = base / "no-path"
        _build(t, workflow=GOOD_WORKFLOW.replace("          path: upstream-kacho\n", ""))
        _check("выборка без path: — находка (затёрла бы копию службы)", 1, t, "нет path:")

        t = base / "checkout-after"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}\n"
            "          ref: ${{ steps.vendor-pin.outputs.revision }}\n"
            "          path: upstream-kacho\n", "") + """      - uses: actions/checkout@v7
        with:
          repository: ${{ steps.vendor-pin.outputs.repo }}
          ref: ${{ steps.vendor-pin.outputs.revision }}
          path: upstream-kacho
""")
        _check("выборка ПОСЛЕ сверки — находка", 1, t, "стоит ПОСЛЕ сверки")

        t = base / "short-rev"; _build(t, revision="370c154d")
        _check("ревизия коротким хэшем — находка", 1, t, "не в форме полного хэша")

        t = base / "no-record"; _build(t); (t / RECORD_REL).unlink()
        _check("записи нет — код 2, а НЕ 1 и НЕ 0", 2, t,
               "записи вендоринга нет по адресу")

        #    ЩУП НАЗЫВАЕТ ПРЕДМЕТ, а не слово «БЕСПРЕДМЕТНО»: беспредметностей
        #    здесь пять, и одна из них — «описание есть, спросить нечем». Щуп по
        #    слову сходился бы на любой из пяти, то есть принимал бы ЧУЖОЙ МИР.
        t = base / "no-workflow"; _build(t); (t / WORKFLOW_REL).unlink()
        _check("описания процесса нет — код 2", 2, t,
               "описания процесса нет по адресу", absent="разбор")

        t = base / "no-steps"
        _build(t, workflow="name: x\njobs:\n  suite:\n    runs-on: ubuntu-latest\n    steps: []\n")
        _check("обход не дал ни одного шага — код 2, а НЕ 0", 2, t, "ни одного шага")

        # ── ОСЬ: ЗАПИСЬ НЕ НАЗЫВАЕТ РЕПОЗИТОРИЙ ОРИГИНАЛА. Шапка обещала форму
        #    пина ДВУМЯ полями, а держалась одна: снятие проверки `repo` не ронял
        #    ни одного из 18 утверждений.
        t = base / "no-repo"; _build(t, repo="")
        _check("запись без repo оригинала — находка", 1, t,
               "не называет репозиторий оригинала")

        # ── ОСЬ: ПИН ОБЪЯВЛЕН ОДИН РАЗ, НО НЕ В ЗАПИСИ. Вторая половина оси 2, и
        #    она держалась тем же ничем. Предмет — ОТСЛЕЖИВАЕМЫЙ состав: запись
        #    вне индекса объявляет пин там, где его никто не версионирует.
        t = base / "pin-not-at-home"
        _build(t, extra={"docs/wiring.md": f"пин {REV_A}\n"})
        if _git_tree(t, ("docs/wiring.md", WORKFLOW_REL)):
            _check("пин объявлен вне записи (запись не отслеживается) — находка", 1, t,
                   "а не в записи вендоринга")
        else:
            _unmet("пин объявлен вне записи", "git недоступен")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: та же раскладка, но запись ОТСЛЕЖИВАЕТСЯ — молчит,
        #    и перепись называет источник состава индексом, а не обходом ФС.
        t = base / "pin-at-home-twin"; _build(t)
        if _git_tree(t, (RECORD_REL, WORKFLOW_REL)):
            _check("пин в отслеживаемой записи — НЕ находка", 0, t,
                   "источник состава индекс git")
        else:
            _unmet("пин в отслеживаемой записи", "git недоступен")

        # ── ОСЬ: ПУСТОЙ ОБХОД — тот самый страж «ноль находок при ноль
        #    прочитанного». Его снятие тоже не ронял ни одного утверждения.
        t = base / "empty-index"; _build(t)
        if _git_tree(t, ()):
            _check("по индексу ноль файлов — код 2, а НЕ 0", 2, t,
                   "не прочитано ни одного файла")
        else:
            _unmet("пустой обход", "git недоступен")

        # ── ОСЬ: КОД ДЕРЖАТЕЛЯ ДОЕЗЖАЕТ ДО ВЕРДИКТА ШАГА.
        #    Предмет — МАСКА `continue-on-error` у выборки оригинала. Она защитима
        #    ровно тем, что отказ ловит шаг сверки ниже; а ловит он его одной
        #    строкой выхода в развилке, которую не держало НИЧТО. Снятие той строки
        #    возвращало молчаливый проход, ради закрытия которого всё и делалось.
        t = base / "swallowed-rc"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream",
            "        run: |\n"
            "          rc=0\n"
            "          python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream || rc=$?\n"
            "          case \"$rc\" in\n"
            "            3) echo \"третий исход\" ;;\n"
            "          esac"))
        _check("шаг сверки перехватывает код держателя — находка", 1, t,
               "КОД ДЕРЖАТЕЛЯ НЕ ДОЕЗЖАЕТ")

        # ── ОСЬ: ПОСЛАБЛЕНИЕ НА САМОМ ШАГЕ СВЕРКИ. Тогда ненулевой код держателя
        #    задания не роняет, и третий исход снова неотличим от прохода.
        t = base / "masked-verdict"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - name: вендоренный слой сходится с записью и с оригиналом",
            "      - name: вендоренный слой сходится с записью и с оригиналом\n"
            "        continue-on-error: true"))
        _check("послабление на шаге сверки — находка", 1, t,
               "ПОСЛАБЛЕНИЕ НА ШАГЕ СВЕРКИ")

        # ── ОСЬ: ПОСЛАБЛЕНИЕ У ВЫБОРКИ, ЗА КОТОРЫМ НИКТО НЕ ЛОВИТ ОТКАЗ.
        t = base / "mask-unpaired"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}",
            "      - uses: actions/checkout@v7\n        continue-on-error: true\n"
            "        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}").replace(
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream",
            "        run: echo сверки нет"))
        _check("послабление у выборки, а сверки ниже нет — находка", 1, t,
               "ПОСЛАБЛЕНИЕ У ВЫБОРКИ ОРИГИНАЛА")

        #    ЗАКОННЫЙ БЛИЗНЕЦ: послабление есть, и сверка ниже его ловит — молчит.
        t = base / "mask-paired-twin"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "      - uses: actions/checkout@v7\n        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}",
            "      - uses: actions/checkout@v7\n        continue-on-error: true\n"
            "        with:\n"
            "          repository: ${{ steps.vendor-pin.outputs.repo }}"))
        _check("послабление, спаренное со сверкой ниже — НЕ находка", 0, t, "ЧИСТО")

        # ── ОСЬ: ВЕРДИКТ ЕСТЬ И БЕЗ pyyaml. Пробу зовёт общий прогонщик, у
        #    которого третьего исхода для гейта нет: любой ненулевой код он считает
        #    красным. Обязательная зависимость означала бы КРАСНОЕ О ДЕРЕВЕ там, где
        #    вердикта нет вовсе.
        t = base / "no-pyyaml"; _build(t)
        saved = sys.modules.get("yaml", _MISSING)
        sys.modules["yaml"] = None
        try:
            _check("pyyaml нет, а вердикт ЕСТЬ — код 0", 0, t, "ЧИСТО")
            rc_lite, text_lite = _run_verdict(t)
        finally:
            if saved is _MISSING:
                del sys.modules["yaml"]
            else:
                sys.modules["yaml"] = saved
        _plain("и перепись называет сверку разборщиков НЕ ВЫПОЛНЕННОЙ",
               "сверка разборщиков НЕ ВЫПОЛНЕНА" in text_lite, text_lite)

        # ── ОСЬ: СВЕРКА ДВУХ РАЗБОРЩИКОВ — и её способность упасть.
        #    Предмет оси — САМ ВТОРОЙ РАЗБОРЩИК, поэтому без него оси нет: это
        #    третий исход, а не красное. Красным он был бы утверждением о дереве
        #    там, где не создано условие.
        try:
            import yaml as _second                       # noqa: F401 — проверка наличия
            second_parser = True
        except ImportError:
            second_parser = False

        if not second_parser:
            _unmet("сверка двух разборщиков", "pyyaml нет — сверять не с чем")
            _unmet("разборщики разошлись — находка", "pyyaml нет — сверять не с чем")
        else:
            t = base / "parsers-agree"; _build(t)
            rc_both, text_both = _run_verdict(t)
            _plain("при обоих разборщиках сверка ВЫПОЛНЕНА и названа",
                   rc_both == 0 and "сверка разборщиков выполнена" in text_both, text_both)

            t = base / "parsers-diverge"; _build(t)
            original = globals().get("_parse_workflow_lite")
            if original is None:
                _plain("разборщики разошлись — находка, а не молчание", False,
                       "своего разбора нет: функции _parse_workflow_lite не существует")
            else:
                def _parse_short(text: str) -> dict:
                    doc = original(text)
                    doc["jobs"]["suite"]["steps"] = doc["jobs"]["suite"]["steps"][:1]
                    return doc

                globals()["_parse_workflow_lite"] = _parse_short
                try:
                    _check("разборщики разошлись — находка, а не молчание", 1, t,
                           "РАЗБОРЩИКИ РАЗОШЛИСЬ")
                finally:
                    globals()["_parse_workflow_lite"] = original

        # ── ОСЬ: РАЗБОР ОТКАЗЫВАЕТСЯ УГАДЫВАТЬ. Узел, которого он не знает, даёт
        #    беспредметность с ИМЕНЕМ узла — а не тихий разбор наугад и не
        #    сообщение про отсутствующее описание.
        t = base / "folded-scalar"
        _build(t, workflow=GOOD_WORKFLOW.replace(
            "        run: python3 tests/newman/scripts/vendor_provenance_test.py --require-upstream",
            "        run: >\n          python3 tests/newman/scripts/vendor_provenance_test.py\n"
            "          --require-upstream"))
        _check("узел, не поддержанный разбором — код 2 с именем узла", 2, t,
               "свёрнутый блочный скаляр", absent="описания процесса нет")

    print(f"\nутверждений {len(FAILURES) + PASSED[0]} · провалено {len(FAILURES)} · "
          f"НЕ ВЫПОЛНИЛОСЬ {len(UNMET)}")
    if UNMET:
        for name, why in UNMET:
            print(f"  НЕ ВЫПОЛНИЛОСЬ: {name} — {why}", file=sys.stderr)
        print("Это третий исход: он не зачтён в проход и не назван красным.",
              file=sys.stderr)
    if FAILURES:
        print(f"ПРОВАЛЕНО утверждений: {len(FAILURES)}", file=sys.stderr)
        for f in FAILURES:
            print(f"  · {f}", file=sys.stderr)
        return 1
    if UNMET:
        return 2
    print("ВСЕ утверждения сошлись: проба провязки падает там, где должна, "
          "и молчит на законных близнецах.")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    return verdict(REPO)


if __name__ == "__main__":
    sys.exit(main())
