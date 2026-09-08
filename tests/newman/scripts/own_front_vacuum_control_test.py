#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: утверждения о НЕОТЛИЧИМОСТИ не зеленеют на пустом множестве.

ПРЕДМЕТ
-------
Набор `kaname-own-rest-front` несёт утверждения-отрицания: «побайтово тот же
отказ», «неотличимо от „нет такой“», «ответ не сообщает, существует ли объект»,
«субъект не тот, кем вызывающий назвал себя», «запрос НЕ обслужен». Все они
**истинны тривиально** в мире, где всякий ответ полосы обработчика есть один и
тот же отказ: различать нечего, потому что не различается ничто.

Такое утверждение занимает слот и создаёт уверенность, которой нет. Опаснее
сегодняшнего состояния завтрашнее: когда полоса начнёт отвечать различимо, эти
утверждения перевернутся МОЛЧА — либо покраснеют по чужому предмету, либо
останутся зелёными по новой причине, и никто не заметит, что мерили другое.

ЧТО УТВЕРЖДАЕТСЯ
----------------
У каждого такого отрицания обязан стоять ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — наблюдение,
различимое на ТОЙ ЖЕ поверхности, — так что отрицание перестаёт выполняться на
пустом множестве. Проверяется это не чтением текста, а ИСХОДОМ: тот самый
JavaScript из порождённой коллекции исполняется настоящим движком под тремя
мирами.

  W_today   — маршрутизатор различает (промах пути → 404 `Not Found`, чужой
              метод → 501), а всё, что доходит до обработчика, отвечает ОДНИМ И
              ТЕМ ЖЕ отказом независимо от удостоверения и объекта. Это
              состояние стенда, снятое с прогона: тело — чистая функция
              вызванного метода, от объекта и строки запроса не зависит.
              Утверждения о неотличимости обязаны ПАДАТЬ.
  W_hiding  — поверхность обслуживает законный запрос и при этом прячет
              существование: два негодных удостоверения дают побайтово равный
              отказ, чужой объект неотличим от отсутствующего. Обязаны ПРОХОДИТЬ.
  W_leak(T) — W_hiding, где изменён РОВНО ОДИН ответ так, что свойство нарушено.
              Обязано падать РОВНО одно утверждение — то, чьё свойство нарушено.

Три мира, а не два. Без W_today «умеет падать» неотличимо от «падает всегда»;
без W_hiding «падает» неотличимо от «мертво»; без W_leak «зелено» неотличимо от
«не смотрит».

ПОЛНОТА РАСПОЗНАВАТЕЛЯ — ПЕРЕПИСЬЮ, А НЕ СЛОВАРЁМ
--------------------------------------------------
Цели не отбираются по словам («неотличимо», «побайтово»): слово — не предмет.
Предмет — ПОВЕДЕНИЕ: утверждение, проходящее в W_today, о своём свойстве не
свидетельствует. Поэтому объявлено, какие утверждения всей коллекции вправе
проходить в W_today (наблюдения о маршрутизаторе, о том, что ответ вообще
получен, и о принадлежности отказа производимому множеству), и всякое НОВОЕ
прошедшее — находка: либо честное наблюдение (внести в перечень с причиной),
либо вакуум (поставить контроль). Запись, которой больше нечего прощать, —
тоже находка: послабление истекает само.

ПОЧЕМУ ИСПОЛНЕНИЕ, А НЕ РАЗБОР ТЕКСТА. Гейт по образцу нашёл бы слово «контроль»
в комментарии, объясняющем контроль, и остался бы зелёным при снятом контроле.
Движок отвечает на другой вопрос: упадёт ли утверждение там, где обязано.

Способность гейта упасть и смолчать доказывает
`own_front_vacuum_control_injection_test.py`.

КТО ЭТУ ПРОБУ ИСПОЛНЯЕТ — ПУТЕЙ ДВА, И ВТОРОЙ НЕ ОЧЕВИДЕН.

Первый — `.github/scripts/run-python-probes.py`: состав он собирает ОБХОДОМ
дерева по образцу `services/*/tests/newman/scripts/*_test.py` и ни один файл проб
по имени не называет, поэтому отдельного шага в конвейере файл не требует. Вид
здесь «гейт со своим main»: прогон отдельным процессом, вердикт — код выхода.
Проводку держит `tools/pythonprobes`.

Второй — ИМПОРТ ПО ИМЕНИ из `own_front_vacuum_control_injection_test.py`: она
кладёт свой каталог в `sys.path` и делает `import ... as gate`, обращаясь к
модулю 22 раза (`gate.audit` 7, `gate.HONEST_IN_W_TODAY` 7, `gate.TARGETS` 4,
`gate.run_world` 2, `gate.VerdictHasNoSubject` и `gate.COLLECTION` по одному).
Инъекционная проба попадает в ТОТ ЖЕ обход, поэтому за один прогон тело ЭТОГО
модуля исполняется дважды и в разных процессах: как `__main__` (свой прогон,
зовётся `main()`) и как импортируемый модуль — только тело, `main()` закрыт
`if __name__ == "__main__"` внизу файла.

Следствие, которого у соседа нет: ПЕРЕИМЕНОВАНИЕ ИЛИ ПЕРЕНОС ЭТОГО ФАЙЛА ЛОМАЕТ
ИНЪЕКЦИОННУЮ ПРОБУ, а с ней — доказательство, что гейт способен упасть.
Проверяется копией инъекционной пробы вне этого каталога: `ModuleNotFoundError`,
код 1.

Поэтому предикат `git grep` по имени ЭТОГО файла здесь НЕ бесполезен — он
находит живую зависимость, а не одну прозу. Замер 2026-09-07 на `4df215f7f`
+ эта правка: 5 попаданий в 3 файлах, из них ВЫЗОВ один (импорт выше) и ПРОЗА
четыре — `docs/RESULTS.md`, `cases/kaname-own-rest-front.py` дважды и шапка
инъекционной пробы.
"""

import json
import pathlib
import shutil
import subprocess
import sys

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
COLLECTION = NEWMAN / "collections" / "kaname-own-rest-front.postman_collection.json"

# ── Опорные значения окружения ─────────────────────────────────────────────
# Идентификаторы — в форме продукта (префикс типа + crockford-base32): утверждения
# нормализуют их по префиксу (`/acc[0-9a-z]+/`, `/iop[0-9a-z]+/`), и подделка вида
# 'AAA' прошла бы мимо нормализации, сделав фикстуру снисходительнее продукта.
ACCOUNT_A = "accaaaaaaaaaaaaaaaa1"
ACCOUNT_B = "accbbbbbbbbbbbbbbbb2"
ACCOUNT_ABSENT = "accdeadbeefdeadbeef0"
USER_A = "usraaaaaaaaaaaaaaaa1"
# Личность ПРЕДЪЯВИТЕЛЯ служебной учётки: `svaAId` ↔ `jwtSAA` — объявленная пара
# (`tests/authz-fixtures/principal_pairings.py`). `USER_A` остаётся целью
# привязки и предъявителем НЕ бывает by construction.
SVA_A = "svaaaaaaaaaaaaaaaaa1"
OP_OWN = "iopownownownownown01"
OP_ABSENT = "iopdeadbeefdeadbeef00"

ENV_SEED = {
    "existingAccountId": ACCOUNT_A,
    "accountBId": ACCOUNT_B,
    "userAAAId": USER_A,
    "svaAId": SVA_A,
    "ownRestOpId": OP_OWN,
    "runId": "r1",
    "ownRestBaseUrl": "http://127.0.0.1:1/own",
    "ownInternalRestBaseUrl": "http://127.0.0.1:1/own-internal",
}


def _j(obj):
    """Каноничный JSON — тот же, что даёт `JSON.stringify` движка.

    Утверждения набора сравнивают `pm.response.text()` с `JSON.stringify(j)`;
    расхождение в пробелах сделало бы фикстуру строже продукта и покрасило бы то,
    что на стенде зелено.
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


MUX_MISS = (404, _j({"code": 5, "message": "Not Found", "details": []}))
METHOD_MISS = (501, _j({"code": 12, "message": "Method Not Allowed", "details": []}))
# Единственный отказ полосы обработчика — ровно то, что отдаёт стенд сегодня.
ONE_REFUSAL = (403, _j({"code": 7, "message": "permission denied", "details": []}))
CRED_REFUSAL = (401, _j({"code": 16, "message": "credential is not accepted", "details": []}))

# Маршрутизатор различает и сегодня: промах пути и чужой метод — разные ответы.
# Поэтому W_today НЕ «всё одинаково»: одинакова полоса ОБРАБОТЧИКА, и вакуум
# живёт именно там.
ROUTER_LANE = {
    "internal-path-on-public-front": MUX_MISS,
    "nonsense-path-on-own-front": MUX_MISS,
    "known-path-wrong-method": METHOD_MISS,
}

# Отказ полосы ПРАВКИ. Скрытие существования включается поимённо и на правку
# аккаунта не распространяется (`pkg/authz`, `HidesExistenceOnDeny`), поэтому
# отказ приходит СВОИМ кодом, а не кодом промаха, — и по построению не несёт
# идентификатора, то есть одинаков для чужого объекта и для отсутствующего.
MUT_REFUSAL = (403, _j({"code": 7, "message": "permission denied", "details": []}))

W_HIDING = {
    **ROUTER_LANE,
    "internal-path-on-internal-front": ONE_REFUSAL,
    "own-public-front-serves-rest": (200, _j({"id": ACCOUNT_A, "name": "acct-a",
                                              "createdAt": "2026-01-01T00:00:00Z"})),
    "malformed-credential": CRED_REFUSAL,
    "expired-shaped-credential": CRED_REFUSAL,
    "bare-and-bridged-principal-headers": (200, _j({"subject": f"service_account:{SVA_A}",
                                                    "userId": "", "displayName": "ps-sa-a"})),
    "garbage-cursor-granted-caller": (400, _j({"code": 3, "message": "invalid page token", "details": []})),
    "garbage-cursor-ungranted-caller": (400, _j({"code": 3, "message": "invalid page token", "details": []})),
    "create-group-through-own-front": (200, _j({"id": OP_OWN, "done": False})),
    "poll-operation-on-the-same-front": (200, _j({"id": OP_OWN, "done": True})),
    "read-foreign-account": (404, _j({"code": 5, "message": f"Account {ACCOUNT_B} not found", "details": []})),
    "read-absent-account": (404, _j({"code": 5, "message": f"Account {ACCOUNT_ABSENT} not found", "details": []})),
    "no-credential-at-all": CRED_REFUSAL,
    "page-size-over-max-granted": (400, _j({"code": 3, "message": "page_size must be in [0..1000]", "details": []})),
    "page-size-over-max-ungranted": (400, _j({"code": 3, "message": "page_size must be in [0..1000]", "details": []})),
    "page-size-legal-is-served": (200, _j({"accounts": [], "nextPageToken": ""})),
    "poll-absent-operation": (404, _j({"code": 5, "message": f"Operation {OP_ABSENT} not found", "details": []})),
    "poll-someone-elses-operation": (404, _j({"code": 5, "message": f"Operation {OP_OWN} not found", "details": []})),
    "patch-foreign-account": MUT_REFUSAL,
    "patch-absent-account": MUT_REFUSAL,
    "foreign-account-unchanged": (200, _j({"id": ACCOUNT_B, "name": "acct-b",
                                           "createdAt": "2026-01-01T00:00:00Z"})),
}

# Отказ, ЭХОМ выдающий существование объекта: отметка создания в теле отказа.
_LEAK_ECHO = [{"account": {"createdAt": "2026-01-01T00:00:00Z"}}]

# Цели: (шаг, утверждение) → ответ, в котором свойство НАРУШЕНО. Подмена меняет
# РОВНО ОДИН ответ: иначе «упало проверяемое» неотличимо от «упал сосед».
TARGETS = {
    ("expired-shaped-credential",
     "BAD-CRED: второй негодный предъявитель даёт ПОБАЙТОВО тот же отказ"):
        (401, _j({"code": 16, "message": "credential is expired", "details": []})),

    ("bare-and-bridged-principal-headers",
     "SELF-NAMED: и НЕ тот, кем вызывающий назвал себя заголовком — ни голой формой, ни мостовой"):
        (200, _j({"subject": "user:usr-someone-else", "userId": "usr-someone-else",
                  "displayName": "someone"})),

    ("read-absent-account",
     "FOREIGN: «есть, но не твой» и «нет такого» различаются ТОЛЬКО идентификатором "
     "в тексте — иначе ответ служил бы оракулом существования"):
        (404, _j({"code": 5, "message": "Account not found", "details": []})),

    ("no-credential-at-all", "ANON: запрос НЕ обслужен"):
        (200, _j({})),

    ("no-credential-at-all", "ANON: ответ не сообщает, существует ли запрошенный объект"):
        (401, _j({"code": 16, "message": "credential is not accepted", "details": _LEAK_ECHO})),

    ("poll-someone-elses-operation",
     "FOREIGN-OP: «есть, но не твоя» неотличимо от «нет такой» — предикат владения "
     "стоит доводом ЗАПРОСА, поэтому чужая строка не читается вовсе"):
        (404, _j({"code": 5, "message": "operation belongs to another account", "details": []})),

    # ЦЕЛЬ НА ПОЛОСЕ ПРАВКИ ОДНА, И ЭТО РЕШЕНИЕ, А НЕ УПУЩЕНИЕ.
    #
    # Прежде цель стояла на утверждении «в отказе нет отметки создания» того же
    # шага. Оно осталось в наборе и по-прежнему несёт свой контроль, но целью
    # быть перестало: утверждение о РАВЕНСТВЕ двух отказов строго сильнее —
    # отметку создания отказ на ОТСУТСТВУЮЩИЙ объект нести не может вовсе,
    # поэтому её утечка в отказ на чужой ломает равенство и ловится здесь же.
    #
    # Две цели на этой полосе несовместимы ПО ПОСТРОЕНИЮ: соседний шаг читает
    # тело этого, поэтому инъекция в него роняет и его утверждение — и «упало
    # проверяемое» становится неотличимо от «упал сосед», то есть ровно тем, что
    # правило `collateral` ниже и запрещает.
    ("patch-absent-account",
     "FOREIGN-MUT: «есть, но не твой» и «нет такого» неотличимы на маршруте ПРАВКИ — "
     "иначе отказ служил бы оракулом существования"):
        (404, _j({"code": 5, "message": f"Account {ACCOUNT_ABSENT} not found", "details": []})),
}

# Утверждения, которым в W_today проходить ПОЛОЖЕНО, и причина по каждому. Всякое
# иное прошедшее — находка. Ключ — ПАРА (шаг, утверждение): один заголовок
# («status 404») стоит в разных шагах и означает в них разное.
HONEST_IN_W_TODAY = {
    ("internal-path-on-public-front", "status 404"):
        "промах маршрутизатора отличается от ответа полосы обработчика — наблюдение, а не умолчание",
    ("internal-path-on-public-front",
     "INT-ON-PUB: grpc code 5 (необходимое условие, но НЕ различитель — его несёт и промах "
     "маршрутизатора, и сокрытие существования)"): "то же",
    ("internal-path-on-public-front",
     "INT-ON-PUB: это промах МАРШРУТИЗАТОРА — голый Not Found без имени ресурса; ответ "
     "владельца назвал бы ресурс и идентификатор"): "то же",
    ("nonsense-path-on-own-front", "status 404"): "то же",
    ("nonsense-path-on-own-front",
     "UNKNOWN-PATH: grpc code 5 (необходимое условие, но НЕ различитель — его несёт и промах "
     "маршрутизатора, и сокрытие существования)"): "то же",
    ("nonsense-path-on-own-front",
     "UNKNOWN-PATH: это промах МАРШРУТИЗАТОРА — голый Not Found без имени ресурса; ответ "
     "владельца назвал бы ресурс и идентификатор"): "то же",
    ("known-path-wrong-method", "status 501"):
        "чужой метод отвечает своим статусом — различимо от всего прочего на этой поверхности",
    ("known-path-wrong-method",
     "METHOD-MISMATCH: grpc code 12 — это отказ МАРШРУТИЗАТОРА, а не обработчика"): "то же",
    ("known-path-wrong-method",
     "METHOD-MISMATCH: и НЕ 405 — такого статуса край не производит ни при каком входе"):
        "отрицание при ПРОХОДЯЩЕМ положительном близнеце (status 501) в том же шаге",
    ("internal-path-on-internal-front",
     "INT-ON-INT: request was ANSWERED (a check that did not run is not a check that passed)"):
        "страж живости: ответ действительно получен",
    ("no-credential-at-all",
     "ANON: request was ANSWERED (a check that did not run is not a check that passed)"): "то же",
    ("internal-path-on-internal-front",
     "INT-ON-INT: путь на внутреннем фронте НЕ отвечает промахом маршрутизатора — значит 404 "
     "на публичном произведён отсутствием маршрута, а не отсутствием службы"):
        "отказ полосы обработчика доказывает, что путь смаршрутизирован: до обработчика "
        "доходит только смаршрутизированное",
    ("no-credential-at-all", "ANON: отказ принадлежит производимому множеству"):
        "принадлежность множеству — положительное наблюдение об отказе, а не отрицание",
    ("patch-foreign-account", "status 403"):
        "пара «статус + код» ПИНИТ КОНТРАКТ отказа на правку, а не утверждает неотличимость. "
        "На этой полосе отказ по правам и есть единственный ответ обработчика, поэтому пара "
        "совпадает с W_today by construction; различительную работу несёт равенство двух "
        "отказов в шаге `patch-absent-account`, и оно в W_today падает",
    ("patch-foreign-account", "FOREIGN-MUT: grpc code 7"): "то же",
}

# ── Движок ─────────────────────────────────────────────────────────────────
# Подмена `pm` СТРУКТУРНО не способна промолчать: неизвестный член цепочки chai
# бросает, а не возвращает `undefined`, и прогон без единого исполненного
# утверждения — отказ. Подделка, которой проверяют исход, обязана быть не
# снисходительнее продукта.
DRIVER = r"""
const job = JSON.parse(process.argv[1]);
class AssertionError extends Error {}
function deepEqual(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
function typeOf(v) { return v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v; }
function includes(hay, needle) {
  if (typeof hay === 'string') return hay.indexOf(String(needle)) !== -1;
  if (Array.isArray(hay)) return hay.some(v => deepEqual(v, needle));
  throw new Error('shim: include over ' + typeOf(hay));
}
const CHAIN = new Set(['to', 'be', 'and', 'have', 'that', 'with', 'is', 'which']);
function expectOf(actual, msg) {
  const st = { neg: false };
  function verdict(ok, what) {
    const want = !st.neg;
    st.neg = false;
    if (ok !== want) {
      throw new AssertionError(
        (want ? 'expected ' : 'expected NOT ') + what +
        ' | actual=' + JSON.stringify(actual) + (msg === undefined ? '' : ' | ' + String(msg)));
    }
  }
  const api = {
    eql: (e) => (verdict(deepEqual(actual, e), 'eql ' + JSON.stringify(e)), proxy),
    equal: (e) => (verdict(deepEqual(actual, e), 'equal ' + JSON.stringify(e)), proxy),
    a: (t) => (verdict(typeOf(actual) === t, 'a(' + t + ')'), proxy),
    an: (t) => (verdict(typeOf(actual) === t, 'an(' + t + ')'), proxy),
    include: (x) => (verdict(includes(actual, x), 'include ' + JSON.stringify(x)), proxy),
    property: (p) => (verdict(actual !== null && actual !== undefined &&
      Object.prototype.hasOwnProperty.call(actual, p), 'property ' + p), proxy),
    oneOf: (arr) => (verdict(arr.some(v => deepEqual(actual, v)), 'oneOf ' + JSON.stringify(arr)), proxy),
    match: (re) => (verdict(re.test(String(actual)), 'match ' + re), proxy),
  };
  const GETTERS = {
    not: () => { st.neg = !st.neg; return proxy; },
    empty: () => { verdict(actual === '' || actual === null || actual === undefined ||
      (Array.isArray(actual) && actual.length === 0), 'empty'); return proxy; },
  };
  const proxy = new Proxy({}, {
    get(_, k) {
      if (typeof k === 'symbol') return undefined;
      if (CHAIN.has(k)) return proxy;
      if (k in GETTERS) return GETTERS[k]();
      if (k in api) return api[k];
      throw new Error('shim: неизвестный член chai ' + String(k) +
        ' — подделка обязана бросать, а не молчать');
    },
  });
  return proxy;
}
const env = Object.assign({}, job.env);
const out = [];
let executed = 0;
for (const item of job.items) {
  const resp = { code: item.code, text: () => item.body, json: () => JSON.parse(item.body) };
  const pm = {
    response: new Proxy(resp, { get(t, k) {
      if (typeof k === 'symbol') return undefined;
      if (k in t) return t[k];
      throw new Error('shim: неизвестный член pm.response ' + String(k));
    } }),
    environment: {
      get: (k) => (Object.prototype.hasOwnProperty.call(env, k) ? env[k] : undefined),
      set: (k, v) => { env[k] = String(v); },
      unset: (k) => { delete env[k]; },
      has: (k) => Object.prototype.hasOwnProperty.call(env, k),
    },
    variables: {
      get: (k) => env[k],
      replaceIn: (s) => String(s).replace(/\{\{(\w+)\}\}/g, (_, n) => (env[n] === undefined ? '' : env[n])),
    },
    info: { requestName: item.name },
    execution: { setNextRequest: () => {}, skipRequest: () => {} },
    request: { headers: { upsert: () => {} }, url: '' },
    test: (name, fn) => {
      executed += 1;
      try { fn(); out.push({ item: item.name, name, passed: true, error: '' }); }
      catch (e) { out.push({ item: item.name, name, passed: false, error: String((e && e.message) || e) }); }
    },
  };
  pm.expect = (a, m) => expectOf(a, m);
  pm.expect.fail = (m) => { throw new AssertionError(String(m)); };
  try { new Function('pm', item.script)(pm); }
  catch (e) {
    out.push({ item: item.name, name: '<скрипт шага>', passed: false,
      error: 'скрипт упал вне утверждения: ' + String((e && e.message) || e) });
  }
}
process.stdout.write(JSON.stringify({ results: out, executed }));
"""


class VerdictHasNoSubject(Exception):
    """Вердикт не о дереве: исполнить нечем либо исполнять нечего."""


def collection_items(doc):
    """Шаги коллекции с их тест-скриптами — вход берётся ПОРОЖДЁННЫЙ."""

    def walk(nodes):
        for node in nodes:
            if "item" in node:
                yield from walk(node["item"])
            else:
                yield node

    # Имя элемента коллекции — «<case-id> :: <шаг>»; ключом берётся ШАГ: миры и
    # цели объявляются по шагу, а не по идентификатору кейса, который у соседних
    # шагов один и тот же.
    return [(n["name"].split(" :: ")[-1], "\n".join(
        next((e["script"]["exec"] for e in n.get("event", []) if e.get("listen") == "test"), [])))
        for n in walk(doc["item"])]


def run_world(items, world):
    """Исполнить тест-скрипты настоящим движком под данным миром."""
    if shutil.which("node") is None:
        raise VerdictHasNoSubject(
            "node не найден: исполнить порождаемый JavaScript нечем. Это «ноль "
            "прочитанного», а не «ноль находок»")
    unknown = [n for n, _ in items if n not in world]
    if unknown:
        raise VerdictHasNoSubject(
            f"мир не описывает ответы шагам {unknown} — вердикт был бы о части набора")
    job = {"env": ENV_SEED,
           "items": [{"name": n, "script": s, "code": world[n][0], "body": world[n][1]}
                     for n, s in items]}
    proc = subprocess.run(["node", "-e", DRIVER, json.dumps(job, ensure_ascii=False)],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        raise VerdictHasNoSubject(f"движок отказал: {proc.stderr[-2000:]}")
    data = json.loads(proc.stdout)
    if data["executed"] == 0:
        raise VerdictHasNoSubject("исполнено ноль утверждений — вердикт беспредметен")
    return {(r["item"], r["name"]): r for r in data["results"]}


def audit(doc):
    """Судящая функция. Возвращает (перепись, находки)."""
    census, findings = {}, []
    items = collection_items(doc)
    census["шагов"] = len(items)
    if not items:
        raise VerdictHasNoSubject("в коллекции ноль шагов — вердикт беспредметен")

    world_today = {name: ROUTER_LANE.get(name, ONE_REFUSAL) for name, _ in items}

    hiding = run_world(items, W_HIDING)
    today = run_world(items, world_today)
    census["утверждений"] = len(hiding)
    census["целей объявлено"] = len(TARGETS)
    census["прошло в W_today"] = sum(1 for r in today.values() if r["passed"])
    census["прошло в W_hiding"] = sum(1 for r in hiding.values() if r["passed"])

    # 0. Цель, потерявшая своё утверждение, — находка, а не молчание.
    lost = [key for key in TARGETS if key not in hiding]
    for key in lost:
        findings.append(
            f"цель {key!r} не найдена в коллекции: утверждение переименовано или снято, "
            f"а гейт продолжал бы зеленеть")
    live = [key for key in TARGETS if key not in lost]

    # 1. W_today — утверждение о неотличимости обязано ПАДАТЬ.
    for key in live:
        if today[key]["passed"]:
            findings.append(
                f"{key[0]} / {key[1]!r}: ПРОШЛО в мире, где всякий ответ полосы обработчика "
                f"один и тот же. Утверждение об одинаковости тривиально истинно там, где "
                f"одинаково всё; рядом обязан стоять положительный контроль — наблюдение, "
                f"различимое на ТОЙ ЖЕ поверхности")

    # 2. W_hiding — обязано ПРОХОДИТЬ, иначе «падает» неотличимо от «мертво».
    for key in live:
        if not hiding[key]["passed"]:
            findings.append(
                f"{key[0]} / {key[1]!r}: упало в мире, где отказы одинаковы ЗАКОННО "
                f"(законный запрос обслужен, существование скрыто): {hiding[key]['error']}")

    # 3. W_leak(T) — падает РОВНО одна цель.
    for key in live:
        step, response = key[0], TARGETS[key]
        world = dict(W_HIDING)
        world[step] = response
        leaked = run_world(items, world)
        if leaked[key]["passed"]:
            findings.append(
                f"{key[0]} / {key[1]!r}: свойство нарушено, а утверждение прошло — оно не "
                f"смотрит на то, что объявляет")
        collateral = [k for k in live if k != key and not leaked[k]["passed"]]
        if collateral:
            findings.append(
                f"инъекция в шаг {step!r} уронила и соседей: {collateral} — тогда «упало "
                f"проверяемое» неотличимо от «упал сосед»")
    census["миров исполнено"] = 2 + len(live)

    # 4. Полнота: всякое НОВОЕ прошедшее в W_today — находка.
    for key, r in sorted(today.items()):
        if r["passed"] and key not in HONEST_IN_W_TODAY and key not in TARGETS:
            findings.append(
                f"{key[0]} / {key[1]!r}: проходит в мире одинаковых ответов и не объявлено "
                f"честным наблюдением. Либо это наблюдение (внести в HONEST_IN_W_TODAY с "
                f"причиной), либо вакуум (поставить положительный контроль)")

    # 5. Послабление истекает само: записи, которой нечего прощать, не бывает.
    for key in sorted(HONEST_IN_W_TODAY):
        if key not in today:
            findings.append(
                f"объявлено честным, но такого утверждения в коллекции нет: {key!r} — запись "
                f"пережила свой предмет")
        elif not today[key]["passed"]:
            findings.append(
                f"объявлено честным, но в W_today не проходит: {key!r} — прощать нечего")
    return census, findings


def main():
    if not COLLECTION.is_file():
        print(f"ОТКАЗ: коллекции нет ({COLLECTION}) — вердикт беспредметен", file=sys.stderr)
        return 1
    try:
        census, findings = audit(json.loads(COLLECTION.read_text(encoding="utf-8")))
    except VerdictHasNoSubject as exc:
        print(f"ОТКАЗ: {exc}", file=sys.stderr)
        return 1
    print("перепись: " + " · ".join(f"{k} {v}" for k, v in census.items()))
    if findings:
        print(f"НАХОДКИ ({len(findings)}):", file=sys.stderr)
        for f in findings:
            print("  " + f, file=sys.stderr)
        return 1
    print("ЧИСТО: у каждого утверждения о неотличимости стоит положительный контроль — "
          "на одинаковых ответах оно падает, на законном сокрытии проходит")
    return 0


if __name__ == "__main__":
    sys.exit(main())
