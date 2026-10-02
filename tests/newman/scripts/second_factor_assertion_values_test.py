#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Гейт: утверждения набора второго фактора не несут значений удостоверений.

ПРЕДМЕТ (kaname#417, п.2 предмета). Отчёт прогона `kaname-second-factor`
выкладывается артефактом ПУБЛИЧНОГО репозитория, и выкладывает его срез
`.github/scripts/redact-newman-report.py`. Срез судит части документа по ИМЕНИ
и по ФОРМЕ. Текст упавшего утверждения — проза: имени у значения в ней нет, а
формы у удостоверений этой полосы почти нет — запасной код короче любого порога
(десять знаков), код по времени — шесть цифр. Значит на тексте утверждения срез
этой полосы слеп ПО ПОСТРОЕНИЮ, и закрывается это не срезом, а источником:
утверждение не получает значения удостоверения вовсе.

ЧТО УТВЕРЖДЕНИЕ ПЕЧАТАЕТ, КОГДА ПАДАЕТ. chai собирает текст отказа из трёх
частей: сообщение (второй довод `pm.expect`), ПРЕДМЕТ («expected <предмет> …») и
ОЖИДАЕМОЕ («… to deeply equal <ожидаемое>»). К ним прибавляются имя утверждения
(`pm.test`), текст `pm.expect.fail`, текст исключения, брошенного внутри
утверждения (newman кладёт его в отчёт вместо текста утверждения), и строки
журнала (`console.*` уходит в вывод прогонщика). Всё это гейт и записывает.

ЧТО ЗНАЧИТ «НЕСЁТ ЗНАЧЕНИЕ». Скрипты исполняются НАСТОЯЩИМ движком (node) — тот
самый JavaScript из порождённой коллекции, — против ответа, в котором стоит
КАЖДОЕ удостоверение полосы: секрет кода по времени (и адрес `otpauth` с ним),
десять запасных кодов, признак формы, печенья сессии и контекста формы; пароль
человека и код по времени приходят окружением и вычислением посева. Ответ один
на все шаги, и это решение, а не упрощение: утверждение печатается тогда, когда
продукт ответил НЕ ТАК, а «не так» бывает любым — отрицательный шаг `enroll`
при дефекте получает тело с секретом, шаг состояния при утечке (Ф12-27) —
секрет и коды. Таблица «какой путь что отдаёт» была бы вторым описанием
контракта, и расходилась бы с ним молча. Значения — в ФОРМЕ ПРОДУКТА (base32 от
20 байт, десять знаков Crockford, шесть цифр): подделка «словом» сделала бы
фикстуру снисходительнее продукта.

ВТОРАЯ ПОЛОВИНА — ОКРУЖЕНИЕ. Набор кладёт удостоверения в переменные окружения
(секрет, код, запасные коды), а окружение уходит в отчёт целиком. Срез режет
значение переменной по её ИМЕНИ, значит имя обязано быть тем, которое срез
знает. Гейт спрашивает об этом САМ СРЕЗ — его точкой входа, на документе из
записанных переменных, — а не держит второй перечень имён: два перечня об одном
предмете разошлись бы молча.

ПОЛНОТА ОБХОДА — ПЕРЕПИСЬЮ МЕСТ. Каждое место вызова `pm.test`, `pm.expect` и
`pm.expect.fail` в тексте скрипта помечается ДО исполнения, и место, которое не
исполнилось ни в одном мире, — находка: его значения не осмотрены. Миров три,
потому что ветвей стража у шага две: адрес полосы есть (все шаги идут до конца),
адреса нет (страж условия стенда), переменная тела не определена (страж
незахваченной переменной). Место, попавшее под пометку внутри строкового
литерала, не исполнится никогда и краснеет — отказ в сторону красного, не
зелёного.

Подделка `pm` СТРОГАЯ: неизвестный член бросает, и брошенное вне утверждения —
находка («скрипт не исполнился — его значения не осмотрены»), а не молчание.

ЧЕГО ГЕЙТ НЕ СУДИТ, и это названо, а не умолчано: тела запросов, в которые
подставляются переменные (`{"code": "{{sfBackupCode0}}"}`) — их судит срез по
имени члена, и держит это его самопроба (`--self-test`, ось видов полосы второго
фактора); наборы других полос — предмет этой задачи набор второго фактора.

ИСХОДЫ: 0 — находок нет, перепись напечатана; 1 — находки либо вердикт
беспредметен (коллекции нет, node нет, мест ноль, срез не ответил).

Способность упасть и смолчать доказывает
`second_factor_assertion_values_injection_test.py` (импортирует этот модуль по
имени — переименование файла ломает её).
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

NEWMAN = pathlib.Path(__file__).resolve().parents[1]
ROOT = NEWMAN.parents[1]
COLLECTION = NEWMAN / "collections" / "kaname-second-factor.postman_collection.json"
REDACTOR = ROOT / ".github" / "scripts" / "redact-newman-report.py"

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b64url(label: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest()).rstrip(b"=").decode()


# ── Удостоверения полосы в форме продукта ─────────────────────────────────
SECRET = base64.b32encode(hashlib.sha1(b"kaname#417 probe totp secret").digest()).decode()
BACKUP_CODES = ["".join(CROCKFORD[b % 32] for b in hashlib.sha256(
    f"kaname#417 probe backup {i}".encode()).digest()[:10]) for i in range(10)]
CSRF = _b64url("kaname#417 probe csrf")
SESSION_COOKIE = _b64url("kaname#417 probe session")
FORM_COOKIE = _b64url("kaname#417 probe form")
PASSWORD = "Pw-2fa-" + _b64url("kaname#417 probe password")[:20]
# Код по времени вычисляет посев (`__totp`) из HMAC-SHA1 секрета. Подделка
# crypto-js отдаёт этот отпечаток, и усечение RFC 4226 даёт из него шесть цифр:
# смещение — последний полубайт (0), первые четыре байта — 0x000b2b01 = 731905.
TOTP_DIGEST_HEX = "000b2b01" + "0" * 32
TOTP_CODE = f"{(int(TOTP_DIGEST_HEX[:8], 16) & 0x7FFFFFFF) % 1000000:06d}"

KINDS: dict[str, list[str]] = {
    "секрет кода по времени": [SECRET],
    "запасной код": BACKUP_CODES,
    "признак формы": [CSRF],
    "печенье сессии": [SESSION_COOKIE],
    "печенье контекста формы": [FORM_COOKIE],
    "пароль": [PASSWORD],
    "код по времени": [TOTP_CODE],
}

OTPAUTH = (f"otpauth://totp/kaname:login-lane-2fa%40stand.invalid?secret={SECRET}"
           "&issuer=kaname&algorithm=SHA1&digits=6&period=30")

# ОДИН ОТВЕТ НА ВСЕ ШАГИ: каждое удостоверение полосы — на своём месте контракта.
WORST_BODY = {
    "secret": SECRET,
    "otpauthUri": OTPAUTH,
    "expiresAt": "2026-09-26T10:00:00Z",
    "backupCodes": BACKUP_CODES,
    "backupCodesRemaining": 9,
    "csrfToken": CSRF,
    "session": {"assuranceLevel": "2", "expiresAt": "2026-09-26T10:00:00Z", "emailVerified": True},
    "assurance": {"level": "2", "level2Reachable": True, "missingForLevel2": []},
    "totp": {"enrolled": True, "confirmedAt": "2026-09-26T09:00:00Z",
             "pendingUntil": "2026-09-26T09:10:00Z"},
    "code": 16,
    "message": "authentication failed",
    "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                 "reason": "FORM_TOKEN_REJECTED", "domain": "kaname"}],
}
WORST_HEADERS = [
    {"key": "Content-Type", "value": "application/json"},
    {"key": "Set-Cookie", "value": f"kaname_session={SESSION_COOKIE}; Path=/; HttpOnly; Secure"},
    {"key": "Set-Cookie", "value": f"kaname_form={FORM_COOKIE}; Path=/; HttpOnly; Secure"},
]

LANE_ENV = {"loginLaneEmail": "login-lane-2fa@stand.invalid", "loginLanePassword": PASSWORD}
WORLDS = {
    "адрес полосы есть": dict(LANE_ENV, loginLaneBaseUrl="https://127.0.0.1:9443"),
    "адреса полосы нет": dict(LANE_ENV, loginLaneBaseUrl=""),
    "переменная не определена": dict(LANE_ENV, loginLaneBaseUrl="https://{{laneHostNeverBound}}"),
}

SITE_RE = re.compile(r"\bpm\.(expect\.fail|expect|test)(\s*\()")

DRIVER = r"""
const job = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = { records: [], hits: [], errors: [], envWrites: [], scripts: 0 };
const FAIL = new Error('pm.expect.fail');
function show(v) {
  try {
    if (typeof v === 'string') return v;
    if (v === undefined) return 'undefined';
    if (v instanceof RegExp) return String(v);
    if (typeof v === 'function') return '[function]';
    return JSON.stringify(v, (k, x) => (x instanceof RegExp ? String(x)
      : (typeof x === 'function' ? '[function]' : (x === undefined ? 'undefined' : x))));
  } catch (e) { return '[не сериализуется: ' + String(e && e.message) + ']'; }
}
function strict(name, obj) {
  return new Proxy(obj, {
    get(t, k) {
      if (typeof k === 'symbol') return t[k];
      if (k in t) return t[k];
      throw new Error('подделка: неизвестный член ' + name + '.' + String(k));
    },
    set(t, k, v) {
      if (k in t) { t[k] = v; return true; }
      throw new Error('подделка: запись в неизвестный член ' + name + '.' + String(k));
    },
  });
}
const hits = new Set();
for (const world of job.worlds) {
  const env = Object.assign({}, world.env);
  for (const item of job.items) {
    for (const phase of ['prerequest', 'test']) {
      for (const sc of item.scripts[phase]) {
        out.scripts += 1;
        let site = null;
        const where = { world: world.name, item: item.name, phase, label: sc.label };
        const rec = (role, value, at) => out.records.push(Object.assign({ site: at, role, text: show(value) }, where));
        const chain = (at) => new Proxy(function () {}, {
          get(t, k) { if (typeof k === 'symbol') return undefined; return chain(at); },
          apply(t, self, args) { for (const a of args) rec('ожидаемое', a, at); return chain(at); },
        });
        const expect = function (subject, message) {
          const at = site;
          rec('предмет', subject, at);
          if (arguments.length > 1) rec('сообщение', message, at);
          return chain(at);
        };
        expect.fail = function (message) { rec('сообщение', message, site); throw FAIL; };
        const hdrs = job.response.headers.map(h => ({ key: h.key, value: h.value }));
        const pm = strict('pm', {
          __site: (k) => { hits.add(k); site = k; return pm; },
          expect,
          test: (name, fn) => {
            const at = site;
            rec('имя утверждения', name, at);
            try { fn(); } catch (e) { if (e !== FAIL) rec('текст исключения', e && e.message !== undefined ? e.message : e, at); }
          },
          environment: strict('pm.environment', {
            get: (k) => (Object.prototype.hasOwnProperty.call(env, k) ? env[k] : undefined),
            set: (k, v) => { env[k] = v === undefined ? undefined : String(v); out.envWrites.push(Object.assign({ name: String(k), text: show(v) }, where)); },
            unset: (k) => { delete env[k]; },
            has: (k) => Object.prototype.hasOwnProperty.call(env, k),
          }),
          variables: strict('pm.variables', {
            get: (k) => env[k],
            has: (k) => Object.prototype.hasOwnProperty.call(env, k),
            replaceIn: (s) => String(s).replace(/\{\{(\w+)\}\}/g, (m, n) => (Object.prototype.hasOwnProperty.call(env, n) ? env[n] : m)),
          }),
          request: strict('pm.request', {
            url: item.url,
            body: item.body === null ? undefined : strict('pm.request.body', { raw: item.body }),
            headers: strict('pm.request.headers', { upsert: () => {}, remove: () => {}, add: () => {} }),
          }),
          response: strict('pm.response', {
            code: job.response.code,
            text: () => job.response.body,
            json: () => JSON.parse(job.response.body),
            headers: strict('pm.response.headers', {
              all: () => hdrs.map(h => Object.assign({}, h)),
              get: (k) => { const h = hdrs.find(x => x.key.toLowerCase() === String(k).toLowerCase()); return h ? h.value : undefined; },
            }),
          }),
          execution: strict('pm.execution', { skipRequest: () => {}, setNextRequest: () => {} }),
          info: strict('pm.info', { requestName: item.name }),
        });
        const cryptoJs = {
          HmacSHA1: () => ({}),
          enc: { Hex: { parse: (s) => s, stringify: () => job.totpDigestHex } },
        };
        const req = (m) => { if (m === 'crypto-js') return cryptoJs; throw new Error('подделка: require(' + String(m) + ')'); };
        const log = (...a) => { for (const x of a) rec('журнал', x, site); };
        const con = { log, info: log, warn: log, error: log, debug: log };
        try { new Function('pm', 'require', 'console', sc.code)(pm, req, con); }
        catch (e) {
          const msg = e && e.message !== undefined ? e.message : e;
          out.errors.push(Object.assign({ text: show(msg) }, where));
          rec('текст исключения', msg, site);
        }
      }
    }
  }
}
out.hits = Array.from(hits);
process.stdout.write(JSON.stringify(out));
"""


class VerdictHasNoSubject(Exception):
    """Вердикт не о дереве: исполнить нечем либо исполнять нечего."""


def _script(node, listen):
    for ev in node.get("event", []) or []:
        if ev.get("listen") == listen:
            return "\n".join(ev.get("script", {}).get("exec", []) or [])
    return ""


def collection_items(doc):
    """Шаги коллекции со скриптами в порядке newman: коллекция → папка → шаг."""
    items = []

    def walk(nodes, parents):
        for node in nodes:
            if "item" in node:
                walk(node["item"], parents + [node])
                continue
            req = node.get("request", {}) or {}
            url = req.get("url", "")
            raw_url = url.get("raw", "") if isinstance(url, dict) else str(url)
            body = (req.get("body") or {}).get("raw") if isinstance(req.get("body"), dict) else None
            scripts = {}
            for phase in ("prerequest", "test"):
                scripts[phase] = [(label, code) for label, code in
                                  [(p.get("name", "коллекция"), _script(p, phase)) for p in parents]
                                  + [("шаг", _script(node, phase))] if code]
            items.append({"name": node.get("name", "?"), "url": raw_url, "body": body,
                          "scripts": scripts})

    walk(doc.get("item", []), [doc])
    return items


def instrument(items):
    """Пометить каждое место вызова ДО исполнения. Возвращает (шаги, места)."""
    sites = []
    out = []
    for item in items:
        scripts = {}
        for phase, pairs in item["scripts"].items():
            done = []
            for label, code in pairs:
                def mark(m):
                    k = len(sites)
                    sites.append({"site": k, "item": item["name"], "phase": phase, "label": label,
                                  "kind": "pm." + m.group(1)})
                    return f"pm.__site({k}).{m.group(1)}{m.group(2)}"
                done.append({"label": label, "code": SITE_RE.sub(mark, code)})
            scripts[phase] = done
        out.append(dict(item, scripts=scripts))
    return out, sites


def execute(items):
    if shutil.which("node") is None:
        raise VerdictHasNoSubject("node не найден: исполнить порождаемый JavaScript нечем — "
                                  "это «ноль прочитанного», а не «ноль находок»")
    job = {"items": items,
           "worlds": [{"name": n, "env": e} for n, e in WORLDS.items()],
           "response": {"code": 200, "body": json.dumps(WORST_BODY, ensure_ascii=False),
                        "headers": WORST_HEADERS},
           "totpDigestHex": TOTP_DIGEST_HEX}
    proc = subprocess.run(["node", "-e", DRIVER], input=json.dumps(job, ensure_ascii=False),
                          capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise VerdictHasNoSubject(f"движок отказал (код {proc.returncode}): {proc.stderr[-1500:]}")
    return json.loads(proc.stdout)


def kinds_in(text):
    """Какие виды удостоверений стоят в тексте. Значения не возвращаются."""
    return sorted({kind for kind, values in KINDS.items() for v in values if v in text})


def redactor_leftovers(writes):
    """Спросить САМ СРЕЗ: какие из записанных переменных он оставил бы в отчёте.

    Вход — окружение из записанных пар в форме отчёта newman; ответ — номера пар,
    в выложенном значении которых удостоверение осталось."""
    if not writes:
        return []
    if not REDACTOR.is_file():
        raise VerdictHasNoSubject(f"среза нет ({REDACTOR}) — спросить о именах некого")
    doc = {"environment": {"values": [{"key": n, "value": v} for n, v in writes]}}
    with tempfile.TemporaryDirectory(prefix="sf-assert-values-") as td:
        src, dst = pathlib.Path(td) / "in", pathlib.Path(td) / "out"
        src.mkdir()
        (src / "env.json").write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run([sys.executable, str(REDACTOR), "--in", str(src), "--out", str(dst)],
                              capture_output=True, text=True, timeout=120)
        published = dst / "env.json"
        if proc.returncode not in (0, 1) or not published.is_file():
            raise VerdictHasNoSubject(f"срез не ответил (код {proc.returncode}): {proc.stderr[-800:]}")
        values = json.loads(published.read_text(encoding="utf-8"))["environment"]["values"]
    return [i for i, (n, v) in enumerate(writes)
            if i < len(values) and kinds_in(str(values[i].get("value", "")))]


def audit(doc):
    """Судящая функция. Возвращает (перепись, находки)."""
    items, sites = instrument(collection_items(doc))
    census = {"шагов": len(items), "мест вызова": len(sites), "миров": len(WORLDS)}
    if not items:
        raise VerdictHasNoSubject("в коллекции ноль шагов — вердикт беспредметен")
    if not sites:
        raise VerdictHasNoSubject("мест вызова утверждений ноль — судить нечего")
    data = execute(items)
    census["скриптов исполнено"] = data["scripts"]
    census["записей осмотрено"] = len(data["records"])
    if not data["records"]:
        raise VerdictHasNoSubject("исполнено, а записано ноль — подделка не видит утверждений")
    findings = []

    seen = set()
    for r in data["records"]:
        kinds = kinds_in(r["text"])
        if not kinds:
            continue
        key = (r["item"], r["phase"], r["site"], r["role"], tuple(kinds))
        if key in seen:
            continue
        seen.add(key)
        where = f"место №{r['site']}" if r["site"] is not None else "вне места вызова"
        findings.append(f"{r['item']} · {r['phase']} ({r['label']}) · {where} · {r['role']}: "
                        f"несёт значение удостоверения — {', '.join(kinds)}")

    executed = set(data["hits"])
    census["мест исполнено"] = len(executed & {s["site"] for s in sites})
    for s in sites:
        if s["site"] not in executed:
            findings.append(f"{s['item']} · {s['phase']} ({s['label']}) · место №{s['site']} "
                            f"({s['kind']}) не исполнилось ни в одном мире — его значения не осмотрены")

    errs = set()
    for e in data["errors"]:
        k = (e["item"], e["phase"], e["label"], e["text"] if not kinds_in(e["text"]) else "<текст несёт удостоверение>")
        if k not in errs:
            errs.add(k)
            findings.append(f"{e['item']} · {e['phase']} ({e['label']}) · мир «{e['world']}»: скрипт "
                            f"упал вне утверждения ({k[3]}) — его значения не осмотрены")

    carrying = {}
    for w in data["envWrites"]:
        if kinds_in(w["text"]):
            carrying.setdefault((w["name"], w["text"]), w)
    census["записей окружения с удостоверением"] = len(carrying)
    pairs = list(carrying)
    for i in redactor_leftovers(pairs):
        name, text = pairs[i]
        findings.append(f"окружение: переменная {name!r} получает удостоверение "
                        f"({', '.join(kinds_in(text))}), а срез отчёта его оставляет — имя "
                        f"ему незнакомо, и окружение уйдёт в артефакт с ним")
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
    print("ЧИСТО: ни одно утверждение набора второго фактора не получает значения "
          "удостоверения ни предметом, ни сообщением, ни ожидаемым, и каждое удостоверение, "
          "положенное в окружение, срез отчёта вырезает")
    return 0


if __name__ == "__main__":
    sys.exit(main())
