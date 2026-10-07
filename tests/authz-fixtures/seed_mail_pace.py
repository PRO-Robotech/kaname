#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ПОСЕВ УСЛОВИЙ ЧАСТОТЫ ЗАПРОСА КОДА И НАБЛЮДАЕМОСТИ НЕДОСТАВЛЕННОГО на стенде
посадки `own`.

ПРЕДМЕТ. «Дано» трёх сквозных позиций приёмки восстановления
(`docs/engineering/acceptance/recovery-of-access.md`), которые несёт набор
`kaname-recovery-lane`:

  · Ф5-26 — окно писем адресата: проба ПЕЧАТАЕТ величину окна `N` и окно `T`,
    читает клетки счётчика исходов запроса кода и у близнеца (в) заполняет окно
    писем ПРИГЛАШЕНИЯ адресата `P′` до `N`;
  · Ф5-27 — окно обращений источника: проба печатает `M` и окно;
  · Ф5-14 — возраст самого старого неотправленного письма виден наблюдаемостью.

Пишет он шесть ключей окружения (`MINTED_KEYS`), и каждый — ответ стенда, а не
литерал:

  · `standMetricsUrl` — адрес слушателя метрик процесса службы (переадресация
    порта `metrics` её выката). Посев утверждает, что по нему ДО прогона
    публикуются обе величины, которые кейсы читают: клетки счётчика исходов
    запроса кода (`kaname_recovery_request_outcomes_total`) и возраст головы
    почтовой очереди (`kaname_outbox_oldest_pending_age_seconds` очереди
    `kaname.invite_mail_outbox`). Клетки существуют до первого события (Ф-е):
    их отсутствие — находка, а не «ещё не было запросов»;
  · `recoveryLettersPerRecipient` и `recoveryLetterWindow` — `N` и `T` окна
    писем адресата (`invite.mail-rate-limit`, MAIL-25), `recoverySourceAttempts`
    и `recoverySourceWindow` — `M` и окно обращений источника
    (`authn.login.source-attempts` · `source-window`, Ф3 Р10). Читаются из карты
    настроек, которую процесс службы ЧИТАЕТ (`<релиз>-config`, ключ
    `config.yaml`): выписанное в кейсе число разошлось бы с посадкой молча.
    Величина, которой в карте нет, — несозданное условие: окно писем стенд
    объявляет накладкой `own` явно, иначе процесс берёт умолчание, которого
    снаружи не прочесть;
  · `paceInviteFullEmail` — адресат `P′` близнеца (в) Ф5-26: человек заводится
    ГЛАГОЛАМИ полосы (регистрация, подтверждение адреса кодом письма — тем же
    посевом, что человек полосы входа), а окно его писем ПРИГЛАШЕНИЯ
    заполняется до `N` ЗАПИСЬЮ — строкой `kaname.invite_mail_windows` вида
    `invite`, как называет §7 приёмки («строкой … вида `invite` посевом»).
    Глагола, который отправил бы приглашение подтверждённому человеку, у
    продукта нет by construction (приглашают того, кого ещё нет), и запись —
    единственный конструктор этого «Дано». Утверждается она оператором с
    возвратом: вид и счёт лежащей строки читаются тем же оператором.

ИСХОДЫ — ТРИ, И ОНИ РАЗЛИЧАЮТСЯ КОДОМ:

    0  — условия созданы, окружение записано;
    1  — НАХОДКА: полоса либо хранилище ответили не по контракту там, где посев
         предъявил всё требуемое; слушатель метрик отвечает, а клеток нет;
   75  — УСЛОВИЕ НЕ СОЗДАНО: полоса, приёмник писем, слушатель метрик либо
         исполнитель записи недостижимы; карты настроек нет либо величины в ней
         не объявлены. Вердикта о дереве нет.

ПАРОЛЬ И ПОЧТА НЕ ПЕЧАТАЮТСЯ: журнал прогона публичного репозитория читает кто
угодно.

САМОПРОВЕРКА — `--self-test`: законный мир и по одному изменённому факту —
величины нет в карте, величина объявлена дважды, слушатель метрик молчит,
клеток нет, строки окна нет, вид строки не тот, счёт не тот, исполнитель не
запустился, почта вне алфавита оператора; сходимость объявленных ключей с
записью и поверхность против переписи долга.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import re
import secrets
import shlex
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

sys.path.insert(0, str(HERE))
from seed_login_lane import Finding, LaneHttp, seed as seed_person  # noqa: E402
from seed_own_stand import Mailbox, Unmet, write_env  # noqa: E402
from seed_stored_value import EMAIL_RE, PsqlStore  # noqa: E402

RC_FINDING = 1
RC_UNMET = 75

MINTED_KEYS = ("standMetricsUrl", "recoveryLettersPerRecipient", "recoveryLetterWindow",
               "recoverySourceAttempts", "recoverySourceWindow", "paceInviteFullEmail")

# Та же поверхность, что у посева полосы входа: кейсы стоят на слушателе формы.
MINTED_SURFACE = "служба (собственный REST-фронт)"

DOMAIN = "kaname.local"

# Серии, которые кейсы читают со слушателя метрик. Имя и метка — контракт
# наблюдаемости (`internal/observability/metrics/login_lane_recorder.go`,
# `outbox_recorder.go`; таблица — `clients.InviteMailTable`).
SERIES_RECOVERY = 'kaname_recovery_request_outcomes_total{outcome="queued"}'
SERIES_OLDEST = 'kaname_outbox_oldest_pending_age_seconds{table="kaname.invite_mail_outbox"}'

DURATION_RE = r'"?((?:[0-9]+(?:ns|us|ms|s|m|h))+)"?'
KNOBS = (
    # (ключ окружения, образец строки карты настроек, имя величины для отказа)
    ("recoveryLettersPerRecipient", r"^\s+max-per-window: ([0-9]+)\s*$",
     "invite.mail-rate-limit.max-per-window"),
    ("recoveryLetterWindow", r"^\s+mail-rate-limit:\n(?:\s+max-per-window: [0-9]+\n)?\s+window: "
     + DURATION_RE + r"\s*$", "invite.mail-rate-limit.window"),
    ("recoverySourceAttempts", r"^\s+source-attempts: ([0-9]+)\s*$", "authn.login.source-attempts"),
    ("recoverySourceWindow", r"^\s+source-window: " + DURATION_RE + r"\s*$", "authn.login.source-window"),
)


def say(msg: str) -> None:
    print(msg, flush=True)


# ─────────────────────────── величины посадки ────────────────────────────────


def knobs(config_text: str) -> dict[str, str]:
    """Величины окон из карты настроек процесса: ровно одно вхождение каждой."""
    out: dict[str, str] = {}
    for key, pattern, name in KNOBS:
        found = re.findall(pattern, config_text, re.M)
        if len(found) != 1:
            raise Unmet(f"величина {name} в карте настроек процесса встречается {len(found)} раз — "
                        f"ждали ровно одно объявление (накладка `own` стенда объявляет окно писем "
                        f"явно, профиль поставки — окно источника)")
        out[key] = found[0]
    if int(out["recoveryLettersPerRecipient"]) < 1 or int(out["recoverySourceAttempts"]) < 1:
        raise Finding("окно объявлено нулём — страж рендера и страж старта такого не пропускают")
    return out


# ─────────────────────────── слушатель метрик ────────────────────────────────


class Metrics:
    """Слушатель метрик процесса: TLS листом стенда, имя сервера проверяется."""

    def __init__(self, base_url: str, pki: pathlib.Path):
        ca = pki / "ca.crt"
        if not ca.is_file():
            raise Unmet(f"нет {ca} — якоря стенда не вынесено")
        self.base = base_url.rstrip("/")
        self.ctx = ssl.create_default_context(cafile=str(ca))

    def scrape(self) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(self.base + "/metrics", context=self.ctx, timeout=30) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, ssl.SSLError, OSError, socket.timeout) as e:
            raise Unmet(f"слушатель метрик по адресу {self.base} недостижим: {e}") from None


def prove_metrics(metrics) -> None:
    code, text = metrics.scrape()
    if code != 200:
        raise Finding(f"слушатель метрик ответил {code}, ждали 200")
    lines = text.splitlines()
    for series in (SERIES_RECOVERY, SERIES_OLDEST):
        if not any(ln.startswith(series + " ") for ln in lines):
            raise Finding(f"слушатель метрик отвечает, а серии {series} нет — клетка обязана "
                          f"существовать до первого события (Ф-е): «ноль» должен быть отличим "
                          f"от «не публикуется»")


# ─────────────────────────── окно писем приглашения ──────────────────────────


def fill_invite_sql(email: str, n: int) -> str:
    if not EMAIL_RE.match(email):
        raise Unmet("почта вне безопасного алфавита оператора — посев не пишет")
    return ("INSERT INTO kaname.invite_mail_windows (kind, recipient, window_started_at, sent, updated_at)\n"
            f"VALUES ('invite', '{email}', now(), {int(n)}, now())\n"
            "ON CONFLICT (kind, recipient) DO UPDATE\n"
            "   SET window_started_at = now(), sent = EXCLUDED.sent, updated_at = now()\n"
            "RETURNING kind || '|' || sent;\n")


def fill_invite_window(store, email: str, n: int) -> None:
    rows = store.run(fill_invite_sql(email, n))
    if rows != [f"invite|{int(n)}"]:
        raise Finding(f"окно писем приглашения адресата не заполнено: оператор вернул {len(rows)} "
                      f"строк, ждали одну строку вида invite со счётом {n}")


# ─────────────────────────── посев ───────────────────────────────────────────


def seed(lane, mailbox, store, metrics, config_text: str, metrics_url: str, sleep=time.sleep) -> dict:
    values = knobs(config_text)
    say(f"  ok   окна посадки: писем адресату {values['recoveryLettersPerRecipient']} за "
        f"{values['recoveryLetterWindow']}, обращений источника {values['recoverySourceAttempts']} за "
        f"{values['recoverySourceWindow']}")
    prove_metrics(metrics)
    say("  ok   слушатель метрик публикует клетки исходов запроса кода и возраст головы почтовой очереди")
    email = f"pace-invite-{secrets.token_hex(6)}@{DOMAIN}"
    password = "Pace-" + secrets.token_hex(12)
    seed_person(lane, mailbox, email, password, sleep)
    fill_invite_window(store, email, int(values["recoveryLettersPerRecipient"]))
    say("  ok   адресат P′ заведён глаголами полосы, адрес подтверждён; окно его писем "
        "приглашения заполнено до величины окна")
    return {"standMetricsUrl": metrics_url.rstrip("/"), **values, "paceInviteFullEmail": email}


def run(args: argparse.Namespace) -> int:
    pki = pathlib.Path(args.pki)
    lane = LaneHttp(args.base_url, pki)
    config_path = pathlib.Path(args.config_file)
    if not config_path.is_file() or not config_path.read_text(encoding="utf-8").strip():
        raise Unmet(f"карты настроек процесса нет ({config_path}) — величины окон читать неоткуда")
    patch = seed(lane, Mailbox(args.mailbox_url), PsqlStore(shlex.split(args.store_exec)),
                 Metrics(args.metrics_url, pki), config_path.read_text(encoding="utf-8"), args.metrics_url)
    replaced = write_env(patch, pathlib.Path(args.env_file), pathlib.Path(args.env_template))
    say(f"посев частоты запроса кода: ключей записано {len(patch)} (заменено {replaced}) в {args.env_file}")
    return 0


# ─────────────────────────── самопроверка ────────────────────────────────────

_SELF: list[str] = []

_CONFIG = """authn:
  login:
    address-attempts: 5
    source-attempts: 50
    source-window: "15m"
invite:
  mail-rate-limit:
    max-per-window: 3
    window: "1h"
"""

_SCRAPE = ("# HELP x\n" + SERIES_RECOVERY + " 0\n"
           'kaname_recovery_request_outcomes_total{outcome="recipient-paced"} 0\n'
           + SERIES_OLDEST + " 0\n")


def _c(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'ПРОВАЛ'} {label}" + ("" if ok else f" — {detail}"))
    if not ok:
        _SELF.append(label)


class _FakeMetrics:
    def __init__(self, code=200, text=_SCRAPE, down=False):
        self.code, self.text, self.down = code, text, down

    def scrape(self):
        if self.down:
            raise Unmet("слушатель метрик недостижим: connection refused")
        return self.code, self.text


class _FakeStore:
    def __init__(self, rows=None, down=False):
        self.rows, self.down = rows, down
        self.sql: list[str] = []

    def run(self, sql):
        if self.down:
            raise Unmet("исполнитель записи не запустился (kubectl: not found)")
        self.sql.append(sql)
        if self.rows is not None:
            return self.rows
        n = re.search(r"now\(\), ([0-9]+), now\(\)", sql).group(1)
        return [f"invite|{n}"]


def _no_person(lane, mailbox, email, password, sleep=None):
    return "заведён · адрес подтверждён"


def _outcome(fn) -> tuple[str, str]:
    try:
        return "ok", str(fn())
    except Finding as e:
        return "finding", str(e)
    except Unmet as e:
        return "unmet", str(e)
    except Exception as e:  # noqa: BLE001 — сбой пробы назван, а не проглочен
        return "crash", f"{type(e).__name__}: {e}"


def _census_surface() -> str | None:
    path = ROOT / ".github" / "scripts" / "newman-suite-debt.py"
    spec = importlib.util.spec_from_file_location("newman_suite_debt_probe_mp", path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.surface_of("", {"loginLaneBaseUrl"})


def self_test() -> int:
    import tempfile

    global seed_person
    real_person = seed_person
    seed_person = _no_person
    try:
        print("=== посев частоты запроса кода: различение исходов ===")

        def sow(config=_CONFIG, metrics=None, store=None):
            st = store if store is not None else _FakeStore()
            return _outcome(lambda: seed(None, None, st, metrics or _FakeMetrics(), config,
                                         "https://127.0.0.1:1/")), st

        (kind, text), st = sow()
        _c("законный мир — величины прочитаны, клетки есть, окно приглашения заполнено до N",
           kind == "ok" and len(st.sql) == 1 and "'invite'" in st.sql[0] and "now(), 3, now()" in st.sql[0],
           f"{kind}: {text}; {st.sql}")
        patch = seed(None, None, _FakeStore(), _FakeMetrics(), _CONFIG, "https://127.0.0.1:1/")
        _c("объявленные ключи = записываемые (в обе стороны)",
           set(patch) == set(MINTED_KEYS), f"{sorted(patch)} против {sorted(MINTED_KEYS)}")
        _c("величины — из карты, а не литерал: N 3 за 1h, M 50 за 15m, адрес без хвостового «/»",
           [patch[k] for k in ("recoveryLettersPerRecipient", "recoveryLetterWindow", "recoverySourceAttempts",
                               "recoverySourceWindow", "standMetricsUrl")]
           == ["3", "1h", "50", "15m", "https://127.0.0.1:1"], f"{patch}")
        other = seed(None, None, _FakeStore(), _FakeMetrics(), _CONFIG.replace("max-per-window: 3",
                                                                              "max-per-window: 7"), "x")
        _c("ЗАКОННЫЙ БЛИЗНЕЦ: другая величина в карте — другое N в окружении",
           other["recoveryLettersPerRecipient"] == "7", f"{other}")

        for label, kw, want in [
            ("окна писем в карте нет — условие не создано",
             {"config": _CONFIG.split("invite:")[0]}, "unmet"),
            ("окно источника объявлено дважды — условие не создано",
             {"config": _CONFIG + "    source-attempts: 9\n"}, "unmet"),
            ("слушатель метрик молчит — условие не создано", {"metrics": _FakeMetrics(down=True)}, "unmet"),
            ("слушатель метрик отвечает 403 — находка", {"metrics": _FakeMetrics(code=403)}, "finding"),
            ("клеток исходов запроса нет — находка",
             {"metrics": _FakeMetrics(text=SERIES_OLDEST + " 0\n")}, "finding"),
            ("возраста головы очереди нет — находка",
             {"metrics": _FakeMetrics(text=SERIES_RECOVERY + " 0\n")}, "finding"),
            ("строки окна не вернулось — находка", {"store": _FakeStore(rows=[])}, "finding"),
            ("строка окна не того вида — находка", {"store": _FakeStore(rows=["recovery|3"])}, "finding"),
            ("счёт окна не тот — находка", {"store": _FakeStore(rows=["invite|2"])}, "finding"),
            ("исполнитель записи не запустился — условие не создано",
             {"store": _FakeStore(down=True)}, "unmet"),
        ]:
            (kind, text), _ = sow(**kw)
            _c(label, kind == want, f"{kind}: {text}")
        got = _outcome(lambda: fill_invite_sql("x'; DROP TABLE x; --@a", 3))
        _c("почта вне алфавита оператора — отказ писать", got[0] == "unmet", f"{got}")

        with tempfile.TemporaryDirectory() as tmp:
            got = _outcome(lambda: Metrics("https://127.0.0.1:1", pathlib.Path(tmp)))
            _c("якоря стенда нет — условие не создано", got[0] == "unmet", f"{got}")
            env, tmpl = pathlib.Path(tmp) / "env.json", pathlib.Path(tmp) / "tmpl.json"
            tmpl.write_text(json.dumps({"values": [{"key": "standMetricsUrl", "value": ""}]}), encoding="utf-8")
            write_env(patch, env, tmpl)
            doc = {v["key"]: v for v in json.loads(env.read_text(encoding="utf-8"))["values"]}
            _c("запись доезжает всеми ключами", all(doc.get(k, {}).get("value") for k in MINTED_KEYS),
               f"{sorted(doc)}")
    finally:
        seed_person = real_person

    try:
        census = _census_surface()
    except Exception as e:  # noqa: BLE001 — любой отказ чтения переписи назван
        census = f"<перепись не прочитана: {e}>"
    _c("поверхность посева = поверхность, которую перепись выводит из loginLaneBaseUrl",
       census == MINTED_SURFACE, f"перепись {census!r}, посев {MINTED_SURFACE!r}")

    print()
    if _SELF:
        print(f"САМОПРОВЕРКА ПРОВАЛЕНА: {len(_SELF)} — {', '.join(_SELF)}", file=sys.stderr)
        return 1
    print("ДОКАЗАНО: величины окон читаются из карты процесса и не выписываются, их "
          "отсутствие отличимо от находки, клетки метрик утверждаются до прогона, окно "
          "приглашения утверждается строкой в хранилище, ключи сходятся с записью.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base-url", default="", help="адрес полосы входа (слушатель формы)")
    ap.add_argument("--pki", default="", help="каталог с edge.crt, edge.key и ca.crt")
    ap.add_argument("--mailbox-url", default="", help="адрес чтения приёмника писем стенда")
    ap.add_argument("--metrics-url", default="", help="адрес слушателя метрик процесса службы")
    ap.add_argument("--config-file", default="", help="карта настроек процесса (config.yaml)")
    ap.add_argument("--store-exec", default="",
                    help="команда до psql включительно (оператор уходит вводом)")
    ap.add_argument("--env-file",
                    default=str(ROOT / "tests" / "newman" / "environments" / "local.postman_environment.json"))
    ap.add_argument("--env-template",
                    default=str(ROOT / "tests" / "newman" / "environments"
                                / "local.postman_environment.template.json"))
    ap.add_argument("--minted-keys", action="store_true")
    ap.add_argument("--minted-surface", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.minted_keys:
        for k in MINTED_KEYS:
            print(k)
        return 0
    if args.minted_surface:
        print(MINTED_SURFACE)
        return 0
    if args.self_test:
        return self_test()
    try:
        if not all((args.base_url, args.pki, args.mailbox_url, args.metrics_url, args.config_file,
                    args.store_exec)):
            raise Unmet("не названы --base-url, --pki, --mailbox-url, --metrics-url, --config-file и "
                        "--store-exec — сеять нечем")
        return run(args)
    except Unmet as e:
        print(f"УСЛОВИЕ НЕ СОЗДАНО: {e}", file=sys.stderr)
        print("Посев не состоялся по причине, не относящейся к дереву: вердикта о продукте нет "
              "НИ ОДНОГО.", file=sys.stderr)
        return RC_UNMET
    except Finding as e:
        print(f"НАХОДКА: {e}", file=sys.stderr)
        return RC_FINDING


if __name__ == "__main__":
    sys.exit(main())
