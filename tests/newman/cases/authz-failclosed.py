# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set authz-failclosed — шлюз обязан ОТКАЗЫВАТЬ, когда хранилище прав недоступно.

Своя коллекция, а не кейс внутри authz-deny, потому что ей нужно УСЛОВИЕ,
несовместимое с остальным прогоном: хранилище прав, свёрнутое в ноль реплик. Пока
кейс жил среди соседей, это условие создать было нечем, и он держался
исключением в гейте — то есть инвариант «нет прав ⇒ отказ, никогда не 200» не
проверялся вообще, а выглядело это как зелёная суита.

Условие создаёт ``scripts/run-failclosed.sh``: сворачивает хранилище прав,
дожидается, пока решение перестанет отдаваться из кэша шлюза, гоняет эту
коллекцию и поднимает хранилище обратно. Прогонщик зовёт его ОТДЕЛЬНОЙ ВОЛНОЙ,
после всех остальных — соседям выключенное хранилище прав сломало бы всё.

Исключения этой коллекции не полагается ни при каком исходе: не удалось создать
условие ⇒ отчёта нет ⇒ гейт докладывает ``authz-failclosed(no-report)`` и
краснеет. «Здесь не запустить» — факт расписания, а не вердикт.

Pre-conditions: `tests/authz-fixtures/setup.sh` (jwtAccountAdminA, accountAId).
"""

CASES = []


# ---------------------------------------------------------------------------
# AUTHZ-FAILCLOSED-OPENFGA-DOWN
#
# Шлюз развёрнут с `authz.enabled=true, authz.failOpen=false`. Когда вызов
# AuthorizeService.Check не может быть выполнен (хранилище прав недоступно),
# промежуточный слой уходит в ветвь ошибки и при failOpen=false ОБЯЗАН ответить
# 503 / gRPC 14. Ответ 200 здесь означал бы, что отсутствие ответа о правах
# засчитывается за «разрешено», — то есть защита снимается ровно тогда, когда
# она нужнее всего.
#
# Запрос выбран самый обычный (чтение своего аккаунта): предмет — НЕ конкретный
# метод, а поведение слоя прав; на разрешённом в норме запросе отличие «отказал,
# потому что не смог спросить» от «отказал, потому что не положено» видно чище
# всего — в норме этот же запрос отвечает 200.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="AUTHZ-FAILCLOSED-OPENFGA-DOWN",
    title="gateway returns 503 Unavailable when the authorization store is unreachable (fail-closed)",
    classes=["AUTHZ", "FLOW", "FAIL_CLOSED"],
    priority="P0",
    steps=[
        Step(
            name="any-authz-gated-rpc-during-openfga-outage",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "// fail-closed: когда хранилище прав недостижимо, слой авторизации",
                "// шлюза уходит в ветвь ошибки и при FailOpen=false отвечает",
                "// 503 Unavailable / gRPC 14. НИКОГДА 200.",
                "//",
                "// Условие создаёт scripts/run-failclosed.sh (своя волна прогона):",
                "// он сворачивает хранилище прав, ждёт истечения кэша решений шлюза,",
                "// гоняет эту коллекцию и поднимает хранилище обратно.",
                "pm.test('[FAIL-CLOSED] gateway 503 Unavailable', () => {",
                "  pm.expect(pm.response.code, 'got ' + pm.response.code + ' ' + pm.response.text()).to.eql(503);",
                "});",
                "pm.test('[FAIL-CLOSED] grpc code 14 (Unavailable)', () => {",
                "  let j; try { j = pm.response.json(); } catch (_) { j = {}; }",
                "  pm.expect(j.code, JSON.stringify(j)).to.eql(14);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# AUTHZ-FAILCLOSED-LIST-NEVER-EMPTY-200 — ни один список НЕ отвечает пустой
# страницей, когда о правах спросить не у кого (задача #645).
#
# ЗАЧЕМ ОТДЕЛЬНО ОТ СОСЕДА ВЫШЕ. Тот кейс про ЧТЕНИЕ ОДНОГО объекта, и его
# отказ производит шлюз: у `Get` есть запись каталога со scope, поэтому до iam
# запрос не доходит вовсе. Списочные RPC iam объявлены `<exempt>` — шлюз по ним
# per-RPC Check НЕ делает, запрос доезжает до сервиса, и отвечает уже САМ СЕРВИС.
# Это разные производители одного кода, и второй здесь не проверялся ничем.
#
# ЧТО ИМЕННО УТВЕРЖДАЕТСЯ. Пустая страница и отказ — разные ответы, и арендатор
# обязан их различать. `200 {}` на списке означает «тебе ничего не выдано»;
# именно так выглядел бы стенд, на котором права спросить не у кого, — то есть
# сломанное развёртывание было бы неотличимо от корректно запертого. Поэтому
# утверждается ПАРА (HTTP-статус И код `google.rpc.Status`) и отдельно — что
# ответ не является успехом с пустым массивом.
#
# ПОЧЕМУ ВСЕ СЕМЬ. Инвариант принадлежит не одной поверхности, а классу: до
# задачи #645 привязки доступа отвечали на непровязанный порт отношений пустой
# страницей, а шесть соседей — отказом. Одна поверхность из семи, ведущая себя
# иначе, и есть та форма дефекта, которую перечень ловит, а точечный кейс нет.
#
# ЧЕГО ЭТОТ КЕЙС НЕ ДОКАЗЫВАЕТ (названо, чтобы не читалось шире). Свёрнутое в
# ноль хранилище прав роняет ВСЕ вопросы сразу, поэтому оно НЕ различает две
# правки контракта, ради которых заведены Go-пробы:
#   * непровязанный порт (`queries == nil`) — состояние ПРОВЯЗКИ, которого
#     развёрнутый стенд не производит: композиционный корень провязывает порт
#     всегда;
#   * отказ ОДНОГО вопроса о субъекте при исправном остальном — требует
#     точечной инъекции, которой волна «хранилище в ноль» не выражает.
# Обе полосы держат интеграционные пробы
# `services/iam/internal/apps/kacho/api/listvisibility` (645-23b и 645-16b), и
# здесь это сказано прямо, чтобы зелень этого кейса не засчитывалась за них.
# ---------------------------------------------------------------------------

_LIST_SURFACES = [
    ("projects", "/iam/v1/projects?accountId={{accountAId}}", "projects"),
    ("accounts", "/iam/v1/accounts", "accounts"),
    ("users", "/iam/v1/users?accountId={{accountAId}}", "users"),
    ("groups", "/iam/v1/groups?accountId={{accountAId}}", "groups"),
    ("service-accounts", "/iam/v1/serviceAccounts?accountId={{accountAId}}", "serviceAccounts"),
    ("roles", "/iam/v1/roles?accountId={{accountAId}}", "roles"),
    ("access-bindings", "/iam/v1/accessBindings", "accessBindings"),
]

CASES.append(Case(
    id="AUTHZ-FAILCLOSED-LIST-NEVER-EMPTY-200",
    title="every iam List refuses (503/14) while the authorization store is unreachable — never 200 with an empty page",
    classes=["AUTHZ", "FLOW", "FAIL_CLOSED", "NEG"],
    priority="P0",
    steps=[
        Step(
            name=f"list-{slug}-during-openfga-outage",
            method="GET",
            path=path,
            auth="jwtAccountAdminA",
            test_script=[
                "let j; try { j = pm.response.json(); } catch (_) { j = {}; }",
                "const body = JSON.stringify(j);",
                # Пара «статус + код», а не один из них: 503 приходит только от
                # UNAVAILABLE, но код несёт смысл, а статус — механическое следствие
                # (api-conventions.md, таблица края).
                f"pm.test('[FAIL-CLOSED] {slug}: 503 Unavailable', () => {{",
                f"  pm.expect(pm.response.code, body).to.eql(503);",
                "});",
                f"pm.test('[FAIL-CLOSED] {slug}: grpc code 14 (Unavailable)', () => {{",
                "  pm.expect(j.code, body).to.eql(14);",
                "});",
                # Отдельное утверждение о ЗАПРЕЩЁННОМ исходе. Оно не дублирует два
                # предыдущих: те говорят, каким ответ обязан быть, это — каким он
                # обязан НЕ быть, и падает с текстом, называющим именно ту подмену,
                # ради которой кейс написан.
                f"pm.test('[FAIL-CLOSED] {slug}: never a successful empty page', () => {{",
                "  const emptyOk = pm.response.code === 200"
                f" && Array.isArray(j.{field}) && j.{field}.length === 0;",
                "  pm.expect(emptyOk, 'answered 200 with an empty array while the "
                "authorization store was unreachable: a tenant cannot tell that from "
                "\"nothing has been granted to you\" — ' + body).to.eql(false);",
                "});",
            ],
        )
        for slug, path, field in _LIST_SURFACES
    ],
))
