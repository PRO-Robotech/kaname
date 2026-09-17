# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Повторная отправка письма приглашения — UserService.ResendInvite (приёмка
ID-MAIL-1, §10 п. 9; MAIL-36, MAIL-37, MAIL-38, MAIL-25; задача продукта #1774).

Чёрный ящик через СОБСТВЕННЫЙ REST-фронт службы (автономный стенд): предмет —
глагол службы, и производитель у него — служба.

Что утверждается, каждое отрицание — в паре с положительным контролем:

  RESEND-OK      приглашение свежего адреса → повторная отправка → Operation
                 done без ошибки, ответ — строка человека (MAIL-38).
  RESEND-SAME    приглашение того же адреса повторяется — исход тот, который
                 объявляет контракт (Operation done), а не отказ по уникальности
                 (MAIL-36); повторные отправки СВЕРХ ограничения частоты отвечают
                 ТЕМ ЖЕ исходом, что в норме, — отказ по частоте не оракул
                 (MAIL-25). Сколько писем ушло, наблюдает приёмник на стенде с
                 почтой (MAIL-05), не этот кейс.
  RESEND-404     строка, которой в аккаунте нет, — NOT_FOUND тем же текстом,
                 что у несуществующего; чужая строка (userNOB) неотличима
                 (hide-existence, MAIL-37).
  RESEND-400     мусорный идентификатор — синхронный INVALID_ARGUMENT.

Предъявитель `jwtAccountAdminA` на автономном стенде — служебная учётка; пол
step-up машин не касается (у машины нет интерактивной церемонии), поэтому оба
глагола проходят без `*StepUp`.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`.
HOME = "kaname"

CASES = []

POLL_CAP = 30


def _poll_op(op_var):
    """Тело самоопрашивающего шага: дождаться `done` операции, отказа быть не должно.

    Ветки захвата `response.id` здесь нет намеренно: ни один вызывающий её не
    передавал, а вклейка имени переменной в JS-литерал — форма, которую держат
    храповики `js_regex_literal_cases_test.py` и `js_name_position_test.py`.
    """
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_pollCount', String(pc + 1));",
        "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        "pm.test('operation carries the response row', () => pm.expect(Boolean(j.response), JSON.stringify(j)).to.eql(true));",
    ]


def _invite(tag, out_var):
    return [
        Step(
            name=f"invite-{tag}",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": f"resend-{tag}-{{{{runId}}}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", f"_op_{out_var}"),
                *save_from_response("j.metadata && j.metadata.userId", out_var),
            ],
        ),
        Step(
            name=f"poll-invite-{tag}",
            method="GET",
            path=f"/operations/{{{{_op_{out_var}}}}}",
            auth="jwtAccountAdminA",
            test_script=_poll_op(f"_op_{out_var}"),
        ),
    ]


def _resend(name, user_ref, op_var):
    return Step(
        name=name,
        method="POST",
        path=f"/iam/v1/users/{user_ref}:resendInvite",
        body={"accountId": "{{accountAId}}"},
        auth="jwtAccountAdminA",
        test_script=[
            *assert_status(200),
            *save_from_response("j.id", op_var),
            "pm.test('metadata names the person and the account', () => {",
            "  const j = pm.response.json();",
            "  pm.expect(j.metadata && j.metadata.userId, JSON.stringify(j)).to.be.a('string').and.not.empty;",
            "  pm.expect(j.metadata && j.metadata.accountId, JSON.stringify(j)).to.eql(pm.environment.get('accountAId'));",
            "});",
        ],
    )


def _poll(name, op_var):
    return Step(name=name, method="GET", path=f"/operations/{{{{{op_var}}}}}",
                auth="jwtAccountAdminA", test_script=_poll_op(op_var))


# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-USR-RESEND-OK",
    title="Пригласить свежий адрес → ResendInvite → Operation done, ответ — строка (MAIL-38)",
    classes=["CRUD"],
    priority="P0",
    steps=[
        *_invite("ok", "rsOkUserId"),
        _resend("resend-ok", "{{rsOkUserId}}", "rsOkOp"),
        _poll("poll-resend-ok", "rsOkOp"),
    ],
))

# ---------------------------------------------------------------------------
# MAIL-36 / MAIL-25: повтор приглашения идемпотентен; отправки сверх нормы
# отвечают тем же исходом. Умолчание нормы — 3 письма в час на адрес
# (invite.mail-rate-limit); приглашение — первое письмо, две повторные — норма,
# третья и четвёртая — сверх нормы, и исход у них ТОТ ЖЕ.
CASES.append(Case(
    id="IAM-USR-RESEND-SAME-OUTCOME",
    title="Повтор приглашения идемпотентен; отправки сверх нормы неотличимы от нормы (MAIL-36, MAIL-25)",
    classes=["IDM", "NEG"],
    priority="P1",
    steps=[
        *_invite("same", "rsSameUserId"),
        Step(
            name="invite-same-again",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": "resend-same-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "rsSameOp0"),
                "pm.test('повтор приглашения возвращает ту же строку, а не дубль', () => "
                "  pm.expect(pm.response.json().metadata.userId).to.eql(pm.environment.get('rsSameUserId')));",
            ],
        ),
        _poll("poll-invite-same-again", "rsSameOp0"),
        _resend("resend-same-1", "{{rsSameUserId}}", "rsSameOp1"),
        _poll("poll-resend-same-1", "rsSameOp1"),
        _resend("resend-same-2", "{{rsSameUserId}}", "rsSameOp2"),
        _poll("poll-resend-same-2", "rsSameOp2"),
        _resend("resend-same-3-over-cap", "{{rsSameUserId}}", "rsSameOp3"),
        _poll("poll-resend-same-3-over-cap", "rsSameOp3"),
        _resend("resend-same-4-over-cap", "{{rsSameUserId}}", "rsSameOp4"),
        _poll("poll-resend-same-4-over-cap", "rsSameOp4"),
    ],
))

# ---------------------------------------------------------------------------
# Hide-existence: строки нет в аккаунте — один текст для «нет нигде» и «есть
# в чужом аккаунте» (userNOB — человек без выдач, посеянный стендом).
CASES.append(Case(
    id="IAM-USR-RESEND-NEG-NOT-IN-ACCOUNT",
    title="ResendInvite по строке не из аккаунта → 404 тем же текстом, что у несуществующей (MAIL-37)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="resend-absent",
            method="POST",
            path="/iam/v1/users/usr0000000000000absn:resendInvite",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                *save_from_response("j.message", "rsAbsentText"),
            ],
        ),
        Step(
            name="resend-foreign-row",
            method="POST",
            path="/iam/v1/users/{{userNOBId}}:resendInvite",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
                "pm.test('чужая строка неотличима от отсутствующей: та же форма текста', () => {",
                "  const mine = String(pm.response.json().message || '').replace(/usr[a-z0-9]+/g, '<id>');",
                "  const absent = String(pm.environment.get('rsAbsentText') || '').replace(/usr[a-z0-9]+/g, '<id>');",
                "  pm.expect(mine).to.eql(absent);",
                "});",
            ],
        ),
    ],
))

# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-USR-RESEND-NEG-MALFORMED-ID",
    title="ResendInvite с мусорным user_id → 400 InvalidArgument синхронно",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="resend-garbage-id",
            method="POST",
            path="/iam/v1/users/not-an-id:resendInvite",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))

# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а): предмет —
# глагол службы, производит его её же дверь, и на автономном стенде другого
# адреса у него нет.
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "ресурса нет адреса на автономном стенде, и кейс "
                                 "проверял бы край платформы вместо предмета")
