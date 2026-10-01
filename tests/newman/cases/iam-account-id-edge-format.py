# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set iam-account-id-edge-format — ФОРМА ИДЕНТИФИКАТОРА АККАУНТА, КОТОРУЮ СУДИТ КРАЙ.

Два кейса, вынесенные при переезде своих модулей на собственный фронт службы
(kaname#398):

  * `IAM-AB-SIA-12-EDGE-LIST-BY-ACCOUNT` — из `iam-access-binding-account-scope.py`
    (`IAM-AB-SIA-12-MALFORMED-NEG`, шаг паритета с `ListByAccount`; приёмка
    `docs/engineering/acceptance/subject-grants-within-an-account.md`, IAM-AB-SIA-12);
  * `IAM-ID2-NEG-FORM-EDGE-ACCOUNT-ID` — из `iam-membership-read.py`
    (`IAM-ID2-NEG-FORM`, половина «идентификатор аккаунта — краем»; IAM-ID-2-04).

ПОЧЕМУ ОТДЕЛЬНЫМ МОДУЛЕМ. У обоих глаголов идентификатор аккаунта стоит в ПУТИ и
служит ЦЕЛЬЮ АВТОРИЗАЦИИ, и отказ по его форме — пара `400` / `3` — производит КРАЙ
платформы: шаг короткого замыкания по форме стоит в нём ДО проверки прав. На
собственном фронте службы этого шага нет: глагол доходит до проверки прав и
отвечает `403` / `7` (`AUTHZ_DENIED`, область `account`) — замер на автономном
стенде 2026-09-30 (`stand-own.sh`, волна kaname#398). Значит на собственном фронте у
пары нет производителя, а утверждение о форме, переписанное под `403`, перестало бы
быть о форме. Исход e2e-flow.md §7а — «оставить утверждение платформе, расщепив
коллекцию»; тот же исход и та же форма, что у кейса края
`PRO-Robotech/kacho:gateway/tests/newman/cases/iam-project-edge-format.py`.

Половины, чей производитель — сама служба, остались в своих модулях и гоняются на
собственном фронте: `invalid account id '<X>'` фильтра `List` и отказы формы
идентификатора членства и терма фильтра.

ДОМ — ПЛАТФОРМА: гоняет её конвейер через край; автономный стенд службы модуль не
исполняет, и печать долга называет его категорией C. Кейсы перенесены дословно, без
изменения ни строгости, ни «Тогда».

Чего этот модуль НЕ утверждает: как отвечает на тот же вход СОБСТВЕННЫЙ фронт
службы. Должен ли он замыкать по форме до проверки прав — предмет задачи
PRO-Robotech/kaname#168 (исходы её предиката называют оба пути), а не этих кейсов.
"""

# ДОМ МОДУЛЯ — ПЛАТФОРМА: свойство производит её край (e2e-flow.md §7а).
# `HOME_REASON` называет производителя; сверяет `scripts/case_home_test.py`.
HOME = "kacho"
HOME_REASON = (
    "производитель пары — край платформы: короткое замыкание по форме идентификатора "
    "аккаунта, стоящего целью авторизации в пути, идёт в нём ДО проверки прав и "
    "отвечает 400/3 без обращения к службе; собственный фронт службы такого шага не "
    "несёт и на том же входе отвечает 403/7 от проверки прав"
)

CASES = []

# Хорошо сформированный, но несуществующий аккаунт — положительный контроль рубежа
# формы (тот же литерал, что у `iam-membership-read.py`).
ABSENT_ACCOUNT = "acc00000000000000000"


def _q(text):
    """Строковый литерал JavaScript. Экранируется всё, что рвёт литерал."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _grpc_code(code, label):
    """Утверждается ПАРА: HTTP-статус проверяется отдельно, здесь — код rpc.Status."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


def _save_body(var):
    """Сохранить ТЕЛО ответа целиком — предмет сверки на байт-идентичность."""
    return [f"pm.environment.set({_q(var)}, pm.response.text());"]


def _same_body_as(var, label):
    return [
        f"pm.test({_q(label)}, () => {{",
        f"  pm.expect(pm.response.text()).to.eql(pm.environment.get({_q(var)}));",
        "});",
    ]


# ---------------------------------------------------------------------------
# IAM-AB-SIA-12-EDGE-LIST-BY-ACCOUNT — у `ListByAccount` `account_id` — ЦЕЛЬ
# АВТОРИЗАЦИИ (`scope_extractor`), и край судит её форму ДО модели прав, иначе
# отказ «пути нет» замаскировал бы 400 под 403. Отвечает КРАЙ, своим нейтральным
# именем ресурса: `invalid resource id '<X>'`. Нейтральное имя — предмет задачи
# PRO-Robotech/kacho#1932: появится словарь имён — шаг покраснеет и позовёт к себе.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-AB-SIA-12-EDGE-LIST-BY-ACCOUNT",
    title="IAM-AB-SIA-12: /accounts/not-an-id/accessBindings → 400 INVALID_ARGUMENT, "
          "\"invalid resource id 'not-an-id'\" — у цели авторизации производитель отказа формы КРАЙ",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="sia-malformed-parity-with-list-by-account",
            method="GET",
            path="/iam/v1/accounts/not-an-id/accessBindings?pageSize=100",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('у цели авторизации отказ формы производит край, и текст его', () =>",
                "  pm.expect(pm.response.json().message, pm.response.text())",
                "    .to.eql(\"invalid resource id 'not-an-id'\"));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-NEG-FORM-EDGE-ACCOUNT-ID (IAM-ID-2-04) — негодный accountId отвергает
# КРАЙ, до модели прав: исход не зависит от выданного вызывающему.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ID2-NEG-FORM-EDGE-ACCOUNT-ID",
    title="Негодная форма идентификатора аккаунта отвергается КРАЕМ до модели прав: "
          "400 у держателя права и у вызывающего без права, тела равны",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="malformed-account-id-rights-holder",
            method="GET",
            path="/iam/v1/accounts/not-an-account/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(3, "негодный accountId — отказ КРАЯ, до модели прав"),
                *_save_body("mbrMalformedAcctBody"),
            ],
        ),
        Step(
            name="malformed-account-id-no-rights",
            method="GET",
            path="/iam/v1/accounts/not-an-account/memberships",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(400),
                *_same_body_as(
                    "mbrMalformedAcctBody",
                    "исход НЕ является функцией прав: у вызывающего без единой выдачи ответ тот же, "
                    "потому что права не спрашиваются вовсе",
                ),
            ],
        ),
        Step(
            name="control-wellformed-absent-account-reaches-the-model",
            method="GET",
            path=f"/iam/v1/accounts/{ABSENT_ACCOUNT}/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_grpc_code(7,
                            "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: well-formed accountId рубеж формы ПРОХОДИТ — "
                            "иначе отрицание зеленело бы на крае, отвергающем ВСЯКИЙ accountId"),
            ],
        ),
    ],
))
