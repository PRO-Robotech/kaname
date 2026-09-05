# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Пробы стража `audit_gone_principal` — «ресурса нет» под предъявителем без доступа.

ЧТО ЗДЕСЬ ЗАЩИЩАЕТСЯ. Пообъектные чтения `/Get` в iam скрывают существование:
отказ в доступе отдаётся как `404 "<Resource> <id> not found"`, байт-в-байт
равный настоящему промаху. Значит шаг «ресурс исчез после удаления», заданный
предъявителю, у которого доступа к объекту не было никогда, получает 404 и на
ЖИВОМ объекте — то есть зеленеет при любом поведении продукта. Страж требует,
чтобы предъявитель этого шага РАНЬШЕ В ТОМ ЖЕ КЕЙСЕ получил 200 на том же
адресе.

ПОЧЕМУ ПРОБЫ, А НЕ ДОВЕРИЕ К СТРАЖУ. Страж — тоже проверка, и его зелёный
ничего не значит, пока не доказано, что он умеет краснеть НА НАСТОЯЩЕМ ВХОДЕ и
молчать на ЗАКОННОМ БЛИЗНЕЦЕ той же формы. Обе стороны утверждаются по каждой
оси: субъект, объект, форма доказательства доступа, предпосылка самого стража.

ФИКСТУРА НЕ СНИСХОДИТЕЛЬНЕЕ ПРОДУКТА. Синтетические коллекции здесь собираются
НАСТОЯЩИМ сериализатором набора (`gen._RUN.collection`), а не пишутся руками: страж
читает выданный им же комментарий с именем бэрера, и рукописный JSON молча
разошёлся бы с тем, что реально уезжает в прогон.

verifies: PRO-Robotech/kacho#1068
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gen  # noqa: E402

SUITE = Path(__file__).resolve().parent.parent


def _emit(tmp_path, *cases):
    """Собрать коллекцию настоящим сериализатором и положить в каталог для стража."""
    d = tmp_path / "collections"
    d.mkdir(exist_ok=True)
    (d / "synthetic.postman_collection.json").write_text(
        json.dumps(gen._RUN.collection("synthetic", list(cases)), ensure_ascii=False))
    return d


def _gone_case(case_id, *, gone_auth, witness_auth=None, witness_path=None,
               witness_script=None, delete_auth="jwtOwner"):
    path = "/iam/v1/accounts/{{crudAccountId}}"
    steps = []
    if witness_auth is not None:
        steps.append(gen.Step(
            name="witness", method="GET", path=witness_path or path, auth=witness_auth,
            test_script=list(witness_script) if witness_script is not None
            else list(gen.assert_status(200)),
        ))
    steps.append(gen.Step(
        name="delete", method="DELETE", path=path, auth=delete_auth,
        test_script=[*gen.assert_status(200), *gen.save_from_response("j.id", "opId")],
    ))
    steps.append(gen.get_until_gone(path, "Account", auth=gone_auth))
    return gen.Case(id=case_id, title="t", classes=["CRUD"], priority="P0", steps=steps)


# ---------------------------------------------------------------------------
# Настоящий вход: страж КРАСНЕЕТ и называет координату
# ---------------------------------------------------------------------------

def test_gone_step_under_a_principal_that_never_saw_the_object_is_a_finding(tmp_path):
    # Ровно форма #1068: удаляет владелец, а «ушёл?» спрашивает посторонний.
    d = _emit(tmp_path, _gone_case("T-BLIND", gone_auth="jwtStranger"))
    res = gen.audit_gone_principal(d)
    assert res["census"]["gone_steps"] == 1
    assert res["census"]["with_witness"] == 0
    assert len(res["findings"]) == 1
    # Находка обязана НАЗЫВАТЬ виновника — перечень без координаты не чинится.
    assert "T-BLIND" in res["findings"][0]
    assert "jwtStranger" in res["findings"][0]


def test_the_guard_exits_nonzero_and_prints_the_finding(tmp_path, capsys):
    d = _emit(tmp_path, _gone_case("T-BLIND", gone_auth="jwtStranger"))
    assert gen.assert_gone_principal(d, out=sys.stdout) == 1
    out = capsys.readouterr().out
    assert "T-BLIND" in out
    # Объём осмотренного печатается ВСЕГДА: «ноль находок» обязано быть отличимо
    # от «ноль прочитанного».
    assert "осмотрено" in out


# ---------------------------------------------------------------------------
# Законный близнец той же формы: страж МОЛЧИТ
# ---------------------------------------------------------------------------

def test_gone_step_under_the_principal_that_read_200_first_is_silent(tmp_path):
    d = _emit(tmp_path, _gone_case("T-PAIR", gone_auth="jwtOwner", witness_auth="jwtOwner"))
    res = gen.audit_gone_principal(d)
    assert res["census"]["gone_steps"] == 1
    assert res["census"]["with_witness"] == 1
    assert res["findings"] == []


def test_a_successful_mutation_on_the_same_path_counts_as_demonstrated_access(tmp_path):
    # Удаление, отвергнутое авторизацией, вернуло бы 403/404 и не дошло бы до
    # конверта операции — поэтому 200 на нём доказывает, что объект резолвился.
    d = _emit(tmp_path, _gone_case("T-BYDELETE", gone_auth="jwtOwner"))
    res = gen.audit_gone_principal(d)
    assert res["findings"] == []
    assert res["census"]["with_witness"] == 1


def test_the_guard_exits_zero_and_says_so(tmp_path, capsys):
    d = _emit(tmp_path, _gone_case("T-PAIR", gone_auth="jwtOwner", witness_auth="jwtOwner"))
    assert gen.assert_gone_principal(d, out=sys.stdout) == 0
    assert "OK" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Оси различения — по одной, каждая со своим близнецом выше
# ---------------------------------------------------------------------------

def test_a_200_by_a_DIFFERENT_principal_is_not_a_witness(tmp_path):
    # СУБЪЕКТ. Кто-то другой видел объект — это не значит, что видел ЭТОТ.
    d = _emit(tmp_path, _gone_case("T-OTHERSUBJ", gone_auth="jwtStranger",
                                   witness_auth="jwtOwner"))
    assert len(gen.audit_gone_principal(d)["findings"]) == 1


def test_a_200_on_a_DIFFERENT_path_is_not_a_witness(tmp_path):
    # ОБЪЕКТ. Тот же предъявитель видел ДРУГОЙ ресурс — про этот он не сказал ничего.
    d = _emit(tmp_path, _gone_case("T-OTHEROBJ", gone_auth="jwtStranger",
                                   witness_auth="jwtStranger",
                                   witness_path="/iam/v1/accounts/{{accountAId}}"))
    assert len(gen.audit_gone_principal(d)["findings"]) == 1


def test_a_tolerant_oneOf_200_404_is_not_a_witness(tmp_path):
    # ФОРМА. `oneOf([200, 404])` проходит и на невидимом объекте, поэтому доступа
    # не доказывает. Приняв его, страж выдал бы послабление ровно тому классу,
    # который ловит.
    tolerant = ["pm.test('gone or there', () => pm.expect(pm.response.code)"
                ".to.be.oneOf([200, 404]));"]
    d = _emit(tmp_path, _gone_case("T-TOLERANT", gone_auth="jwtStranger",
                                   witness_auth="jwtStranger", witness_script=tolerant))
    assert len(gen.audit_gone_principal(d)["findings"]) == 1


def test_the_witness_must_come_BEFORE_the_gone_step(tmp_path):
    # ПОРЯДОК. Чтение ПОСЛЕ снятия доказательством доступа до снятия не является:
    # оно само есть тот самый 404, который надо было отличить.
    path = "/iam/v1/accounts/{{crudAccountId}}"
    case = gen.Case(
        id="T-ORDER", title="t", classes=["CRUD"], priority="P0",
        steps=[
            gen.Step(name="delete", method="DELETE", path=path, auth="jwtOwner",
                     test_script=[*gen.assert_status(200)]),
            gen.get_until_gone(path, "Account", auth="jwtStranger"),
            gen.Step(name="late-witness", method="GET", path=path, auth="jwtStranger",
                     test_script=[*gen.assert_status(200)]),
        ])
    assert len(gen.audit_gone_principal(_emit(tmp_path, case))["findings"]) == 1


# ---------------------------------------------------------------------------
# Предпосылка самого стража
# ---------------------------------------------------------------------------

def test_nothing_to_read_is_a_FAILURE_not_a_clean_verdict(tmp_path, capsys):
    empty = tmp_path / "collections"
    empty.mkdir()
    assert gen.assert_gone_principal(empty, out=sys.stdout) == 1
    assert "ноль прочитанного" in capsys.readouterr().out


def test_zero_recognised_gone_steps_is_a_FAILURE_marker_drift(tmp_path, capsys):
    # Если текст утверждения изменится, страж перестанет опознавать шаги и будет
    # печатать «чисто», ничего не проверив. Именно это и случилось при первой
    # редакции: `json.dumps` экранирует не-ASCII, и дословная копия строки не
    # нашла НИ ОДНОГО шага.
    case = gen.Case(id="T-NOGONE", title="t", classes=["CRUD"], priority="P0",
                    steps=[gen.Step(name="get", method="GET", path="/iam/v1/accounts/{{a}}",
                                    auth="jwtOwner", test_script=[*gen.assert_status(200)])])
    assert gen.assert_gone_principal(_emit(tmp_path, case), out=sys.stdout) == 1
    assert "ПРЕДПОСЫЛКА СТРАЖА ЛОЖНА" in capsys.readouterr().out


def test_the_marker_is_derived_from_the_helper_not_copied(tmp_path):
    # Копия текста разошлась бы с helper'ом молча. Проба утверждает СХОДИМОСТЬ:
    # маркер обязан находиться в скрипте, который helper реально печатает.
    col = gen._RUN.case_item(_gone_case("T-MARK", gone_auth="jwtOwner", witness_auth="jwtOwner"))
    # Склейка ТА ЖЕ, что у стража (`_test_code`): повторный `json.dumps` удвоил бы
    # обратную косую, и проба утверждала бы про строку, которой страж не видит.
    blob = "\n".join(line for it in col["item"] for ev in it.get("event", [])
                     if ev.get("listen") == "test" for line in ev["script"]["exec"])
    assert gen._GONE_MARK in blob


# ---------------------------------------------------------------------------
# Дерево, а не только синтетика
# ---------------------------------------------------------------------------

def test_the_shipped_collections_carry_no_vacuous_gone_assertion():
    res = gen.audit_gone_principal(SUITE / "collections")
    c = res["census"]
    # Ноль опознанных шагов означал бы, что проба ниже ничего не утверждает.
    assert c["gone_steps"] > 0, "ни одного утверждения о снятии не опознано в дереве"
    assert res["findings"] == [], res["findings"]
    assert c["with_witness"] == c["gone_steps"]
