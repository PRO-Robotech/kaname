# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Шапка кейса не вправе называть предъявителя принципалом того, кем он не бывает.

ЧТО ЗАЩИЩАЕТСЯ. Набор, который привязывает роль к `{{<id>}}` и читает
`{{<токен>}}`, зависит от того, что эти двое называют ОДНОГО принципала. Изнутри
кейса рассогласование неотличимо от ещё не доехавшей материализации: оно приходит
таймаутом, не в том месте и с неверным объяснением, шестью шагами позже. Модуль
`tests/authz-fixtures/principal_pairings.py` держит это свойство для ВЫДАННЫХ
фикстур — но обходит он значения, а не ШАПКИ, а решение «какой слот взять» человек
принимает, читая именно шапку.

ЧТО ЭТО ЗА ДЕФЕКТ. Шесть шапок iam объявляли `jwtAccountAdminA` предъявителем
`userAAAId`. Такого предъявителя не существует и не может: машинный харнесс
получает `client_credentials`, то есть служебную учётку, а `userAAAId` заведён
ЦЕЛЬЮ ПРИВЯЗКИ. Врезка, прямо это запрещающая, была написана — прозой, в соседнем
модуле, — и повторила судьбу комментария, из-за которого тот модуль и появился.

ГРАНИЦА РАСПОЗНАВАТЕЛЯ ОБЪЯВЛЕНА, А НЕ УМОЛЧАНА. Читается СТРУКТУРНЫЙ блок
зависимостей фикстуры (две табличные формы записи, обе — см. `principal_pairings`),
и НЕ читается свободная проза. Почему — там же: в прозе утверждение неотличимо от
предостережения и от перечня переменных, и замер дал бы каждую третью находку
ложной. Форма, которую распознаватель не читает, остаётся за человеком.

verifies: PRO-Robotech/kacho#1441
"""
import ast
import sys
from pathlib import Path

import pytest


def _services_root() -> Path:
    """Корень каталога сервисов — вверх по дереву, не отсчётом уровней."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "services").is_dir() and (parent / "tests" / "authz-fixtures").is_dir():
            return parent / "services"
    raise AssertionError("корень `services/` не найден — обходить нечего")


def _fixtures_dir() -> Path:
    """Каталог фикстур ищется ВВЕРХ по дереву, а не отсчитывается уровнями.

    Счёт уровней ломается молча при первом же переносе каталога набора: путь
    указывает не туда, модуля нет, и без явного отказа ниже гейт стал бы
    пропуском. Поиск вверх переживает перенос, а его неудача остаётся отказом.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "tests" / "authz-fixtures"
        if (candidate / "principal_pairings.py").is_file():
            return candidate
    raise AssertionError(
        "tests/authz-fixtures/principal_pairings.py не найден ни на одном уровне вверх "
        f"от {Path(__file__).resolve()} — судить нечем, вердикт беспредметен")


sys.path.insert(0, str(_fixtures_dir()))

# Отсутствие модуля-авторитета — ОТКАЗ, а не пропуск: гейт, тихо не нашедший
# того, чем судит, зеленеет на любом дереве и неотличим от исправного.
import principal_pairings as pp  # noqa: E402


def _case_files() -> list[Path]:
    """Кейсы ВСЕХ наборов дерева, а не одного iam.

    Словарь фикстур общий (`tests/authz-fixtures` лежит в корне и читается каждым
    набором), поэтому и класс общий. Гейт, стерегущий один сервис, закрыл бы
    экземпляр, а не класс: следующий набор завёл бы ту же пару, и никто бы не
    заметил.
    """
    return sorted(_services_root().glob("*/tests/newman/cases/*.py"))


def _headers() -> list[tuple[Path, str]]:
    out = []
    for path in _case_files():
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        if doc:
            out.append((path, doc))
    return out


def test_no_case_header_claims_a_binding_target_as_a_principal(capsys):
    headers = _headers()
    findings = []
    for path, doc in headers:
        for lineno, slot, ident in pp.header_principal_claims(doc):
            findings.append(f"{path.relative_to(_services_root())}: шапка+{lineno}: {slot} объявлен предъявителем {ident}")

    # Объём осмотренного печатается ВСЕГДА: «ноль находок» обязано быть отличимо
    # от «ноль прочитанного».
    suites = {p.parents[2].parent.name for p in _case_files()}
    with capsys.disabled():
        print(f"\nперепись: наборов {len(suites)}, файлов кейсов {len(_case_files())}, "
              f"шапок прочитано {len(headers)}, "
              f"целей-только-привязок {len(pp.BINDING_TARGET_ONLY_IDS)}, "
              f"находок {len(findings)}")

    assert headers, "обход пуст — шапок не прочитано ни одной; вердикт беспредметен"
    assert not findings, (
        "шапка кейса называет предъявителя принципалом цели-только-привязки; "
        "такого предъявителя не существует by construction "
        "(tests/authz-fixtures/principal_pairings.py):\n  " + "\n  ".join(findings))


# --- доказательство способности упасть и смолчать -------------------------
#
# Инъекция настоящей формой из дерева, обе стороны по каждой оси. Без второй
# половины гейт ловил бы форму, а не существо, и первый ложный срабат его снял бы.

@pytest.mark.parametrize("line, why", [
    ("  jwtAccountAdminA  — JWT for userAAAId (admin of accountAId)", "прямая запись"),
    ("  jwtAccountAdminA  — JWT for accountA owner (userAAAId)", "прямая, id не первым словом"),
    ("  userAAAId         — User.id of jwtAccountAdminA principal", "обратная запись"),
])
def test_injection_defect_is_found(line, why):
    assert pp.header_principal_claims(line), f"невидим дефект: {why}"


@pytest.mark.parametrize("line, why", [
    ("  jwtHumanCeremony / ceremonyUserId — человек, добытый настоящим входом",
     "человек церемонии — законный предъявитель, не цель-только-привязка"),
    ("  svaAId — User.id of jwtSAA principal",
     "объявленная пара служебной учётки"),
    ("  СУБЪЕКТ ВЫДАЧИ — svaInviteeId, А НЕ userINVId. Читает набор jwtInvitee",
     "предостережение об этом же дефекте — не само утверждение"),
    ("  Pre-conditions: setup.sh (jwtAccountAdminA, accountAId, userAAAId)",
     "перечень переменных, а не утверждение о принципале"),
])
def test_injection_legal_twin_stays_silent(line, why):
    assert not pp.header_principal_claims(line), f"ложная находка: {why}"


def test_recognizer_knows_both_declared_forms():
    """Обе объявленные формы читаются — иначе одна осталась бы вне наблюдения."""
    assert pp.header_principal_claims("x jwtNoBindings — JWT for userNOBId")
    assert pp.header_principal_claims("x userNOBId — User.id of jwtNoBindings principal")
