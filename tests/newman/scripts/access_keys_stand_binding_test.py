# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Доверяющая сторона и происхождение ключей доступа — из окружения СТЕНДА (kaname#684).

ПРЕДМЕТ. Имя доверяющей стороны и происхождение консоли — величины установки, а
не набора: автономный стенд службы берёт их из своего профиля поставки
(`deploy/values.prod.yaml`, `authn.accessKeys`), стенд платформы объявляет свои —
из адреса консоли своего пространства. Набор `kaname-access-keys` прежде вшивал
величины профиля литералом в каждый шаг, и на стенде с другим объявлением
церемония собиралась под чужое имя: продукт честно отказывал, а отказ читался
дефектом.

Теперь величины стенда называет посев личностей с ключом
(`tests/authz-fixtures/seed_key_person.py`): он читает переменные
`KANAME_STAND_ACCESS_KEYS_RP_ID` и `KANAME_STAND_ACCESS_KEYS_ORIGIN` (без них —
профиль) и пишет в окружение набора ключи `accessKeysRpId` и `accessKeysOrigin`.
Коллекция читает их в момент шага; незаписанный ключ — величина профиля.

ЧТО ДЕРЖИТ ЭТА ПРОБА:

  * в скриптах коллекции нет литерала профиля вне формы «ключ окружения, иначе
    профиль» — ни имени, ни происхождения, ни выведенных из имени «чужих» величин;
  * формы с запасным значением есть у обоих ключей (положительный контроль:
    пустой обход не зеленит);
  * распознаватель находит голый литерал и молчит на законной форме (инъекция в
    обе стороны);
  * оба ключа объявлены шаблоном окружения пустыми и названы посевом в перечне
    записываемых (`--minted-keys`): перепись долга набора зачитывает их посеву.

Различение величин в самом посеве (переменные против профиля, одна из двух,
происхождение вне имени) доказывает его `--self-test`.
"""

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
COLLECTION = ROOT / "tests" / "newman" / "collections" / "kaname-access-keys.postman_collection.json"
TEMPLATE = ROOT / "tests" / "newman" / "environments" / "local.postman_environment.template.json"
SEED = ROOT / "tests" / "authz-fixtures" / "seed_key_person.py"
PROFILE = ROOT / "deploy" / "values.prod.yaml"

RP_KEY, ORIGIN_KEY = "accessKeysRpId", "accessKeysOrigin"


def _profile_rp_and_origin() -> tuple[str, str]:
    found = re.findall(r"^  accessKeys:\n    rpId: (\S+)\n    origins:\n      - (\S+)\n",
                       PROFILE.read_text(encoding="utf-8"), re.M)
    assert len(found) == 1, f"блок authn.accessKeys найден {len(found)} раз в профиле — ждали ровно один"
    return found[0]


def _script_lines(node) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for ev in node.get("event", []) or []:
            out.extend((ev.get("script") or {}).get("exec", []) or [])
        for child in node.get("item", []) or []:
            out.extend(_script_lines(child))
    return out


def _fallback(key: str, value: str) -> str:
    return f"pm.environment.get('{key}') || '{value}'"


def bare_binding_literals(lines: list[str], rp: str, origin: str) -> list[str]:
    """Строки, несущие величину профиля ВНЕ формы «ключ окружения, иначе профиль».

    Имя доверяющей стороны — подстрока и происхождения, и выведенных «чужих»
    величин (`https://elsewhere.<имя>`, `elsewhere-<имя>`), поэтому одного поиска
    имени после вычета законных форм хватает на все четыре."""
    lawful = (_fallback(RP_KEY, rp), _fallback(ORIGIN_KEY, origin))
    found = []
    for ln in lines:
        rest = ln
        for form in lawful:
            rest = rest.replace(form, "")
        if rp in rest:
            found.append(ln)
    return found


def _collection_lines() -> list[str]:
    doc = json.loads(COLLECTION.read_text(encoding="utf-8"))
    lines = _script_lines(doc)
    assert lines, f"в {COLLECTION.name} не прочитано ни одной строки скрипта — обход пуст, вердикта нет"
    return lines


def test_collection_carries_no_profile_literal_outside_the_environment_form():
    rp, origin = _profile_rp_and_origin()
    lines = _collection_lines()
    bare = bare_binding_literals(lines, rp, origin)
    print(f"строк скриптов осмотрено: {len(lines)}; с голым литералом профиля: {len(bare)}")
    assert not bare, ("величина профиля вшита в шаг мимо ключа окружения — на стенде с другим "
                      f"объявлением церемония соберётся под чужое имя: {bare[0][:160]!r}")


def test_collection_reads_both_keys_with_the_profile_fallback():
    rp, origin = _profile_rp_and_origin()
    text = "\n".join(_collection_lines())
    n_rp, n_origin = text.count(_fallback(RP_KEY, rp)), text.count(_fallback(ORIGIN_KEY, origin))
    print(f"форм «{RP_KEY}, иначе профиль»: {n_rp}; «{ORIGIN_KEY}, иначе профиль»: {n_origin}")
    assert n_rp > 0 and n_origin > 0, "коллекция не читает величины стенда из окружения ни в одном шаге"


def test_injection_bare_literal_is_found_and_lawful_twin_is_silent():
    rp, origin = "rp.example.invalid", "https://console.rp.example.invalid"
    bare = [f"_ak.register({{ rpId: '{rp}', origin: '{origin}' }});",
            f"pm.request.headers.upsert({{key: 'Origin', value: 'https://elsewhere.{rp}'}});",
            f"pm.expect(__j.rpId).to.eql('{rp}');"]
    lawful = [f"_ak.register({{ rpId: ({_fallback(RP_KEY, rp)}), origin: ({_fallback(ORIGIN_KEY, origin)}) }});",
              f"pm.request.headers.upsert({{key: 'Origin', value: 'https://elsewhere.' + ({_fallback(RP_KEY, rp)})}});"]
    assert bare_binding_literals(bare, rp, origin) == bare, "голый литерал не распознан"
    assert bare_binding_literals(lawful, rp, origin) == [], "законная форма принята за голый литерал"


def test_template_declares_both_keys_empty():
    doc = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    values = {v.get("key"): v for v in doc.get("values", [])}
    for key in (RP_KEY, ORIGIN_KEY):
        assert key in values, f"шаблон окружения не объявляет {key}"
        assert values[key].get("value", "") == "", (f"{key} в шаблоне не пуст — величина стенда "
                                                     "выписана литералом, а не записана посевом")
        assert "KANAME_STAND_ACCESS_KEYS_" in values[key].get("description", ""), (
            f"описание {key} не называет переменную стенда, из которой его пишет посев")


def test_seed_names_both_keys_among_minted():
    proc = subprocess.run([sys.executable, str(SEED), "--minted-keys"], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    minted = set(proc.stdout.split())
    assert {RP_KEY, ORIGIN_KEY} <= minted, f"посев не называет {RP_KEY}/{ORIGIN_KEY} записываемыми: {sorted(minted)}"


# ── потолок ключей человека (kaname#699) ─────────────────────────────────────
#
# Потолок — величина установки, как имя и происхождение: автономный стенд службы
# берёт профильную (`ownCeilings.accessKeysPerUser`), стенд платформы объявляет
# свою. Набор прежде вшивал профильную при сборке — и числом заводимых ключей, и
# числом в утверждениях перечня, — и на стенде с другим потолком кейсы потолка
# краснели не по продукту. Теперь посев пишет величину стенда ключом
# `accessKeysCeiling` (переменная `KANAME_STAND_ACCESS_KEYS_CEILING`, без неё —
# профиль), а шаги потолка читают её в момент исполнения.

CEILING_KEY = "accessKeysCeiling"
CEILING_ENV = "KANAME_STAND_ACCESS_KEYS_CEILING"
# Шаги, чьё утверждение ЗАВИСИТ от потолка: перечни человека A после заполнения
# (Ф7-37, Ф7-34, Ф7-47) и отказ сверх потолка, называющий действующую величину.
_CEILING_STEP = re.compile(r":: ak(?:37-list-|34-list-|47-list-a-|37-over-op$)")


def _profile_ceiling() -> int:
    found = re.findall(r"^  accessKeysPerUser: (\d+)\s*$", PROFILE.read_text(encoding="utf-8"), re.M)
    assert len(found) == 1, f"ownCeilings.accessKeysPerUser найден {len(found)} раз в профиле — ждали ровно один"
    return int(found[0])


def _ceiling_form(ceiling: int) -> str:
    return f"parseInt(pm.environment.get('{CEILING_KEY}') || '{ceiling}', 10)"


def _items(node, out=None) -> list[tuple[str, list[str]]]:
    out = [] if out is None else out
    for child in node.get("item", []) or []:
        if "request" in child:
            lines: list[str] = []
            for ev in child.get("event", []) or []:
                lines.extend((ev.get("script") or {}).get("exec", []) or [])
            out.append((child.get("name", ""), lines))
        else:
            _items(child, out)
    return out


def ceiling_steps_without_stand_value(items: list[tuple[str, list[str]]], ceiling: int) -> list[str]:
    """Шаги потолка, не читающие величину стенда формой «ключ окружения, иначе профиль».

    Судится ШАГ, а не число в строке: у человека B ровно три ключа при любом
    потолке, и его перечень законно несёт ту же цифру, что профильный потолок."""
    form = _ceiling_form(ceiling)
    return [name for name, lines in items if _CEILING_STEP.search(name) and form not in "\n".join(lines)]


def fill_registrations(items: list[tuple[str, list[str]]]) -> list[str]:
    """Шаги заведения ключей заполнения: их число не обязано зависеть от потолка."""
    return [name for name, _ in items if re.search(r":: ak37-fill(?:-[^:]*)?-begin$", name)]


def test_ceiling_steps_read_the_stand_value_with_the_profile_fallback():
    ceiling = _profile_ceiling()
    items = _items(json.loads(COLLECTION.read_text(encoding="utf-8")))
    judged = [n for n, _ in items if _CEILING_STEP.search(n)]
    bare = ceiling_steps_without_stand_value(items, ceiling)
    print(f"шагов осмотрено: {len(items)}; шагов потолка: {len(judged)}; без величины стенда: {len(bare)}")
    assert len(judged) >= 6, f"шагов потолка найдено {len(judged)} — обход не узнаёт их, вердикта нет"
    assert not bare, f"шаг потолка судит профильную величину, вшитую при сборке: {bare}"


def test_fill_is_one_ceremony_repeated_up_to_the_stand_ceiling():
    items = _items(json.loads(COLLECTION.read_text(encoding="utf-8")))
    fills = fill_registrations(items)
    assert len(fills) == 1, (f"шагов заведения ключей заполнения {len(fills)} — число вшито при сборке и "
                             f"равно профильному потолку минус два: {fills}")
    loop = [ln for n, lines in items if n.endswith(":: ak37-fill-op") for ln in lines]
    assert any("setNextRequest('IAM-ACCESSKEY-BVA-CEILING :: ak37-fill-begin')" in ln for ln in loop), (
        "опрос заведения не возвращает к испытанию — заполнение не доходит до потолка стенда")
    assert any(_ceiling_form(_profile_ceiling()) in ln for ln in loop), "повтор заведения не сверяется с потолком стенда"


def test_injection_profile_ceiling_in_a_step_is_found_and_stand_form_is_silent():
    ceiling = 3
    bare = [("C :: ak37-list-full", ["pm.test('AK37-LIST-FULL: ключей у человека 3', () => "
                                     "pm.expect(_akL.length).to.eql(3));"]),
            ("C :: ak37-over-op", ["pm.expect(__m.indexOf('3') >= 0).to.eql(true);"])]
    lawful = [("C :: ak37-list-full", [f"pm.expect(_akL.length).to.eql({_ceiling_form(ceiling)});"]),
              ("C :: ak27-list-b-kept", ["pm.expect(_akL.length).to.eql(3);"])]
    assert ceiling_steps_without_stand_value(bare, ceiling) == [n for n, _ in bare], "вшитый потолок не распознан"
    assert ceiling_steps_without_stand_value(lawful, ceiling) == [], (
        "законная форма либо перечень человека B (три ключа при любом потолке) приняты за вшитый потолок")
    assert fill_registrations([("C :: ak37-fill-k3-begin", []), ("C :: ak37-fill-k4-begin", [])]) == [
        "C :: ak37-fill-k3-begin", "C :: ak37-fill-k4-begin"], "заполнение по слоту не распознано"


def test_template_declares_the_ceiling_key_empty():
    doc = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    values = {v.get("key"): v for v in doc.get("values", [])}
    assert CEILING_KEY in values, f"шаблон окружения не объявляет {CEILING_KEY}"
    assert values[CEILING_KEY].get("value", "") == "", f"{CEILING_KEY} в шаблоне не пуст — потолок выписан литералом"
    assert CEILING_ENV in values[CEILING_KEY].get("description", ""), (
        f"описание {CEILING_KEY} не называет переменную стенда {CEILING_ENV}")


def test_seed_names_the_ceiling_key_among_minted():
    proc = subprocess.run([sys.executable, str(SEED), "--minted-keys"], capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert CEILING_KEY in set(proc.stdout.split()), f"посев не называет {CEILING_KEY} записываемым"


def test_seed_tells_the_stand_ceiling_from_the_profile():
    """Заданная величина и профиль различимы: самопроверка посева гоняет обе стороны."""
    proc = subprocess.run([sys.executable, str(SEED), "--self-test"], capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-3000:]
    for label in ("потолок: переменной стенда нет — величина профиля",
                  "потолок: переменная названа — величина стенда",
                  "потолок: не число — условие не создано",
                  "потолок: ниже трёх — условие не создано"):
        assert label in out, f"самопроверка посева не различает исход «{label}»"



# ── адрес шага собирается ДО предусловия шага (kaname#699, прогон на стенде) ──
#
# Шаг собственного фронта службы получает адрес строкой оснастки
# `pm.request.url = <фронт> + pm.variables.replaceIn('<путь>')` — первой в
# предусловии, раньше предусловия самого шага. Переменная пути, которую шаг
# назначает СВОИМ предусловием, подставляется поэтому ПРОШЛОЙ величиной: при
# повторе шага (`setNextRequest`) запрос уходит по адресу прошлого захода. Так
# уборка человека A на стенде снимала один и тот же ключ дважды (второй — 404) и
# оставляла пять ключей. Переменную пути назначает шаг ВЫШЕ — своим утверждением.

_URL_REWRITE = re.compile(r"pm\.request\.url = .*pm\.variables\.replaceIn\('([^']*)'\)")
_ENV_SET = re.compile(r"pm\.environment\.set\('([A-Za-z0-9_]+)'")


def _prerequest_items(node, out=None) -> list[tuple[str, list[str]]]:
    out = [] if out is None else out
    for child in node.get("item", []) or []:
        if "request" in child:
            lines: list[str] = []
            for ev in child.get("event", []) or []:
                if ev.get("listen") == "prerequest":
                    lines.extend((ev.get("script") or {}).get("exec", []) or [])
            out.append((child.get("name", ""), lines))
        else:
            _prerequest_items(child, out)
    return out


def path_vars_set_after_the_url_is_built(items: list[tuple[str, list[str]]]) -> list[str]:
    """Шаги, чьё предусловие назначает переменную пути ПОСЛЕ сборки адреса."""
    found = []
    for name, lines in items:
        built = [(i, m.group(1)) for i, ln in enumerate(lines) if (m := _URL_REWRITE.search(ln))]
        if not built:
            continue
        at, path = built[0]
        late = {v for ln in lines[at + 1:] for v in _ENV_SET.findall(ln) if "{{" + v + "}}" in path}
        found.extend(f"{name} ← {v}" for v in sorted(late))
    return found


def test_no_step_sets_its_own_path_variable_after_the_url_is_built():
    items = _prerequest_items(json.loads(COLLECTION.read_text(encoding="utf-8")))
    built = [n for n, lines in items if any(_URL_REWRITE.search(ln) for ln in lines)]
    late = path_vars_set_after_the_url_is_built(items)
    print(f"шагов осмотрено: {len(items)}; с адресом от оснастки: {len(built)}; "
          f"переменная пути назначена после сборки адреса: {len(late)}")
    assert built, "ни у одного шага не узнана сборка адреса оснасткой — обход пуст, вердикта нет"
    assert not late, ("шаг назначает переменную своего пути после того, как оснастка собрала адрес — "
                      f"при повторе запрос уйдёт по прошлой величине: {late}")


def test_injection_late_path_variable_is_found_and_step_above_is_silent():
    rewrite = "  pm.request.url = __cfgUrl + pm.variables.replaceIn('/iam/v1/users/{{u}}/accessKeys/{{k}}');"
    late = [("C :: drop-next", [rewrite, "pm.environment.set('k', JSON.parse(q)[0]);"])]
    lawful = [("C :: drop-next", [rewrite, "pm.environment.set('other', '1');"]),
              ("C :: drop-next-op", ["pm.environment.set('k', JSON.parse(q)[0]);"]),
              ("C :: drop-before", ["pm.environment.set('k', '1');", rewrite])]
    assert path_vars_set_after_the_url_is_built(late) == ["C :: drop-next ← k"], "поздняя переменная пути не найдена"
    assert path_vars_set_after_the_url_is_built(lawful) == [], (
        "законные формы (чужая переменная, назначение шагом выше либо до сборки адреса) приняты за находку")

if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as e:
                failed += 1
                print(f"  ПРОВАЛ {name}: {e}")
    sys.exit(1 if failed else 0)
