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
