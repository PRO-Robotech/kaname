# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set церемонии `authorization_code` нашими силами (приёмка LINE-A-1, kaname#423).

ПРЕДМЕТ — поверхность выдачи службы, а не край платформы: точка авторизации
`GET /iam/v1/authorize`, полосы `authorization_code` и `refresh_token`
токен-эндпоинта `POST /iam/v1/token`. Человек входит НАШИМ входом (полоса входа,
контракт Ф1), а выданный предъявитель принимает собственный публичный фронт
службы. Кейсы написаны чёрным ящиком — по приёмке (kacho-workspace,
`docs/specs/sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md`,
sha256 `b755886f…`) и по странице контракта `docs/content/api/oauth-ceremony.mdx`,
а не по коду обработчиков.

АДРЕСА — ТРИ ПОВЕРХНОСТИ СЛУЖБЫ, и у каждой своя переменная:

  {{loginLaneBaseUrl}}         — слушатель формы (вход паролем; посадка `own`)
  {{iamRegistryTokenBaseUrl}}  — поверхность выдачи (:9096): токен-эндпоинт и
                                 церемония стоят на ней и больше нигде
  {{ownRestBaseUrl}}           — собственный публичный фронт (:9098): рутинный
                                 глагол `GET /iam/v1/me` под выданным токеном

УСЛОВИЕ СТЕНДА — посев, а не глагол продукта, и это решение приёмки. Её §1:
«клиент существует как Given, сконструированный посевом»; собственный реестр
посадки `own` сегодня заводит интерактивного клиента ПУБЛИЧНЫМ (kaname#405), а
Р3 требует конфиденциального. Поэтому клиентов набор не заводит, а читает:

  {{loginLaneEmail}} {{loginLanePassword}} — человек со способом входа паролем
                                             (`seed_login_lane.py`)
  {{oauthClientId}} {{oauthClientSecret}}  — конфиденциальный клиент `ACTIVE`
                                             (секрет на токен-эндпоинте)
  {{oauthRedirectUri}} {{oauthRedirectUriAlt}} — ДВА адреса возврата, оба
                                             зарегистрированы у этого клиента
  {{oauthOtherClientId}} {{oauthOtherClientSecret}} — второй конфиденциальный
                                             клиент `ACTIVE` (сценарий 16)

У обоих клиентов получатель выдаваемого токена обязан включать адресата
собственного публичного фронта: иначе фронт отвергнет годный токен, и
сценарий 18 покраснеет не о церемонии. Непосеянный ключ — «условие не создано»
помеченным утверждением (третья категория), а не зелёное и не красное.

ПЕЧЕНЬЯ — ТОЛЬКО ЯВНЫМ ЗАГОЛОВКОМ. Каждый шаг выключает банку прогонщика
(`cookie_jar=False`): порт границей печенья не является, и без этого отрицание
«сессии нет» (03) получало бы сессию из банки. Перенаправлению точки авторизации
прогонщик не следует (`follow_redirects=False`): предмет — сам ответ `302`.

ТОКЕН НЕ ПРЕДЪЯВЛЯЕТСЯ ДО ОТЗЫВА, И ЭТО СВОЙСТВО ФРОНТА, А НЕ ПОСЛАБЛЕНИЕ.
Собственный фронт кэширует вердикт «не отозван» на `revocation-cache-ttl`
посадки — это объявленное окно отзыва. Поэтому в 13 и 21 токен, который обязан
оказаться отозванным, впервые предъявляется ПОСЛЕ повтора: вердикта в кэше нет,
отказ обязан прийти сразу, и ожидания здесь нет ни одного.

Coverage (техники: классы эквивалентности · границы · переходы состояний кода и
токена обновления · угадывание ошибок):
  IAM-AUTHCODE-OK-ISSUE-EXCHANGE-ACCEPT     — 02→10→18: код выдан перенаправлением,
                                              обмен даёт наш токен, фронт его принимает
  IAM-AUTHCODE-BVA-STATE-AT-FLOOR           — 30: `state` ровно 22 знака → код (граница)
  IAM-AUTHCODE-NEG-STATE-BELOW-FLOOR        — 29: `state` нет либо 21 знак → только
                                              `error=invalid_request` (граница снизу)
  IAM-AUTHCODE-NEG-NO-SESSION               — 03: сессии нет → 401 login_required;
                                              близнец с сессией → код
  IAM-AUTHCODE-NEG-REDIRECT-UNREGISTERED    — 04: чужой адрес возврата → 400 без
                                              перенаправления; та же страница, что у
                                              неизвестного клиента
  IAM-AUTHCODE-NEG-PKCE-MISSING-OR-PLAIN    — 06: без PKCE либо `plain` → только
                                              `error=invalid_request`
  IAM-AUTHCODE-NEG-WRONG-VERIFIER           — 11: неверный `code_verifier` → invalid_grant,
                                              и код погашен
  IAM-AUTHCODE-NEG-CLIENT-UNAUTHENTICATED   — 12: клиент не доказал себя → 401 invalid_client
  IAM-AUTHCODE-NEG-CODE-REPLAY-REVOKES      — 13: повтор кода → invalid_grant и отзыв
                                              выданного по нему
  IAM-AUTHCODE-NEG-REDIRECT-MISMATCH        — 15: другой (зарегистрированный) адрес на
                                              обмене → invalid_grant
  IAM-AUTHCODE-NEG-FOREIGN-CLIENT           — 16: код другого клиента → invalid_grant
  IAM-AUTHCODE-OK-REFRESH-ROTATES           — 20: токен обновления оборачивается по цепочке
  IAM-AUTHCODE-NEG-REFRESH-REPLAY-REVOKES-FAMILY — 21: повтор обёрнутого → invalid_grant
                                              и отзыв семейства; соседнее семейство живо
  IAM-AUTHCODE-NEG-CODE-EXPIRED             — 14: код старше 60 с → invalid_grant
"""

HOME = "kaname"

CASES = []

_AUTHORIZE = "/iam/v1/authorize"
_TOKEN = "/iam/v1/token"
_ME = "/iam/v1/me"
_CSRF = "/iam/v1/auth/csrf"
_LOGIN = "/iam/v1/auth/login"
_DISCOVERY = "/.well-known/oauth-authorization-server"

_ISSUANCE = "iamRegistryTokenBaseUrl"
_ISSUANCE_WHY = ("поверхность выдачи службы: точка авторизации и токен-эндпоинт церемонии "
                 "стоят на ней и больше нигде")
_LANE_WHY = ("слушатель полосы входа паролем службы; поднимается только посадкой `own` — "
             "на посадке `external` его нет, и это условие, которого стенд не создал")
_OWN_WHY = ("собственный публичный фронт службы: рутинный глагол, которым проверяется, что "
            "выданный церемонией токен годен")

# Адрес источника, который на живом проводе ставит край полосы входа. Свой, а не
# общий с соседними наборами: окно частоты по источнику у них не общее.
_SOURCE = "203.0.113.12"

# Пол `state` — НАША величина (приёмка Р13): запись BASE64URL от 16 байтов.
_STATE_FLOOR = 22
# Срок кода по контракту — 60 с (`oauth-ceremony.mdx`, «Обмен кода»). Ждётся
# срок, а не готовность: опрос кода невозможен — первое же предъявление гасит его.
_CODE_EXPIRY_WAIT_MS = 63_000
# Песочница newman обрывает скрипт дольше 30 с (замер: «Script execution timed out
# after 30000ms», весь прогон без отчёта). Поэтому срок отсчитывается петлёй:
# шаг ждёт не дольше `_CLOCK_TURN_MS` и повторяет себя, пока срок не выдержан.
_CLOCK_TURN_MS = 5_000
_CLOCK_CAP = 30

_CLIENT = ("oauthClientId", "oauthClientSecret")
_OTHER_CLIENT = ("oauthOtherClientId", "oauthOtherClientSecret")
_REDIRECT = "oauthRedirectUri"
_REDIRECT_ALT = "oauthRedirectUriAlt"


def _env(key):
    return f"pm.environment.get({js_str(key)})"


def _need(*keys):
    """Посеянные ключи стенда — третья категория, если их нет, с именами ключей."""
    cond = " || ".join(f"!{_env(k)}" for k in keys)
    return [
        f"if ({cond}) {{",
        *precondition_not_met(
            "посев стенда: " + ", ".join(keys) + " заданы",
            "посев стенда посадки own не завёл конфиденциального интерактивного клиента "
            "церемонии (приёмка LINE-A-1 §1: клиент — Given посевом). Шаг не может "
            "исполниться, и молча выпасть ему нельзя.",
            indent="  "),
        "}",
    ]


def _prelude():
    """Случайность и PKCE S256 средствами песочницы (RFC 7636 §4.2)."""
    return [
        "const _acB64u = (wa) => { let s = CryptoJS.enc.Base64.stringify(wa).split('+').join('-')"
        ".split('/').join('_'); while (s.endsWith('=')) { s = s.slice(0, -1); } return s; };",
        "const _acRand = (bytes) => _acB64u(CryptoJS.lib.WordArray.random(bytes));",
        "const _acS256 = (v) => _acB64u(CryptoJS.SHA256(v));",
    ]


def _parse_location():
    """`Location` ответа — в адрес и параметры строки запроса (URL песочницы нет)."""
    return [
        "const _acParse = (u) => { const s = String(u || ''); const i = s.indexOf('?'); const q = {};",
        "  if (i >= 0) { s.slice(i + 1).split('#')[0].split('&').forEach((kv) => { if (!kv) { return; }",
        "    const j = kv.indexOf('='); const dec = (x) => decodeURIComponent(x.split('+').join(' '));",
        "    const k = dec(j < 0 ? kv : kv.slice(0, j)); (q[k] = q[k] || []).push(j < 0 ? '' : dec(kv.slice(j + 1))); }); }",
        "  return { base: i < 0 ? s.split('#')[0] : s.slice(0, i), q: q }; };",
        "const _acLoc = pm.response.headers.get('Location') || '';",
        "const _acGot = _acParse(_acLoc);",
    ]


def _no_location(label):
    return [
        f"pm.test({js_str(label + ': перенаправления нет — заголовка Location в ответе нет')}, () => {{",
        "  const loc = pm.response.headers.get('Location');",
        "  pm.expect(loc === null || loc === undefined || loc === '', 'Location=' + String(loc)).to.eql(true);",
        "});",
    ]


def _lane(path):
    return [
        *require_env_url("loginLaneBaseUrl", path, _LANE_WHY),
        f"pm.request.headers.upsert({{key: 'X-Forwarded-For', value: {js_str(_SOURCE)}}});",
    ]


def _cookie_from(name, var, label):
    """Захват значения печенья из `Set-Cookie`; отсутствие — красное."""
    return [
        "{",
        "  const __sc = pm.response.headers.all()"
        f".filter(h => h.key.toLowerCase() === 'set-cookie' && h.value.startsWith({js_str(name + '=')}));",
        f"  pm.test({js_str(label + ': ответ ставит печенье ' + name)}, () => "
        "pm.expect(__sc.length, 'Set-Cookie ' + " + js_str(name) + ").to.eql(1));",
        f"  if (__sc.length === 1) {{ pm.environment.set({js_str(var)}, __sc[0].value.split(';')[0].slice({len(name) + 1})); }}",
        "}",
    ]


def _v(tag, what):
    """Имя переменной кейса: префикс, тег кейса, предмет."""
    return f"_ac{tag}{what}"


def _login(tag):
    """Вход НАШИМ входом (Ф1) — Given «человек с аутентифицированной сессией».

    Шаги посева утверждают СВОЙ исход: упади вход — виновником назовётся он, а
    не точка авторизации тремя шагами позже.
    """
    csrf, form, sess = _v(tag, "Csrf"), _v(tag, "FormCookie"), _v(tag, "SessionCookie")
    user, level, at = _v(tag, "UserId"), _v(tag, "Level"), _v(tag, "LoginAt")
    return [
        Step(
            name=f"{tag}-login-csrf",
            method="GET",
            path=_CSRF + "?form=login",
            pre_script=[*_need("loginLaneEmail", "loginLanePassword"), *_lane(_CSRF + "?form=login")],
            insecure_tls=True,
            auth="anonymous",
            cookie_jar=False,
            test_script=[
                *assert_status(200),
                "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
                "pm.test('ВХОД: признак формы выдан', () => pm.expect(j.csrfToken, 'csrfToken').to.be.a('string').and.not.empty);",
                f"if (j.csrfToken) {{ pm.environment.set({js_str(csrf)}, j.csrfToken); }}",
                *_cookie_from("kaname_form", form, "ВХОД"),
            ],
        ),
        Step(
            name=f"{tag}-login",
            method="POST",
            path=_LOGIN,
            body={"email": "{{loginLaneEmail}}", "password": "{{loginLanePassword}}",
                  "csrfToken": "{{" + csrf + "}}"},
            pre_script=[
                *_lane(_LOGIN),
                f"pm.environment.unset({js_str(sess)}); pm.environment.unset({js_str(user)});",
                f"pm.environment.set({js_str(at)}, String(Math.floor(Date.now() / 1000)));",
                f"pm.request.headers.upsert({{key: 'Cookie', value: 'kaname_form=' + ({_env(form)} || '')}});",
            ],
            insecure_tls=True,
            auth="anonymous",
            cookie_jar=False,
            test_script=[
                *assert_status(200),
                "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
                "pm.test('ВХОД: тело называет человека', () => pm.expect(j.user && j.user.id, 'user.id').to.be.a('string').and.not.empty);",
                "pm.test('ВХОД: сессия уровня 1 — вход паролем без второго фактора', () => "
                "pm.expect(j.session && j.session.assuranceLevel, 'session.assuranceLevel').to.eql('1'));",
                f"if (j.user && j.user.id) {{ pm.environment.set({js_str(user)}, j.user.id); }}",
                f"if (j.session) {{ pm.environment.set({js_str(level)}, String(j.session.assuranceLevel)); }}",
                *_cookie_from("kaname_session", sess, "ВХОД"),
            ],
        ),
    ]


def _authorize(tag, slot, name, *, test_script, redirect=None, client=None,
               state_len=43, challenge="S256", response_type="code", session=True,
               reuse=None):
    """Запрос авторизации (приёмка 02): PKCE S256 и `state` не ниже пола.

    Каждый параметр, отличающий отрицание от близнеца, — аргумент, чтобы
    отличие оставалось ровно в одном факте. `redirect` и `client` — выражения
    JS (по умолчанию — посеянный адрес и посеянный клиент). `reuse` — слот, чей
    запрос повторяется дословно (03: тот же запрос без сессии и с сессией).
    """
    q, v, s, r = _v(tag, f"Q{slot}"), _v(tag, f"Verifier{slot}"), _v(tag, f"State{slot}"), _v(tag, f"Redirect{slot}")
    code = _v(tag, f"Code{slot}")
    redirect = redirect or _env(_REDIRECT)
    client = client or _env(_CLIENT[0])
    pre = [*_need(*_CLIENT, _REDIRECT, _REDIRECT_ALT), *_prelude(), f"pm.environment.unset({js_str(code)});"]
    if reuse is not None:
        rq, rv, rs, rr = (_v(tag, f"{w}{reuse}") for w in ("Q", "Verifier", "State", "Redirect"))
        pre += [f"pm.environment.set({js_str(x)}, {_env(y)} || '');"
                for x, y in ((q, rq), (v, rv), (s, rs), (r, rr))]
    else:
        pre += [
            "const _acV = _acRand(32);",
            f"pm.environment.set({js_str(v)}, _acV);",
            ("const _acS = null;" if state_len is None
             else f"const _acS = _acRand(48).slice(0, {int(state_len)});"),
            f"pm.environment.set({js_str(s)}, _acS === null ? '' : _acS);",
            f"const _acR = {redirect};",
            f"pm.environment.set({js_str(r)}, _acR || '');",
            "const _acP = [",
            f"  ['response_type', {js_str(response_type)}],",
            f"  ['client_id', {client}],",
            "  ['redirect_uri', _acR],",
            "  ['scope', 'openid'],",
            "  ['state', _acS],",
            {"S256": "  ['code_challenge', _acS256(_acV)], ['code_challenge_method', 'S256'],",
             "plain": "  ['code_challenge', _acV], ['code_challenge_method', 'plain'],",
             None: ""}[challenge],
            "];",
            "const _acQ = _acP.filter((p) => p[1] !== null).map((p) => "
            "encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1])).join('&');",
            f"pm.environment.set({js_str(q)}, _acQ);",
        ]
    pre += [*require_env_url(_ISSUANCE, _AUTHORIZE + "?{{" + q + "}}", _ISSUANCE_WHY)]
    if session:
        sess = _v(tag, "SessionCookie")
        pre += [
            f"if (!{_env(sess)}) {{",
            *report_then_skip(
                f"{tag}: сессия человека не захвачена входом",
                "вход выше не выдал kaname_session — точке авторизации нечего предъявить; "
                "причина — в шаге входа, не здесь", indent="  "),
            "} else {",
            f"  pm.request.headers.upsert({{key: 'Cookie', value: 'kaname_session=' + {_env(sess)}}});",
            "}",
        ]
    return Step(name=name, method="GET", path=_AUTHORIZE + "?{{" + q + "}}", pre_script=pre,
                insecure_tls=True, auth="anonymous", cookie_jar=False, follow_redirects=False,
                test_script=test_script)


def _code_issued(tag, slot, label):
    """02/30: `302` на зарегистрированный адрес, ровно один код, `state` дословно."""
    r, s, code = _v(tag, f"Redirect{slot}"), _v(tag, f"State{slot}"), _v(tag, f"Code{slot}")
    return [
        *assert_status(302),
        *_parse_location(),
        f"pm.test({js_str(label + ': перенаправление ведёт на адрес возврата запроса')}, () => "
        f"pm.expect(_acGot.base, _acLoc).to.eql(_acParse({_env(r)}).base));",
        f"pm.test({js_str(label + ': в перенаправлении ровно один непустой code')}, () => {{",
        "  pm.expect(_acGot.q.code, _acLoc).to.be.an('array').with.lengthOf(1);",
        "  pm.expect(_acGot.q.code[0], 'code').to.be.a('string').and.not.empty; });",
        f"pm.test({js_str(label + ': state возвращён дословно')}, () => "
        f"pm.expect(_acGot.q.state, _acLoc).to.eql([{_env(s)}]));",
        f"pm.test({js_str(label + ': отказа в перенаправлении нет')}, () => "
        "pm.expect(_acGot.q.error, _acLoc).to.eql(undefined));",
        f"if (_acGot.q.code && _acGot.q.code.length === 1) {{ pm.environment.set({js_str(code)}, _acGot.q.code[0]); }}",
    ]


def _redirected_refusal(tag, slot, err, label):
    """06/29: `302` на адрес возврата, и в строке запроса ТОЛЬКО `error`.

    Собственные параметры адреса возврата сохраняются контрактом, поэтому они
    вычитаются до сравнения; всё прочее — `code`, `state`, описание отказа —
    уехать в перенаправление не имеет права.
    """
    r = _v(tag, f"Redirect{slot}")
    return [
        *assert_status(302),
        *_parse_location(),
        f"pm.test({js_str(label + ': перенаправление ведёт на адрес возврата запроса')}, () => "
        f"pm.expect(_acGot.base, _acLoc).to.eql(_acParse({_env(r)}).base));",
        f"pm.test({js_str(label + ': в перенаправлении только error=' + err + ' — ни кода, ни state, ни описания')}, () => {{",
        f"  const own = _acParse({_env(r)}).q; const got = Object.assign({{}}, _acGot.q);",
        "  Object.keys(own).forEach((k) => { if (JSON.stringify(got[k]) === JSON.stringify(own[k])) { delete got[k]; } });",
        f"  pm.expect(got, _acLoc).to.eql({{error: [{js_str(err)}]}}); }});",
    ]


def _basic(id_key, secret_expr):
    """Секрет клиента схемой Basic (RFC 6749 §2.3.1): обе половины кодируются."""
    return [
        "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' + "
        "CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
        f"  encodeURIComponent({_env(id_key)} || '') + ':' + encodeURIComponent({secret_expr})))}});",
    ]


def _need_captured(var, label, why):
    return [
        f"if (!{_env(var)}) {{",
        *report_then_skip(label, why, indent="  "),
        "}",
    ]


def _exchange(tag, name, *, code_slot, test_script, verifier=None, redirect=None,
              client=_CLIENT, secret=None, basic=True, body_client_id=False, code_value=None):
    """Обмен кода (приёмка 10): `POST /iam/v1/token`, форма, секрет клиента Basic."""
    code = _v(tag, f"Code{code_slot}")
    verifier = verifier or _env(_v(tag, f"Verifier{code_slot}"))
    redirect = redirect or _env(_v(tag, f"Redirect{code_slot}"))
    secret = secret or f"{_env(client[1])} || ''"
    pre = [*_need(*dict.fromkeys((*_CLIENT, *client)))]
    if code_value is None:
        pre += _need_captured(code, f"{tag}: код не захвачен точкой авторизации",
                              "шаг выдачи кода выше не выдал code — обменивать нечего; "
                              "причина — в шаге выдачи, не здесь")
        code_value = _env(code)
    pre += [
        f"pm.variables.set('_acFCode', encodeURIComponent({code_value} || ''));",
        f"pm.variables.set('_acFRedirect', encodeURIComponent({redirect} || ''));",
        f"pm.variables.set('_acFVerifier', encodeURIComponent({verifier} || ''));",
        f"pm.variables.set('_acFClientId', encodeURIComponent({_env(client[0])} || ''));",
        *require_env_url(_ISSUANCE, _TOKEN, _ISSUANCE_WHY),
        *(_basic(client[0], secret) if basic else []),
    ]
    form = [("grant_type", "authorization_code"), ("code", "{{_acFCode}}"),
            ("redirect_uri", "{{_acFRedirect}}"), ("code_verifier", "{{_acFVerifier}}")]
    if body_client_id:
        form.append(("client_id", "{{_acFClientId}}"))
    return Step(name=name, method="POST", path=_TOKEN, form=form, pre_script=pre,
                insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test_script)


def _refresh(tag, name, *, rt_var, test_script):
    """Предъявление токена обновления (приёмка 20): форма, секрет клиента Basic."""
    return Step(
        name=name, method="POST", path=_TOKEN,
        form=[("grant_type", "refresh_token"), ("refresh_token", "{{_acFRefresh}}")],
        pre_script=[
            *_need(*_CLIENT),
            *_need_captured(rt_var, f"{tag}: токен обновления не захвачен",
                            "обмен выше не вернул refresh_token — предъявлять нечего; "
                            "причина — в шаге обмена, не здесь"),
            f"pm.variables.set('_acFRefresh', encodeURIComponent({_env(rt_var)} || ''));",
            *require_env_url(_ISSUANCE, _TOKEN, _ISSUANCE_WHY),
            *_basic(_CLIENT[0], f"{_env(_CLIENT[1])} || ''"),
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=test_script)


def _clock(tag, name, *, since_var, wait_ms, label):
    """Отсчёт срока петлёй по публичному чтению поверхности выдачи (14).

    Ждётся СРОК, а не готовность, и отсчитывается он от момента выдачи кода,
    записанного шагом выдачи. Каждый оборот ждёт не дольше `_CLOCK_TURN_MS`
    занятым циклом (newman таймеров между запросами не ждёт) и повторяет шаг;
    утверждения исполняются один раз — на последнем обороте, поэтому их число
    от длины ожидания не зависит.
    """
    turns, started = _v(tag, "ClockTurns"), _v(tag, "ClockStep")
    return Step(
        name=name, method="GET", path=_DISCOVERY,
        pre_script=[
            *require_env_url(_ISSUANCE, _DISCOVERY, _ISSUANCE_WHY),
            f"if ({_env(started)} !== pm.info.requestName) {{",
            f"  pm.environment.set({js_str(turns)}, '0'); pm.environment.set({js_str(started)}, pm.info.requestName);",
            "}",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False,
        test_script=[
            f"const _acTurn = parseInt({_env(turns)} || '0', 10);",
            f"const _acSince = Number({_env(since_var)} || '0');",
            f"const _acLeft = _acSince > 0 ? {int(wait_ms)} - (Date.now() - _acSince) : 0;",
            f"if (_acLeft > 0 && _acTurn < {_CLOCK_CAP}) {{",
            f"  pm.environment.set({js_str(turns)}, String(_acTurn + 1));",
            f"  const _acTick = Date.now(); while (Date.now() - _acTick < Math.min(_acLeft, {_CLOCK_TURN_MS})) {{ /* срок кода, не готовность */ }}",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset({js_str(turns)}); pm.environment.unset({js_str(started)});",
            f"pm.test({js_str(label + ': момент выдачи кода записан шагом выдачи')}, () => "
            "pm.expect(_acSince, 'момент выдачи').to.be.above(0));",
            f"pm.test({js_str(label + ': срок кода выдержан по часам прогона')}, () => "
            "pm.expect(_acLeft <= 0, 'осталось ' + _acLeft + ' мс после ' + _acTurn + ' оборотов').to.eql(true));",
            *assert_status(200),
        ])


def _tokens_issued(tag, slot, label):
    """Ответ `200` стандартной формы (RFC 6749 §5.1): пара токенов, срок, область."""
    at, rt = _v(tag, f"AccessToken{slot}"), _v(tag, f"RefreshToken{slot}")
    return [
        f"pm.environment.unset({js_str(at)}); pm.environment.unset({js_str(rt)});",
        *assert_status(200),
        "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"pm.test({js_str(label + ': token_type — Bearer')}, () => "
        "pm.expect(j.token_type, JSON.stringify(Object.keys(j))).to.eql('Bearer'));",
        f"pm.test({js_str(label + ': access_token — непустая строка')}, () => "
        "pm.expect(j.access_token, 'access_token').to.be.a('string').and.not.empty);",
        f"pm.test({js_str(label + ': refresh_token — непустая строка')}, () => "
        "pm.expect(j.refresh_token, 'refresh_token').to.be.a('string').and.not.empty);",
        f"pm.test({js_str(label + ': expires_in — положительное число секунд')}, () => "
        "pm.expect(j.expires_in, 'expires_in').to.be.a('number').and.above(0));",
        f"pm.test({js_str(label + ': выданная область — openid')}, () => pm.expect(j.scope, 'scope').to.eql('openid'));",
        f"if (j.access_token) {{ pm.environment.set({js_str(at)}, j.access_token); }}",
        f"if (j.refresh_token) {{ pm.environment.set({js_str(rt)}, j.refresh_token); }}",
    ]


def _grant_refused(label):
    """Отказ после того, как назван код или токен обновления (Р10): 400 invalid_grant."""
    return [
        *assert_status(400),
        "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"pm.test({js_str(label + ': error — invalid_grant')}, () => pm.expect(j.error, JSON.stringify(j)).to.eql('invalid_grant'));",
        f"pm.test({js_str(label + ': токен не выдан')}, () => "
        "pm.expect([j.access_token, j.refresh_token], 'тело несёт токен').to.eql([undefined, undefined]));",
    ]


def _client_refused(label):
    """Клиент не доказал себя (Р10, 12): 401 invalid_client — о клиенте, не о коде."""
    return [
        *assert_status(401),
        "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        f"pm.test({js_str(label + ': error — invalid_client')}, () => pm.expect(j.error, JSON.stringify(j)).to.eql('invalid_client'));",
        f"pm.test({js_str(label + ': токен не выдан')}, () => "
        "pm.expect([j.access_token, j.refresh_token], 'тело несёт токен').to.eql([undefined, undefined]));",
    ]


def _present(tag, name, *, token_var, accepted):
    """Рутинный глагол собственного фронта под выданным токеном (18; отзыв — 13, 21)."""
    user = _v(tag, "UserId")
    if accepted:
        tests = [
            *assert_status(200),
            "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
            "pm.test('ФРОНТ: субъект запроса — человек, вошедший нашим входом', () => "
            f"pm.expect(j.subject, JSON.stringify(j)).to.eql('user:' + {_env(user)}));",
        ]
    else:
        tests = [
            *assert_status(401),
            *assert_grpc_code(16, "UNAUTHENTICATED"),
            "pm.test('ФРОНТ: отказ — единственный текст негодного удостоверения', () => {",
            "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
            "  pm.expect(j.message, JSON.stringify(j)).to.eql('credential is not accepted'); });",
        ]
    return Step(
        name=name, method="GET", path=_ME,
        pre_script=[
            *require_env_url("ownRestBaseUrl", _ME, _OWN_WHY),
            f"if (!{_env(token_var)}) {{",
            *report_then_skip(f"{tag}: токен доступа не захвачен обменом",
                              "обмен выше не вернул access_token — предъявлять нечего; "
                              "причина — в шаге обмена, не здесь", indent="  "),
            "} else {",
            f"  pm.request.headers.upsert({{key: 'Authorization', value: 'Bearer ' + {_env(token_var)}}});",
            "}",
        ],
        insecure_tls=True, auth="anonymous", cookie_jar=False, test_script=tests)


# ───────────────────────────────────────────────────────────────────────────
# 02 → 10 → 18: код выдан, обменян на НАШ токен, токен принят фронтом.
# ───────────────────────────────────────────────────────────────────────────
_T = "Hp"
CASES.append(Case(
    id="IAM-AUTHCODE-OK-ISSUE-EXCHANGE-ACCEPT",
    title="02→10→18: вход нашим входом, код перенаправлением, обмен на наш токен, фронт принимает его",
    classes=["CRUD", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=[
            *_code_issued(_T, "1", "02"),
            # Непрозрачность кода (приёмка 02): ни субъекта, ни области — ни в самом
            # значении, ни в его base64-раскодировке.
            "pm.test('02: код не несёт ни субъекта, ни области в разбираемом виде', () => {",
            f"  const c = {_env(_v(_T, 'Code1'))} || ''; const uid = {_env(_v(_T, 'UserId'))} || '';",
            "  let dec = ''; try { dec = CryptoJS.enc.Base64.parse(c.split('-').join('+').split('_').join('/'))"
            ".toString(CryptoJS.enc.Latin1); } catch (e) { dec = ''; }",
            "  pm.expect(c, 'код не выдан').to.not.eql('');",
            "  pm.expect([c.includes(uid), dec.includes(uid), c.includes('openid'), dec.includes('openid')], 'код').to.eql([false, false, false, false]); });",
            "pm.test('02: код — не токен с утверждениями (не три сегмента через точку)', () => "
            f"pm.expect(({_env(_v(_T, 'Code1'))} || '').split('.').length, 'сегментов').to.not.eql(3));",
        ]),
        _exchange(_T, "exchange", code_slot="1", test_script=[
            *_tokens_issued(_T, "1", "10"),
            # Утверждения токена (Р6): субъект, уровень и момент — той сессии, в
            # которой выдан код; подпись проверяет фронт (18), здесь — содержание.
            "const _acClaims = (t) => { try { let b = String(t).split('.')[1].split('-').join('+').split('_').join('/');",
            "  while (b.length % 4) { b += '='; } return JSON.parse(CryptoJS.enc.Base64.parse(b).toString(CryptoJS.enc.Utf8)); }",
            "  catch (e) { return {}; } };",
            "const c = _acClaims(j.access_token);",
            f"const uid = {_env(_v(_T, 'UserId'))};",
            "pm.test('10: sub — человек, вошедший нашим входом', () => pm.expect(c.sub, JSON.stringify(Object.keys(c))).to.eql(uid));",
            "pm.test('10: вид принципала — user', () => pm.expect(c.kaname_principal_type, 'kaname_principal_type').to.eql('user'));",
            "pm.test('10: идентификатор принципала — тот же человек', () => pm.expect(c.kaname_principal_id, 'kaname_principal_id').to.eql(uid));",
            f"pm.test('10: client_id — клиент, которому выдан код', () => pm.expect(c.client_id, 'client_id').to.eql({_env('oauthClientId')}));",
            f"pm.test('10: acr — уровень сессии, в которой выдан код', () => pm.expect(String(c.acr), 'acr').to.eql({_env(_v(_T, 'Level'))}));",
            "pm.test('10: auth_time — момент входа этой сессии (±60 с часов стенда)', () => {",
            f"  const at = Number({_env(_v(_T, 'LoginAt'))}); const now = Math.floor(Date.now() / 1000);",
            "  pm.expect(c.auth_time, 'auth_time').to.be.a('number');",
            "  pm.expect(c.auth_time >= at - 60 && c.auth_time <= now + 60, 'auth_time=' + c.auth_time + ' вход=' + at).to.eql(true); });",
            "pm.test('10: получатель токена назван', () => pm.expect([].concat(c.aud || []).length, 'aud').to.be.above(0));",
        ]),
        _present(_T, "present-to-own-front", token_var=_v(_T, "AccessToken1"), accepted=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 30: `state` РОВНО на поле — код выдаётся (граница сверху).
# ───────────────────────────────────────────────────────────────────────────
_T = "Sf"
CASES.append(Case(
    id="IAM-AUTHCODE-BVA-STATE-AT-FLOOR",
    title="30: state ровно 22 знака — код выдан, state возвращён дословно",
    classes=["BVA"],
    priority="P1",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize-state-22", state_len=_STATE_FLOOR,
                   test_script=_code_issued(_T, "1", "30")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 29: `state` нет либо на знак короче пола — один исход обеих ветвей.
# ───────────────────────────────────────────────────────────────────────────
_T = "Sb"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-STATE-BELOW-FLOOR",
    title="29: state не прислан либо 21 знак — перенаправление только с error=invalid_request",
    classes=["NEG", "BVA"],
    priority="P1",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize-without-state", state_len=None,
                   test_script=_redirected_refusal(_T, "1", "invalid_request", "29/нет")),
        _authorize(_T, "2", "authorize-state-21", state_len=_STATE_FLOOR - 1,
                   test_script=_redirected_refusal(_T, "2", "invalid_request", "29/21")),
        # Положительный контроль в том же кейсе: та же сессия, тот же клиент,
        # отличие — длина `state`. Без него отказ выше мог прийти от чего угодно.
        _authorize(_T, "3", "authorize-state-22-control", state_len=_STATE_FLOOR,
                   test_script=_code_issued(_T, "3", "29/контроль")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 03: сессии нет — код не выдаётся; близнец — тот же запрос с сессией.
# ───────────────────────────────────────────────────────────────────────────
_T = "Ns"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-NO-SESSION",
    title="03: запрос авторизации без сессии — 401 login_required; тот же запрос с сессией — код",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        _authorize(_T, "1", "authorize-without-session", session=False, test_script=[
            *assert_status(401),
            "let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
            "pm.test('03: error — login_required', () => pm.expect(j.error, JSON.stringify(j)).to.eql('login_required'));",
            *_no_location("03"),
        ]),
        *_login(_T),
        _authorize(_T, "2", "same-request-with-session", reuse="1",
                   test_script=_code_issued(_T, "2", "03/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 04: адрес возврата не зарегистрирован — отказ БЕЗ перенаправления.
# ───────────────────────────────────────────────────────────────────────────
_T = "Ru"
_UNREGISTERED = "'https://unregistered-' + pm.environment.get('runId') + '.invalid/cb'"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-REDIRECT-UNREGISTERED",
    title="04: чужой адрес возврата — 400 без перенаправления; страница та же, что у неизвестного клиента",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "registered-redirect-control", test_script=[
            *_code_issued(_T, "1", "04/близнец"),
            f"pm.environment.set({js_str(_v(_T, 'ControlStatus'))}, String(pm.response.code));",
        ]),
        _authorize(_T, "2", "unregistered-redirect", redirect=_UNREGISTERED, test_script=[
            *assert_status(400),
            *_no_location("04"),
            f"pm.environment.set({js_str(_v(_T, 'RefusalPage'))}, pm.response.text());",
        ]),
        _authorize(_T, "3", "unknown-client", client="'oic' + pm.environment.get('runId') + 'nosuchclient'",
                   test_script=[
            *assert_status(400),
            "pm.test('04: неизвестный клиент и чужой адрес — ПОБАЙТОВО одна страница', () => {",
            f"  const first = {_env(_v(_T, 'RefusalPage'))};",
            "  pm.expect(first, 'первый отказ не захвачен — сравнивать не с чем').to.be.a('string').and.not.empty;",
            # Контроль ВНУТРИ того же утверждения: равенство двух отказов ни о чём
            # не свидетельствует там, где поверхность отвечает одинаково на всё.
            f"  pm.expect({_env(_v(_T, 'ControlStatus'))}, 'близнец не выдал код — равенство отказов ни о чём не говорит').to.eql('302');",
            "  pm.expect(pm.response.text()).to.eql(first); });",
        ]),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 06: PKCE нет либо метод не S256 — отказ перенаправляем, только `error`.
# ───────────────────────────────────────────────────────────────────────────
_T = "Pk"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-PKCE-MISSING-OR-PLAIN",
    title="06: без code_challenge либо с методом plain — перенаправление только с error=invalid_request",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize-without-pkce", challenge=None,
                   test_script=_redirected_refusal(_T, "1", "invalid_request", "06/нет")),
        _authorize(_T, "2", "authorize-pkce-plain", challenge="plain",
                   test_script=_redirected_refusal(_T, "2", "invalid_request", "06/plain")),
        _authorize(_T, "3", "authorize-pkce-s256-control",
                   test_script=_code_issued(_T, "3", "06/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 11: неверный `code_verifier` — invalid_grant, и код этим погашен.
# ───────────────────────────────────────────────────────────────────────────
_T = "Wv"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-WRONG-VERIFIER",
    title="11: неверный code_verifier — invalid_grant; код погашен; свежий код с верным — 200",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "11")),
        _exchange(_T, "exchange-wrong-verifier", code_slot="1",
                  verifier="(pm.environment.get('runId') + 'Z').repeat(8).slice(0, 43)",
                  test_script=_grant_refused("11")),
        # Контракт: код гасит ПЕРВОЕ предъявление, в том числе с неверным
        # `code_verifier` (`oauth-ceremony.mdx`, «Обмен кода»).
        _exchange(_T, "exchange-right-verifier-after", code_slot="1",
                  test_script=_grant_refused("11/погашен")),
        _authorize(_T, "2", "authorize-fresh", test_script=_code_issued(_T, "2", "11/близнец")),
        _exchange(_T, "exchange-fresh-right-verifier", code_slot="2",
                  test_script=_tokens_issued(_T, "2", "11/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 12: клиент не доказал себя — 401 invalid_client, решается ДО кода.
# ───────────────────────────────────────────────────────────────────────────
_T = "Cu"
_WRONG_SECRET = "'not-the-secret-' + pm.environment.get('runId')"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-CLIENT-UNAUTHENTICATED",
    title="12: без секрета, с неверным секретом, с неверным секретом и неизвестным кодом — 401 invalid_client",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "12")),
        _exchange(_T, "exchange-without-client-secret", code_slot="1", basic=False,
                  body_client_id=True, test_script=_client_refused("12/нет секрета")),
        _exchange(_T, "exchange-wrong-client-secret", code_slot="1", secret=_WRONG_SECRET,
                  test_script=_client_refused("12/неверный секрет")),
        # Код неизвестен И секрет неверен: ответ обязан быть о КЛИЕНТЕ — клиент
        # судится до того, как код назван (Р10).
        _exchange(_T, "exchange-unknown-code-wrong-secret", code_slot="1", secret=_WRONG_SECRET,
                  code_value="('unknown' + pm.environment.get('runId')).repeat(4)",
                  test_script=_client_refused("12/неизвестный код")),
        _authorize(_T, "2", "authorize-fresh", test_script=_code_issued(_T, "2", "12/близнец")),
        _exchange(_T, "exchange-fresh-right-secret", code_slot="2",
                  test_script=_tokens_issued(_T, "2", "12/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 13: повтор кода — invalid_grant И отзыв выданного по нему на ПРЕДЪЯВЛЕНИИ.
# ───────────────────────────────────────────────────────────────────────────
_T = "Cr"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-CODE-REPLAY-REVOKES",
    title="13: второй обмен тем же кодом — invalid_grant, и токен первого обмена фронт больше не принимает",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "13")),
        _exchange(_T, "exchange-first", code_slot="1", test_script=_tokens_issued(_T, "1", "13/первый")),
        # Близнец выдаётся ДО повтора и не предъявляется до него: вердикт «не
        # отозван» не попадает в кэш фронта ни у одного из двух токенов.
        _authorize(_T, "2", "authorize-fresh", test_script=_code_issued(_T, "2", "13/близнец")),
        _exchange(_T, "exchange-fresh", code_slot="2", test_script=_tokens_issued(_T, "2", "13/близнец")),
        _exchange(_T, "exchange-replay", code_slot="1", test_script=_grant_refused("13/повтор")),
        _present(_T, "present-token-of-the-replayed-code", token_var=_v(_T, "AccessToken1"), accepted=False),
        _present(_T, "present-token-of-the-fresh-code", token_var=_v(_T, "AccessToken2"), accepted=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 15: адрес возврата обмена не совпадает с адресом кода — invalid_grant.
# ───────────────────────────────────────────────────────────────────────────
_T = "Rm"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-REDIRECT-MISMATCH",
    title="15: обмен с другим, пусть зарегистрированным, адресом возврата — invalid_grant",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        # Положительный контроль: второй адрес ЗАРЕГИСТРИРОВАН — отказ ниже о
        # несовпадении со связкой кода, а не о незарегистрированном адресе.
        _authorize(_T, "0", "alt-redirect-is-registered", redirect=_env(_REDIRECT_ALT),
                   test_script=_code_issued(_T, "0", "15/второй адрес")),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "15")),
        _exchange(_T, "exchange-with-alt-redirect", code_slot="1", redirect=_env(_REDIRECT_ALT),
                  test_script=_grant_refused("15")),
        _authorize(_T, "2", "authorize-fresh", test_script=_code_issued(_T, "2", "15/близнец")),
        _exchange(_T, "exchange-with-same-redirect", code_slot="2",
                  test_script=_tokens_issued(_T, "2", "15/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 16: код предъявлен другим (доказавшим себя) клиентом — invalid_grant.
# ───────────────────────────────────────────────────────────────────────────
_T = "Fc"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-FOREIGN-CLIENT",
    title="16: код первого клиента, предъявленный вторым с его верным секретом — invalid_grant",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "16")),
        # Второй клиент ДОКАЗЫВАЕТ себя: иначе ответ был бы 401 invalid_client, и
        # шаг покраснел бы, а не прошёл бы на чужом отказе.
        _exchange(_T, "exchange-by-other-client", code_slot="1", client=_OTHER_CLIENT,
                  test_script=_grant_refused("16")),
        _authorize(_T, "2", "authorize-fresh", test_script=_code_issued(_T, "2", "16/близнец")),
        _exchange(_T, "exchange-by-own-client", code_slot="2",
                  test_script=_tokens_issued(_T, "2", "16/близнец")),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 20: токен обновления оборачивается при каждом предъявлении.
# ───────────────────────────────────────────────────────────────────────────
_T = "Rr"


def _rotated(tag, slot, prev_slot, label):
    return [
        *_tokens_issued(tag, slot, label),
        f"pm.test({js_str(label + ': выдан НОВЫЙ токен обновления — прежний обёрнут, а не возвращён')}, () => "
        f"pm.expect(j.refresh_token, 'refresh_token').to.not.eql({_env(_v(tag, f'RefreshToken{prev_slot}'))}));",
        f"pm.test({js_str(label + ': выдан НОВЫЙ токен доступа')}, () => "
        f"pm.expect(j.access_token, 'access_token').to.not.eql({_env(_v(tag, f'AccessToken{prev_slot}'))}));",
    ]


CASES.append(Case(
    id="IAM-AUTHCODE-OK-REFRESH-ROTATES",
    title="20: обмен выдаёт токен обновления; каждое предъявление даёт новую пару, цепочка продолжается",
    classes=["CRUD"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "20")),
        _exchange(_T, "exchange", code_slot="1", test_script=_tokens_issued(_T, "1", "20/обмен")),
        _refresh(_T, "refresh-first", rt_var=_v(_T, "RefreshToken1"),
                 test_script=_rotated(_T, "2", "1", "20/первое")),
        _refresh(_T, "refresh-rotated", rt_var=_v(_T, "RefreshToken2"),
                 test_script=_rotated(_T, "3", "2", "20/по цепочке")),
        _present(_T, "present-rotated-access-token", token_var=_v(_T, "AccessToken3"), accepted=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 21: повтор обёрнутого токена обновления — отзыв СЕМЕЙСТВА на предъявлении.
# ───────────────────────────────────────────────────────────────────────────
_T = "Rp"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-REFRESH-REPLAY-REVOKES-FAMILY",
    title="21: повтор обёрнутого токена обновления — invalid_grant, семейство отозвано; соседнее семейство живо",
    classes=["NEG", "SEC"],
    priority="P0",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize", test_script=_code_issued(_T, "1", "21")),
        _exchange(_T, "exchange", code_slot="1", test_script=_tokens_issued(_T, "1", "21/обмен")),
        # Соседнее семейство: тот же человек, та же сессия, ДРУГОЙ код. Отзыв —
        # «всё семейство выданного по исходному коду», не сессия и не человек.
        _authorize(_T, "4", "authorize-neighbour", test_script=_code_issued(_T, "4", "21/сосед")),
        _exchange(_T, "exchange-neighbour", code_slot="4", test_script=_tokens_issued(_T, "4", "21/сосед")),
        _refresh(_T, "refresh-first", rt_var=_v(_T, "RefreshToken1"),
                 test_script=_tokens_issued(_T, "2", "21/обёртка")),
        _refresh(_T, "replay-wrapped-refresh-token", rt_var=_v(_T, "RefreshToken1"),
                 test_script=_grant_refused("21/повтор")),
        _refresh(_T, "current-refresh-token-after-replay", rt_var=_v(_T, "RefreshToken2"),
                 test_script=_grant_refused("21/текущий после повтора")),
        _present(_T, "present-family-access-token", token_var=_v(_T, "AccessToken2"), accepted=False),
        _present(_T, "present-neighbour-access-token", token_var=_v(_T, "AccessToken4"), accepted=True),
    ],
))

# ───────────────────────────────────────────────────────────────────────────
# 14: код старше срока — invalid_grant. ПОСЛЕДНИМ: кейс ждёт срок кода.
# ───────────────────────────────────────────────────────────────────────────
_T = "Ce"
CASES.append(Case(
    id="IAM-AUTHCODE-NEG-CODE-EXPIRED",
    title="14: код, предъявленный позже 60 с, — invalid_grant; выданный тогда же и обменянный сразу — 200",
    classes=["NEG", "BVA"],
    priority="P1",
    steps=[
        *_login(_T),
        _authorize(_T, "1", "authorize-to-expire", test_script=[
            *_code_issued(_T, "1", "14"),
            f"if ({_env(_v(_T, 'Code1'))}) {{ pm.environment.set({js_str(_v(_T, 'IssuedAt1'))}, String(Date.now())); }}",
        ]),
        _authorize(_T, "2", "authorize-to-exchange-now", test_script=_code_issued(_T, "2", "14/близнец")),
        _exchange(_T, "exchange-within-ttl", code_slot="2", test_script=_tokens_issued(_T, "2", "14/близнец")),
        _clock(_T, "wait-for-code-expiry", since_var=_v(_T, "IssuedAt1"),
               wait_ms=_CODE_EXPIRY_WAIT_MS, label="14/срок"),
        _exchange(_T, "exchange-after-ttl", code_slot="1", test_script=_grant_refused("14")),
    ],
))
