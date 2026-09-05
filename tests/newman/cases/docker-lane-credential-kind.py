# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set docker-lane-credential-kind — ДОКЕР-ПОЛОСА ПРИНИМАЕТ ОДИН ВИД (#1143).

ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ
---------------------
Вопрос ставится СКВОЗЬ ВЕСЬ ТРАКТ: выдали удостоверение вида SECRET → вошли им
в докер-полосу → получили удостоверение реестра → предъявили ключевой материал
в том же поле пароля → отказ. Половина этого («полоса принимает секрет») не
доказывает ничего о снятии прежнего входа, а вторая половина без первой верна и
о полосе, сломанной целиком.

ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ СТОИТ ПЕРВЫМ и в том же прогоне — иначе «ключевой
материал отвергнут» зеленело бы на выдаче, отвергающей всё.

ОТКАЗ НЕ ОРАКУЛ, И ЭТО УТВЕРЖДАЕТСЯ СРАВНЕНИЕМ
-----------------------------------------------
Снятие приёма — ЛОМАЮЩЕЕ изменение, и клиент, настроенный по-старому, обязан
получить ТОТ ЖЕ отказ, что и клиент с неверным секретом. Отдельный отказ на
«негодный вид» сказал бы предъявителю, что его строка разобрана как ключ, — то
есть подтвердил бы существование учётной записи, на которую он не
аутентифицировался. Поэтому сверяются ТЕЛА двух отказов, а не только коды.

Годный вид отказ называет СТАТИЧЕСКИ — так же, как называет его страница
документации, — и из тела нельзя узнать ничего о предъявленном.

ПОЧЕМУ ЛАНА ЖИВЁТ В СУИТЕ IAM
------------------------------
Её предмет — полоса выдачи kacho-iam, а не данные реестра: адрес `:9096` —
собственная ручка iam, и раннер открывает к ней проброс БЕЗУСЛОВНО (iam входит
в ядро каждого шарда). Кейс IBT-14 уехал в суиту реестра потому, что дополнительно
дозванивался до ДАННЫХ реестра — компонента, который шард может не поднимать.
Здесь такого адреса нет.

  {{iamRegistryTokenBaseUrl}} — ручка докер-токена iam (:9096), server-TLS с
                                листом внутреннего центра → шаги несут
                                `insecure_tls`: предмет пробы — ЧТО ОТДАЁТСЯ,
                                а не цепочка доверия туннеля.

Идемпотентность: удостоверение выпускается своё на прогон и отзывается тем же
кейсом. За собой не остаётся ничего.
"""

CASES = []

# АДРЕСАТ НЕ ВЫПИСЫВАЕТСЯ, А СПРАШИВАЕТСЯ У САМОЙ ПОЛОСЫ (прогон 32777733533).
#
# Здесь стоял литерал `registry.kacho.local` с комментарием «объявленная
# посадкой полосы». Посадка объявляла другое: перечень адресатов всех трёх
# профилей — `https://api.kacho.cloud,registry.in-cloud.io`, а это имя было
# снятым встроенным умолчанием процесса (задача #1184, разбор — в комментарии
# самого профиля рядом с `allowedAudiences`). То есть утверждение о посадке
# было написано по памяти и разошлось с ней молча.
#
# ЧТО ЭТО СТОИЛО. Положительный контроль получал 401, и по телу отказа причина
# не читалась вовсе: полоса отвечает ОДНИМ телом на всякую причину — намеренно,
# чтобы не быть оракулом. Настоящую причину назвал только журнал службы:
# «requested audience is not allowed … outside the landing declaration».
# Предъявленный секрет при этом был РАЗОБРАН, НАЙДЕН и ПРИНЯТ — адресат
# решается ПОСЛЕ проверки учётных данных (`executeBasic`), — то есть предмет
# кейса работал, а красным был его собственный литерал.
#
# ПОЧЕМУ НЕ ВТОРОЙ ЛИТЕРАЛ. Заменить одно имя другим значило бы завести третью
# копию величины, которая уже разошлась однажды; профиль об этом расхождении
# прямо и предупреждает. Полоса называет своего адресата САМА: запрос без
# `service=` получает вызов на аутентификацию, в котором стоит её умолчание.
# Оно ГОДНО ПО ПОСТРОЕНИЮ — страж старта отказывает службе в подъёме, если
# умолчание вне объявленного посадкой перечня (`config/registry_token.go`),
# поэтому спрошенное имя не может оказаться отвергнутым тем же перечнем.
# Ровно так же узнаёт адресата и настоящий докер-клиент — из вызова, а не из
# своей настройки.
_TOKEN_PATH = ("/iam/token?service={{dockerLaneServiceAud}}"
               "&scope=repository:kacho/km-{{runId}}:pull")

# Ключевой материал: нарочито НЕ похож на настоящий ключ. Правдоподобная
# фикстура сделала бы «прошло» неотличимым от исправного потока. Записывается
# литералом JS прямо в шаге — помощник экранирования в пространство имён
# case-модуля не передаётся.


CASES.append(Case(
    id="IAM-DOCKER-LANE-BASIC-TOKEN-ONLY",
    title=(
        "Докер-полоса принимает базовый токен доступа и отвергает ключевой "
        "материал в поле пароля тем же отказом, что и неверный секрет"
    ),
    classes=["SEC", "CONF", "NEG"],
    priority="P0",
    steps=[
        # ── АДРЕСАТ ПОЛОСЫ: спрашивается, а не предполагается ──────────────
        Step(
            name="ask-the-lane-which-audience-it-serves",
            method="GET",
            path="/iam/token",
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl", "/iam/token",
                "докер-полоса — у неё же и спрашиваем, кому она чеканит",
            ),
            test_script=[
                *assert_answered("вызов полосы на аутентификацию"),
                # 401 — тот же исход, что у соседней пробы фасада на этой же
                # ручке: анонимная выдача не включена, полоса вызывает на
                # аутентификацию. 200 означало бы включённую анонимную выдачу,
                # и тогда адресата надо брать иначе — молчать об этом нельзя.
                "pm.test('полоса вызывает на аутентификацию (401)', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.eql(401);",
                "});",
                "const _wa = pm.response.headers.get('WWW-Authenticate') || '';",
                "const _m = _wa.match(/service=\"([^\"]+)\"/);",
                # Имя адресата в вызове — не украшение: докер-клиент возвращает
                # услышанное здесь, и полоса сверяет его со своим перечнем.
                # Пустой вызов означал бы, что узнать адресата клиенту неоткуда.
                "pm.test('вызов НАЗЫВАЕТ адресата, которому полоса чеканит', () => {",
                "  pm.expect(_m && _m[1], 'WWW-Authenticate: ' + _wa)",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "});",
                # Пустое не записывается: страж незакреплённой подстановки ловит
                # ИМЯ, не определённое нигде, и говорит о пропаже по имени, —
                # а пустая строка уехала бы в адрес и вернулась чужим отказом.
                "if (_m && _m[1]) { pm.environment.set('dockerLaneServiceAud', _m[1]); }",
            ],
        ),

        Step(
            name="issue-secret-credential-for-a-service-account",
            method="POST",
            path="/iam/v1/serviceAccounts/{{svaAId}}/keys",
            auth="jwtBootstrap",
            # `createdByUserId` ЗДЕСЬ НЕ ШЛЁТСЯ, и это не упрощение тела.
            # Предъявитель полосы — служебная учётка (`jwtBootstrap`), а у неё
            # это поле отвергается СИНХРОННО и с именем поля: происхождение
            # выводится из владельца аккаунта целевой учётки, и принять
            # присланное значило бы вернуть запрещённый третий исход
            # («принято-и-проигнорировано»). Прогон 32768969536 ответил на это
            # тело `400 Illegal argument created_by_user_id: must be empty for a
            # service-account caller`, и девять утверждений упали каскадом от
            # одного отказа. Продукт прав; образец рядом —
            # `iam-token-facade-conformance.py` :: issue-sa-key, тот же RPC под
            # тем же предъявителем БЕЗ этого поля, зелёный в том же прогоне.
            body={
                "serviceAccountId": "{{svaAId}}",
                "description": "docker lane credential kind {{runId}}",
                "credentialKind": "CREDENTIAL_KIND_SECRET",
                "ttlSeconds": 2592000,
            },
            test_script=[
                *assert_answered("SAKeyService.Issue вида SECRET"),
                *assert_status(200),
                # Вид SECRET завершается НА ПУТИ ЗАПРОСА: строка показывается
                # один раз, и второго чтения у неё не существует.
                "pm.test('операция завершена в ответе самого Issue (done=true)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.done, 'operation.done').to.eql(true);",
                "  pm.expect(j.error, 'operation.error: ' + JSON.stringify(j.error)).to.be.undefined;",
                "});",
                "const _r = pm.response.json().response || {};",
                # ПАРА: что есть и чего нет. «Секрет непуст» в одиночку зеленело
                # бы на ответе, который ВДОБАВОК отдал ключевой материал.
                # ФОРМА, А НЕ ТОЛЬКО НЕПУСТОТА, и образец берётся ИЗ ОБЪЯВЛЕНИЯ
                # (#1253). «Непуст» зеленеет на любой строке, включая ту, которую
                # продукт не чеканит; а образец, выписанный здесь руками, был бы
                # второй копией предиката — она уже расходилась молча в соседнем
                # кейсе. Объявление одно (`credential-secret-form.json`), и
                # `scripts/credsecretmint/form_test.go` требует, чтобы оно
                # принимало значения, ОТЧЕКАНЕННЫЕ `credsecret.Mint`.
                # Вид здесь — ключ служебной учётки: `SAKeyService.Issue` чеканит
                # идентификатор с префиксом `PrefixSAOAuthClient`.
                "pm.test('ответ несёт непустую строку секрета объявленной формы', () => {",
                "  pm.expect(_r.secret, 'response.secret').to.be.a('string')",
                f"    .and.to.match(/{credential_secret_pattern('serviceAccountKey', where='docker-lane/issue-secret-credential')}/);",
                "});",
                "pm.test('ответ вида SECRET НЕ несёт ключевого материала ни в одном поле', () => {",
                "  pm.expect(_r.privateKeyPem || '', 'response.privateKeyPem').to.eql('');",
                "  pm.expect(_r.publicKeyPem || '', 'response.publicKeyPem').to.eql('');",
                "  pm.expect(_r.algorithm || '', 'response.algorithm').to.eql('');",
                "});",
                # Имя докер-входа — идентификатор, который несёт САМА строка.
                # Берётся из неё, а не из соседнего поля: у полосы ровно один
                # источник имени, и проба обязана пользоваться тем же.
                "const _p = String(_r.secret).split('_');",
                "const _credId = _p.slice(1, _p.length - 1).join('_');",
                "pm.test('строка называет своё удостоверение', () => {",
                "  pm.expect(_credId, 'идентификатор из строки').to.be.a('string').with.length.greaterThan(0);",
                "});",
                # КООРДИНАТЫ НЕ ЗАПИСЫВАЮТСЯ ПУСТЫМИ. Страж незакреплённой
                # переменной (gen.py) намеренно узок: он ловит имя, не
                # определённое НИ В ОДНОЙ области, и переменная, заданная пустой
                # строкой, проходит мимо него by construction — пустое значение
                # это законный отрицательный вход. Прежняя редакция вычисляла
                # `_credId` из отказа (`String(undefined).split('_')` → '') и
                # записывала пустую строку безусловно; адрес отзыва собирался как
                # `…/keys/` без последнего сегмента, край не находил маршрута и
                # отвечал `403` с пустыми `subject`/`action` — отказ, к правам
                # отношения не имеющий, шестнадцать раз подряд через обёртку
                # повтора. Записываем только непустое: тогда о пропаже говорит
                # страж, называя имя, а не чужая полоса чужим кодом.
                "if (_r.secret) { pm.environment.set('dockerLaneSecret', _r.secret); }",
                "if (_credId) { pm.environment.set('dockerLaneCredId', _credId); }",
                "const _keyId = _r.keyId || (_r.key && _r.key.id) || _credId;",
                "if (_keyId) { pm.environment.set('dockerLaneKeyId', _keyId); }",
            ],
        ),

        # ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ─────────────────────────────────────────
        Step(
            name="docker-login-with-the-basic-access-token",
            method="GET",
            path=_TOKEN_PATH,
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl", _TOKEN_PATH,
                "докер-полоса — ручка, которую реестр называет докер-клиенту",
            ) + [
                "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' +",
                "  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
                "    pm.environment.get('dockerLaneCredId') + ':' + pm.environment.get('dockerLaneSecret')))});",
            ],
            test_script=[
                *assert_answered("докер-вход базовым токеном доступа"),
                "pm.test('живой базовый токен доступа принят докер-полосой', () => {",
                "  pm.expect(pm.response.code, '401 здесь означает, что полоса не приняла годную '",
                "    + 'строку; 503 — что авторитет не ответил. Тело: ' + pm.response.text()).to.eql(200);",
                "});",
                "pm.test('выдано удостоверение реестра', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.token, 'token').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(j.access_token, 'access_token — докер-клиент читает оба поля')",
                "    .to.be.a('string').with.length.greaterThan(0);",
                "});",
                # Секрет не имеет права уехать в выданное удостоверение.
                "pm.test('предъявленная строка не уехала в выданный токен', () => {",
                "  pm.expect(pm.response.text()).to.not.include(pm.environment.get('dockerLaneSecret'));",
                "});",
            ],
        ),

        # ── ОТРИЦАНИЕ: снятый вид ──────────────────────────────────────────
        Step(
            name="docker-login-with-key-material-is-refused",
            method="GET",
            path=_TOKEN_PATH,
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl", _TOKEN_PATH,
                "докер-полоса — прежний вход ключевым материалом",
            ) + [
                "const _km = '-----BEGIN PRIVATE KEY-----\\n'",
                "  + 'not-a-real-key-1143\\n-----END PRIVATE KEY-----';",
                "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' +",
                "  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
                "    pm.environment.get('dockerLaneCredId') + ':' + _km))});",
            ],
            test_script=[
                *assert_answered("докер-вход ключевым материалом"),
                "pm.test('ключевой материал в поле пароля отвергнут (#1143)', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.eql(401);",
                "});",
                "pm.test('удостоверение реестра не выдано', () => {",
                "  let j = null; try { j = pm.response.json(); } catch (e) { j = null; }",
                "  pm.expect(j && j.token, JSON.stringify(j)).to.be.oneOf([undefined, null]);",
                "});",
                # Отказ обязан НАЗЫВАТЬ годный вид: без этого арендатор,
                # настроенный по-старому, не узнает, чем заменить вход.
                "pm.test('отказ называет годный вид удостоверения', () => {",
                "  pm.expect(pm.response.text(), 'тело отказа').to.include('kacho_');",
                "});",
                "pm.environment.set('dockerLaneRefusalKind', pm.response.text());",
                "pm.environment.set('dockerLaneRefusalKindWWW',",
                "  pm.response.headers.get('WWW-Authenticate') || '');",
            ],
        ),

        # ── ОТРИЦАНИЕ: неверный секрет, и СРАВНЕНИЕ отказов ────────────────
        Step(
            name="docker-login-with-a-wrong-secret-is-refused-identically",
            method="GET",
            path=_TOKEN_PATH,
            auth="anonymous",
            insecure_tls=True,
            pre_script=require_env_url(
                "iamRegistryTokenBaseUrl", _TOKEN_PATH,
                "докер-полоса — контроль неразличимости отказа",
            ) + [
                # Строка НАШЕЙ марки, но не та: чтобы отказ пришёл с той же
                # полосы, что и у годной строки, а не из соседней ветки.
                "const _wrong = 'kacho_' + pm.environment.get('dockerLaneCredId')",
                "  + '_00000000000000000000000000000000';",
                "pm.request.headers.upsert({key: 'Authorization', value: 'Basic ' +",
                "  CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(",
                "    pm.environment.get('dockerLaneCredId') + ':' + _wrong))});",
            ],
            test_script=[
                *assert_answered("докер-вход неверным секретом"),
                "pm.test('неверный секрет отвергнут', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.eql(401);",
                "});",
                # ЭТО И ЕСТЬ УТВЕРЖДЕНИЕ О НЕОРАКУЛЬНОСТИ: два разных по природе
                # входа обязаны быть НЕОТЛИЧИМЫ снаружи — по телу и по вызову.
                "pm.test('отказ снятому виду и отказ неверному секрету НЕРАЗЛИЧИМЫ', () => {",
                "  pm.expect(pm.response.text(), 'тело: различимые тела сказали бы предъявителю, '",
                "    + 'как разобран его вход').to.eql(pm.environment.get('dockerLaneRefusalKind'));",
                "  pm.expect(pm.response.headers.get('WWW-Authenticate') || '', 'WWW-Authenticate')",
                "    .to.eql(pm.environment.get('dockerLaneRefusalKindWWW'));",
                "});",
            ],
        ),

        # ── уборка: удостоверение живёт ровно этот прогон ──────────────────
        Step(
            name="revoke-the-credential",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{svaAId}}/keys/{{dockerLaneKeyId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("SAKeyService.Revoke"),
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("pm.response.json().id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtBootstrap"),
    ],
))
