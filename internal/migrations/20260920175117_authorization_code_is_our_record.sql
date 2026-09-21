-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- authorization_code_is_our_record — КОД АВТОРИЗАЦИИ и СЕМЕЙСТВО выданного по
-- нему становятся записями службы (задача PRO-Robotech/kaname#313).
--
-- До этой миграции собственной церемонии OAuth в схеме не было НИ ОДНОЙ строки:
-- `grep -ic 'authorization_code\|code_challenge\|pkce' internal/migrations/*.sql`
-- давал 0, выдача шла через внешнего поставщика (`internal/clients/hydra_*.go`).
--
-- =============================================================================
-- ПОЧЕМУ ФОРМА ИМЕННО ТАКАЯ: ГАШЕНИЕ ОДНОЙ ИНСТРУКЦИЕЙ
-- =============================================================================
-- Движок внешнего поставщика читает код ВНЕ транзакции и гасит ВНУТРИ, значит
-- атомарности обмена он не даёт: две одновременные копии запроса обе читают код
-- живым, обе доходят до безусловного `UPDATE`, и по одному коду уходит ДВОЙНАЯ
-- выдача. Положительный путь при этом зелёный — последовательная проба такую
-- реализацию не отличает от верной.
--
-- Поэтому форма строки подчинена ОДНОМУ требованию: обмен обязан выражаться
-- ОДНИМ оператором с условием на ПРЕЖНЕЕ состояние и возвратом затронутой
-- строки —
--
--   UPDATE kaname.authorization_codes
--      SET active = false, deactivated_at = now(), deactivated_reason = 'redeemed'
--    WHERE code_digest = $1 AND active AND expires_at > now() AND <семейство живо>
--   RETURNING …;
--
-- Ноль затронутых строк — отказ, и он ОДИН на всех проигравших. Пары «прочитать,
-- затем записать» здесь нет и быть не может: условие и запись исполняет сам
-- движок под строчным замком (ban #10).
--
-- =============================================================================
-- СНЯТИЕ — ОТМЕТКА, А НЕ УДАЛЕНИЕ
-- =============================================================================
-- Использованный код ПОМЕЧАЕТСЯ неактивным и ЖИВЁТ до истечения. Обнаружение
-- повторного использования строится на различении «неактивен» и «не найден»:
-- первое — повтор, и по нему отзывается ВСЁ семейство; второе — неизвестный
-- код. Удалённая строка неотличима от никогда не существовавшей, и удаление
-- стоило бы ровно этого различения.
--
-- ЧТО СНИМАЕТ СТРОКУ — названо ТОЧНО, потому что здесь стояло обещание шире
-- предмета. Своей записи в реестре уборки (`internal/apps/kaname/retention`) у
-- этих трёх таблиц НЕТ, и ни один уборщик их не перечисляет: предикат
-- `grep -n 'Subject' internal/apps/kaname/retention/registry.go` не даёт ни
-- одного предмета церемонии. Строки снимает ЕДИНСТВЕННЫЙ путь — каскад
-- `token_families_session_fk` от удаления строки сессии, а её удаляет уборка
-- предмета `human_sessions` (`SweepUnservableSessions`, порог поверх снятия
-- либо истечения).
--
-- Отсюда действительный порог жизни этих строк: НЕ срок кода, который идёт
-- минутами, а срок необслуживаемой сессии плюс порог её уборки. Обновляющий
-- токен, переживающий сессию, этим путём не убирается вовсе — рост ограничен
-- числом сессий, а не числом выдач, и запись предметом заведена НЕ здесь
-- (долг назван отдельной задачей, а не отложен маркером).
--
-- =============================================================================
-- СЕМЕЙСТВО — ДОМ КОНТЕКСТА ЦЕРЕМОНИИ, И СОГЛАСИЕ ДЕРЖИТ КЛЮЧ
-- =============================================================================
-- Клиент, человек, сессия и область живут на строке семейства И на строке кода
-- (так их читает обмен одним запросом, без соединения). Два написания молча
-- разойтись НЕ МОГУТ: код и обновляющий токен ссылаются на семейство СОСТАВНЫМ
-- внешним ключом по всем ЧЕТЫРЁМ столбцам контекста сразу (`client_id`,
-- `user_id`, `session_id`, `scope` — плюс сам `family_id`, итого пять) —
-- расхождение отвергает база, а не проверка писателя.
--
-- У этого ключа НЕТ `ON UPDATE`, и это существо, а не умолчание: строка
-- выданного есть СВИДЕТЕЛЬСТВО о предъявленном, а не кэш текущего семейства.
-- Каскад на контексте означал бы, что сессию и область прав уже выданного кода
-- можно переписать обновлением родителя, — и ровно это он и означал, пока ключ
-- был один на контекст И живость.
--
-- Сессия обязательна и уходит вместе с собой каскадом: код, выданный в сессии,
-- которой больше нет, обменять всё равно нельзя, а строка без сессии читалась бы
-- как «выдан вне входа».
--
-- =============================================================================
-- ЖИВАЯ ЗАПИСЬ ПРИ ОТОЗВАННОМ СЕМЕЙСТВЕ — НЕПРЕДСТАВИМА, А НЕ ЗАПРЕЩЕНА
-- =============================================================================
-- Отметка отзыва на семействе сама по себе ничего не разводит. Пока `revoked_at`
-- не входит НИ В ОДИН уникальный индекс, отзыв меняет неключевую колонку и берёт
-- на строке семейства `FOR NO KEY UPDATE`, а вставка дочерней строки по внешнему
-- ключу берёт `FOR KEY SHARE`. Эти два замка СОВМЕСТИМЫ — движок их не разводит,
-- и выдача, начатая до отзыва, спокойно доходит до вставки уже ПОСЛЕ него.
--
-- Замер на postgres:16-alpine, две сессии: незакоммиченная вставка ребёнка,
-- следом отзыв с `lock_timeout = 2s`. Форма без `live` в ключе — отзыв прошёл за
-- 0.07 с, вставку не заметив. Та же сцена с `live` в ключе — отзыв ЗАБЛОКИРОВАН
-- и снят по истечении 2 с.
--
-- Поэтому признак живости семейства вынесен ОТДЕЛЬНОЙ колонкой `live`, связанной
-- с отметкой ограничением `token_families_live_pair_ck`, и введён в СВОЙ ключ
-- `token_families_live_uk (id, live)`, на который дети ссылаются ОТДЕЛЬНЫМ от
-- контекста внешним ключом. Следствия, и все три держит движок, а не писатель:
--
--   - отзыв стал КЛЮЧЕВЫМ обновлением и конфликтует со вставкой ребёнка;
--   - отзыв успел первым — вставка получает 23503, и транзакция выдачи
--     откатывается целиком: токена не появляется;
--   - вставка успела первой — `ON UPDATE CASCADE` проставляет свежей строке
--     `family_live = false`, и гасить её руками нечего.
--
-- =============================================================================
-- ЭТОТ ЖЕ КАСКАД ДАЁТ ЦИКЛ ЗАМКОВ — И СНИМАЕТСЯ ОН ПОРЯДКОМ, А НЕ ПОВТОРОМ
-- =============================================================================
-- Каскад, которым держится предыдущий раздел, ходит от РОДИТЕЛЯ К ДЕТЯМ: отзыв
-- берёт ключевой замок на семействе, а затем идёт за замками всех его строк.
-- Выдача до этой полосы шла НАВСТРЕЧУ: условный `UPDATE` предъявленной строки
-- брал замок на РЕБЁНКЕ, и лишь потом вставка преемника брала `FOR KEY SHARE`
-- на семействе. Два встречных порядка — это цикл, и движок снимал одного.
--
-- Снимал он ОТЗЫВ: замер на postgres:16-alpine, 6 прогонов из 6 — жертвой
-- становится транзакция отзыва, семейство остаётся живым, токен остаётся
-- активным. Цикл даёт САМ КАСКАД: отзыв, состоящий из ОДНОГО оператора, даёт те
-- же 6 из 6, так что снятие дописывающих операторов его не лечит.
--
-- Проигрывает здесь не запрос арендатора, а КОНТРОЛЬ БЕЗОПАСНОСТИ, и повтора у
-- него нет: признак повторяемости до клиента доезжает, но повторить обязан
-- клиент, а похититель не повторяет. Поэтому цикл снят ПОРЯДКОМ ЗАМКОВ, а не
-- повтором: обмен и ротация берут замок семейства ПЕРВЫМИ, отдельным оператором
-- до условного `UPDATE` ребёнка (`internal/repo/kaname/pg/oauth_ceremony_repo.go`,
-- `lockFamilyOfCodeSQL` и `lockFamilyOfRefreshSQL`). Оба порядка становятся
-- «родитель → ребёнок», и цикла не остаётся.
--
-- Повтор лечил бы СИМПТОМ и оставлял бы контроль безопасности зависимым от
-- поведения клиента — поэтому его здесь нет.
--
-- Признак активности ребёнка стал ПРОИЗВОДНЫМ (`GENERATED ALWAYS … STORED`) от
-- собственной отметки снятия и живости семейства. Производным, а не проверяемым
-- ограничением: «облегчённый» вариант с обычной колонкой и `CHECK (family_live
-- OR NOT active)` ЛОМАЕТ ОТЗЫВ — каскад проставил бы `family_live = false`
-- строке, у которой `active = true`, нарушил бы это ограничение и уронил бы
-- транзакцию ОТЗЫВА, то есть сам контроль безопасности. Производная колонка
-- пересчитывается тем же каскадом и уронить его не может.
--
-- Цена названа: писать `active` больше НЕЛЬЗЯ НИКОМУ — попытка отвергается кодом
-- 428C9. Снятие записывается отметкой `deactivated_at`, признак следует за ней
-- сам. Ровно этой ценой «активная запись при отозванном семействе» перестаёт
-- быть представимой — включая ручной SQL и восстановление из дампа.

-- +goose Up

-- +goose StatementBegin
CREATE TABLE kaname.token_families (
    id             text NOT NULL,
    client_id      text NOT NULL,
    user_id        text NOT NULL,
    session_id     text NOT NULL,
    scope          text[] NOT NULL,
    created_at     timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at     timestamp with time zone,
    revoked_reason text,
    -- Живость семейства ОТДЕЛЬНОЙ колонкой — ради того, чтобы попасть в ключ:
    -- отметка `revoked_at` вне ключа оставляет отзыв неключевым обновлением, а
    -- оно со вставкой ребёнка НЕ конфликтует (см. головной раздел).
    live           boolean DEFAULT true NOT NULL,
    CONSTRAINT token_families_pkey PRIMARY KEY (id),
    -- ДВА ключа, потому что у них ДВЕ РАЗНЫЕ ЗАДАЧИ, и в одном они несовместимы.
    --
    -- Контекст церемонии обязан быть НЕИЗМЕНЯЕМЫМ у выданного: строка кода —
    -- свидетельство о том, что было предъявлено, а не кэш текущего состояния
    -- семейства. Живость, наоборот, обязана СНОСИТЬСЯ вниз каскадом.
    --
    -- Один ключ на все шесть столбцов давал ровно одно правило обновления на
    -- обе задачи, и каскад, заведённый ради живости, доставался контексту:
    -- `UPDATE token_families SET session_id = …` и `SET scope = …` ПРОХОДИЛИ и
    -- молча переписывали сессию и область прав уже выданного кода (измерено:
    -- область `{openid,profile}` становилась `{openid,profile,admin}` у строки,
    -- выданной до этого оператора). Задним числом расширить права выданного
    -- нельзя ничем, и меньше всего — обновлением родителя.
    CONSTRAINT token_families_context_uk UNIQUE (id, client_id, user_id, session_id, scope),
    -- Живость отдельным ключом: `live` стоит в УНИКАЛЬНОМ индексе, поэтому отзыв
    -- остаётся обновлением КЛЮЧА и движок по-прежнему разводит его со вставкой
    -- ребёнка (см. головной раздел). Ради этого ключ и заведён.
    CONSTRAINT token_families_live_uk UNIQUE (id, live),
    CONSTRAINT token_families_id_form_ck CHECK ((id ~ '^tfm-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT token_families_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(client_id) ON DELETE CASCADE,
    CONSTRAINT token_families_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT token_families_session_fk FOREIGN KEY (session_id)
        REFERENCES kaname.human_sessions(id) ON DELETE CASCADE,
    -- Область непуста, без пустых имён и без NULL: пустая область — не «все
    -- права», а отсутствие решения, и хранить её как область нельзя.
    CONSTRAINT token_families_scope_ck CHECK (
        (cardinality(scope) > 0)
        AND (array_position(scope, NULL::text) IS NULL)
        AND (NOT (scope && ARRAY[''::text]))),
    CONSTRAINT token_families_revoked_pair_ck CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    -- Живость и отметка отзыва — ОДНО состояние, записанное дважды; пара держится
    -- ограничением, а не соглашением писателя.
    CONSTRAINT token_families_live_pair_ck CHECK ((live = (revoked_at IS NULL))),
    -- Словарь причин отзыва ЗАКРЫТ: корзины «прочее» у него нет.
    CONSTRAINT token_families_revoked_reason_ck CHECK (
        ((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY[
            'code-replay'::text, 'refresh-replay'::text, 'logout'::text,
            'session-ended'::text, 'consent-withdrawn'::text, 'client-removed'::text]))))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.token_families IS
  'Семейство выданного по одному коду авторизации (kaname#313). Несёт контекст церемонии — клиента, человека, сессию, область — и отметку отзыва. Отзыв семейства снимает ВСЁ выданное по нему.';

CREATE INDEX token_families_user_id_idx ON kaname.token_families USING btree (user_id);
CREATE INDEX token_families_session_id_idx ON kaname.token_families USING btree (session_id);
CREATE INDEX token_families_client_id_idx ON kaname.token_families USING btree (client_id);

-- +goose StatementBegin
CREATE TABLE kaname.authorization_codes (
    code_digest           text NOT NULL,
    family_id             text NOT NULL,
    client_id             text NOT NULL,
    user_id               text NOT NULL,
    session_id            text NOT NULL,
    scope                 text[] NOT NULL,
    redirect_uri          text NOT NULL,
    code_challenge        text NOT NULL,
    code_challenge_method text NOT NULL,
    issued_at             timestamp with time zone DEFAULT now() NOT NULL,
    expires_at            timestamp with time zone NOT NULL,
    -- Живость семейства, СНЕСЁННАЯ каскадом: колонка ключа, а не копия решения.
    family_live           boolean DEFAULT true NOT NULL,
    deactivated_at        timestamp with time zone,
    deactivated_reason    text,
    -- ПРОИЗВОДНАЯ от собственной отметки снятия и живости семейства. Писать её
    -- не может никто — ни этот код, ни ручной SQL, ни восстановление из дампа.
    active                boolean GENERATED ALWAYS AS (((deactivated_at IS NULL) AND family_live)) STORED,
    CONSTRAINT authorization_codes_pkey PRIMARY KEY (code_digest),
    -- Сам код НЕ хранится: хранится его свёртка (SHA-256, шестнадцатерично) —
    -- копия таблицы не даёт ни одного годного кода. Та же форма, что у свёртки
    -- носителя сессии (`human_sessions.bearer_digest`).
    CONSTRAINT authorization_codes_digest_form_ck CHECK ((code_digest ~ '^[0-9a-f]{64}$'::text)),
    -- КОНТЕКСТ — ключ БЕЗ `ON UPDATE`: контекст кода не может разойтись с
    -- семейством, и переписать его у выданного нельзя ни с какой стороны.
    -- Умолчание `NO ACTION` отвергает попытку сменить сессию либо область прав
    -- семейства, у которого есть выданное, кодом 23503.
    CONSTRAINT authorization_codes_family_context_fk FOREIGN KEY (family_id, client_id, user_id, session_id, scope)
        REFERENCES kaname.token_families(id, client_id, user_id, session_id, scope)
        ON DELETE CASCADE,
    -- ЖИВОСТЬ — ключ С `ON UPDATE CASCADE`: он отвергает код, заводимый в
    -- отозванное семейство, и сносит отзыв на уже лежащие строки. Каскад здесь
    -- законен ровно потому, что `live` — не контекст, а состояние семейства.
    CONSTRAINT authorization_codes_family_live_fk FOREIGN KEY (family_id, family_live)
        REFERENCES kaname.token_families(id, live)
        ON DELETE CASCADE ON UPDATE CASCADE,
    -- Одно семейство заводится ОДНИМ кодом: второй код того же семейства — это
    -- вторая церемония, и семейство ей полагается своё.
    CONSTRAINT authorization_codes_family_uk UNIQUE (family_id),
    CONSTRAINT authorization_codes_redirect_uri_ck CHECK (
        ((redirect_uri ~ '^https://[^/?#]+'::text) AND (POSITION(('#'::text) IN (redirect_uri)) = 0)
         AND (length(redirect_uri) <= 512))),
    -- PKCE ОБЯЗАТЕЛЕН и метод один — S256 (RFC 7636 §4.2). `plain` не заводится:
    -- значение вне словаря законным стать не может ни одним решением, а колонка,
    -- допускающая его, была бы местом, куда он однажды ляжет.
    CONSTRAINT authorization_codes_challenge_method_ck CHECK ((code_challenge_method = 'S256'::text)),
    -- Испытание — 43 знака base64url без выравнивания: SHA-256 от верификатора.
    CONSTRAINT authorization_codes_challenge_form_ck CHECK ((code_challenge ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT authorization_codes_expiry_after_issue_ck CHECK ((expires_at > issued_at)),
    CONSTRAINT authorization_codes_deactivated_pair_ck CHECK (((deactivated_at IS NULL) = (deactivated_reason IS NULL))),
    -- Словарь ЗАКРЫТ и несёт ровно то, что произошло С САМОЙ СТРОКОЙ. Смерти от
    -- отзыва семейства здесь НЕТ и быть не должно: основание принадлежит
    -- семейству (`token_families.revoked_reason`), а строка кода отвечает за
    -- СВОЁ событие. Копия основания на ребёнке была бы вторым написанием одного
    -- факта — и писалась бы отдельным оператором по КАЖДОЙ строке семейства
    -- внутри транзакции отзыва, под ключевым замком.
    --
    -- Различение при этом не теряется, а становится СТРУКТУРНЫМ:
    --   `deactivated_at IS NOT NULL` — строку погасило собственное событие;
    --   `NOT family_live`            — строка умерла вместе с семейством,
    --                                  основание читается соединением.
    CONSTRAINT authorization_codes_deactivated_reason_ck CHECK (
        ((deactivated_reason IS NULL) OR (deactivated_reason = 'redeemed'::text)))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.authorization_codes IS
  'Код авторизации собственной церемонии (kaname#313). Хранится СВЁРТКОЙ. Обмен — ОДИН оператор с условием на прежнее состояние и возвратом строки; ноль затронутых строк означает отказ и отзыв семейства. Использованный код помечается неактивным и ЖИВЁТ до истечения: «неактивен» и «не найден» обязаны различаться.';

COMMENT ON COLUMN kaname.authorization_codes.family_live IS
  'Живость семейства, снесённая сюда каскадом внешнего ключа. Писателем не выставляется: при заведении строки берётся умолчание, при отзыве семейства её меняет ON UPDATE CASCADE.';

COMMENT ON COLUMN kaname.authorization_codes.active IS
  'Признак активности — ПРОИЗВОДНЫЙ от отметки снятия и живости семейства. Условие одноинструкционного гашения; читателем не вычисляется и ПИСАТЕЛЕМ НЕ ЗАПИСЫВАЕТСЯ (428C9). Снятие пишется отметкой deactivated_at.';

CREATE INDEX authorization_codes_expires_at_idx ON kaname.authorization_codes USING btree (expires_at);
CREATE INDEX authorization_codes_user_id_idx ON kaname.authorization_codes USING btree (user_id);

-- Свёртка кода не идёт в статистику планировщика: ищут её только равенством по
-- первичному ключу, а выборка значений в `pg_stats` была бы выдачей свёрток
-- всякому, кто читает статистику (гейт `TestSecretMaterialCandidatesAreAllAdjudicated`).
ALTER TABLE kaname.authorization_codes ALTER COLUMN code_digest SET STATISTICS 0;

-- +goose StatementBegin
CREATE TABLE kaname.refresh_tokens (
    token_digest       text NOT NULL,
    family_id          text NOT NULL,
    client_id          text NOT NULL,
    user_id            text NOT NULL,
    session_id         text NOT NULL,
    scope              text[] NOT NULL,
    generation         integer NOT NULL,
    issued_at          timestamp with time zone DEFAULT now() NOT NULL,
    expires_at         timestamp with time zone NOT NULL,
    -- Живость семейства, СНЕСЁННАЯ каскадом: колонка ключа, а не копия решения.
    family_live        boolean DEFAULT true NOT NULL,
    deactivated_at     timestamp with time zone,
    deactivated_reason text,
    successor_digest   text,
    -- ПРОИЗВОДНАЯ от собственной отметки снятия и живости семейства. Ради неё и
    -- заведена `family_live`: отозвать семейство и оставить живой токен нельзя.
    active             boolean GENERATED ALWAYS AS (((deactivated_at IS NULL) AND family_live)) STORED,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token_digest),
    CONSTRAINT refresh_tokens_digest_form_ck CHECK ((token_digest ~ '^[0-9a-f]{64}$'::text)),
    -- Те же два ключа и по той же причине, что у кода: контекст — без
    -- `ON UPDATE`, живость — с каскадом.
    CONSTRAINT refresh_tokens_family_context_fk FOREIGN KEY (family_id, client_id, user_id, session_id, scope)
        REFERENCES kaname.token_families(id, client_id, user_id, session_id, scope)
        ON DELETE CASCADE,
    CONSTRAINT refresh_tokens_family_live_fk FOREIGN KEY (family_id, family_live)
        REFERENCES kaname.token_families(id, live)
        ON DELETE CASCADE ON UPDATE CASCADE,
    -- Поколение в семействе ОДНО на номер: две строки одного номера означали бы
    -- разветвление семейства, то есть ту же двойную выдачу, только на ротации.
    CONSTRAINT refresh_tokens_generation_uk UNIQUE (family_id, generation),
    CONSTRAINT refresh_tokens_generation_ck CHECK ((generation >= 0)),
    CONSTRAINT refresh_tokens_expiry_after_issue_ck CHECK ((expires_at > issued_at)),
    CONSTRAINT refresh_tokens_deactivated_pair_ck CHECK (((deactivated_at IS NULL) = (deactivated_reason IS NULL))),
    -- Словарь ЗАКРЫТ и несёт СВОЁ событие строки; смерть от отзыва семейства
    -- читается как `NOT family_live`, а основание — у семейства.
    CONSTRAINT refresh_tokens_deactivated_reason_ck CHECK (
        ((deactivated_reason IS NULL) OR (deactivated_reason = 'rotated'::text))),
    -- Преемник есть РОВНО у ротации: снятый отзывом токен преемника не имеет, а
    -- ротация без преемника означала бы потерянное поколение.
    CONSTRAINT refresh_tokens_successor_pair_ck CHECK (
        ((successor_digest IS NULL) = (deactivated_reason IS DISTINCT FROM 'rotated'::text))),
    CONSTRAINT refresh_tokens_successor_form_ck CHECK (
        ((successor_digest IS NULL) OR (successor_digest ~ '^[0-9a-f]{64}$'::text)))
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.refresh_tokens IS
  'Обновляющий токен собственной церемонии (kaname#313). Хранится СВЁРТКОЙ. Ротация — ТОТ ЖЕ механизм, что обмен кода: один оператор с условием на прежнее состояние и возвратом. Отротированный токен помечается неактивным и ЖИВЁТ до истечения — повтор обязан отличаться от неизвестного.';

CREATE INDEX refresh_tokens_family_id_idx ON kaname.refresh_tokens USING btree (family_id);
CREATE INDEX refresh_tokens_expires_at_idx ON kaname.refresh_tokens USING btree (expires_at);

COMMENT ON COLUMN kaname.refresh_tokens.family_live IS
  'Живость семейства, снесённая сюда каскадом внешнего ключа. Писателем не выставляется.';

COMMENT ON COLUMN kaname.refresh_tokens.active IS
  'Признак активности — ПРОИЗВОДНЫЙ от отметки снятия и живости семейства; писателем НЕ ЗАПИСЫВАЕТСЯ (428C9). Снятие пишется отметкой deactivated_at.';

ALTER TABLE kaname.refresh_tokens ALTER COLUMN token_digest SET STATISTICS 0;
ALTER TABLE kaname.refresh_tokens ALTER COLUMN successor_digest SET STATISTICS 0;

-- +goose Down

-- Откат снимает записи, которые восстанавливаются САМОЙ ЦЕРЕМОНИЕЙ: код живёт
-- минуты, обновляющий токен перевыпускается повторным входом. Невосстановимого
-- материала здесь нет — в отличие от способов входа, чей откат уничтожать
-- отказывается.
--
-- Порядок обратен заведению: ссылающиеся уходят раньше семейства.
DROP TABLE kaname.refresh_tokens;
DROP TABLE kaname.authorization_codes;
DROP TABLE kaname.token_families;
