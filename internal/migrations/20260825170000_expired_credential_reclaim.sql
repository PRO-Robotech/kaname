-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260825170000_expired_credential_reclaim — ИСТЁКШЕЕ УДОСТОВЕРЕНИЕ СНИМАЕТСЯ
-- ПЛАТФОРМОЙ, И ВЕЛИЧИНЫ УМОЛЧАНИЯ ПОТОЛКА ПЕРЕСМОТРЕНЫ.
--
-- Задача `PRO-Robotech/kacho#1264`; приёмка —
-- `services/iam/docs/engineering/acceptance/expired-credential-reclaim.md`
-- (вердикт APPROVED, круг 2).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЛОВИН ДВЕ, И ВТОРАЯ ОБЯЗАТЕЛЬНА
--
-- Первая половина живёт в коде: уборщик снимает строку, чей срок истёк более чем
-- на её собственную отсрочку назад, и место возвращает существующий триггер
-- списания.
--
-- Вторая половина здесь. Величины умолчания потолка были выведены как
-- «одновременно действующих × 2», и множитель назван ПЛАТОЙ ЗА ОТСУТСТВИЕ
-- УБОРКИ — дословно, в шапке миграции потолка (20260824230000). Сделать одну
-- уборку значило бы МОЛЧА УЖЕСТОЧИТЬ предел: запас, заложенный под неотозванные
-- истёкшие, исчезает вместе с ними, а число остаётся прежним. Арендатор получил
-- бы предел жёстче прежнего, и ему об этом не сказали бы ничем.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДИКАТ ПОТОЛКА ОБЪЯВЛЯЕТСЯ ИСПОЛНЕННЫМ — ЗДЕСЬ, А НЕ ПРАВКОЙ ЕГО ТЕКСТА
--
-- Миграция 20260824230000 записала: «Появится автоматическое их снятие —
-- величины пересматриваются вниз, до одновременного использования». Снятие
-- появилось. Применённую миграцию не правим (ban #5), в том числе её
-- комментарии: правка комментария — это правка файла, и различать её пришлось бы
-- правилом, которого в дереве нет. Поэтому исход раннего текста называет
-- позднейший — вот этот.
--
-- ИСХОД ПЕРЕСМОТРА — НЕ ТОТ, КОТОРОГО ЖДАЛ ПРЕДИКАТ: величины идут ВВЕРХ,
-- 10 → 12 и 20 → 24. Понижение отказало бы тому, кто ротирует ПРАВИЛЬНО.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ИЗ ЧЕГО ПЕРЕСЧИТАНО (а не «из вкуса»)
--
-- Прежнее основание: «5 назначений» и множитель ×2 как запас под мусор.
-- Разбор вскрыл, что запаса в числе НЕ БЫЛО ВОВСЕ — оно и есть модельный ПИК.
--
--   Правильная ротация заводит новое удостоверение ДО того, как истекло
--   прежнее (иначе доступ рвётся), и в окне перехода ОБА действуют. Пять — это
--   число НАЗНАЧЕНИЙ (рабочее место, автоматизация, временный доступ), а не
--   число строк: при одновременной плановой ротации всех назначений строк
--   становится десять, и все десять ЖИВЫЕ.
--
-- Практика подтверждена не рассуждением, а собственным модулем платформы:
-- `terraform/modules/iam-machine-identity/variables.tf` держит ключи КАРТОЙ
-- именно ради этого — смена ключа требует двух живых ключей одновременно.
--
-- Отсюда разложение по НОВОМУ основанию:
--
--   iam.user.credential            = 5  назначений × 2 (ротация внахлёст) + 2 разовых = 12
--   iam.serviceAccount.credential  = 10 назначений × 2                      + 4 разовых = 24
--
-- «Разовое» — аварийный доступ при разборе инцидента и временный доступ
-- исполнителю: ровно те два случая, когда отказ обходится дороже всего, потому
-- что наступает в худший момент. На прежнем числе арендатор, ротирующий все свои
-- назначения в одном окне, стоял на 10/10 и не мог выпустить НИ ОДНОГО
-- дополнительного удостоверения.
--
-- Пик при этом ограничен СВЕРХУ, и это свойство, а не пожелание: строка занимает
-- место `срок + отсрочка`, значит на одно назначение приходится
-- `(T + G) / P` строк, и при `P >= max(T, G)` это не больше двух. Прежде
-- закрывающего события не существовало вовсе, и накопление шло без верхней
-- границы.
--
-- ЦЕНА ПОВЫШЕНИЯ НАЗВАНА ЧЕСТНО: поверхность утечки растёт на 20 %. Принята
-- сознательно против альтернативы, которая хуже: предел, отказывающий в момент
-- аварийной замены, поднимают ВРУЧНУЮ И НАВСЕГДА, и тогда он перестаёт
-- ограничивать вовсе.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЯВНЫЙ UPDATE, А НЕ ПОВТОРНЫЙ ПОСЕВ
--
-- Величины засеяны применённой миграцией через `INSERT … ON CONFLICT (id) DO
-- NOTHING`. Повторный посев их НЕ МЕНЯЕТ by construction — решение приёмки в
-- дереве не наступило бы вовсе, и это было бы ненаблюдаемо: посев проходит,
-- миграция зелёная, число прежнее.
--
-- Обратного заполнения `project_resource_quotas` не требуется, и это не догадка:
-- снимок величины в строке учёта обновляется БЕЗУСЛОВНО и ДО списания (функция
-- `kacho_quota_count`, ветвь принципала), поэтому первая же мутация принесёт
-- действующее значение, а отказ назовёт его же.

-- +goose Up
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- ── 1. Величины умолчания: пересмотр §4 приёмки ──────────────────────────────
--
-- Ревизию двигать руками не надо: её штампует триггер `limits_stamp_revision` на
-- ИЗМЕНЕНИИ и оставляет на месте при повторе. Значит эта миграция сдвигает
-- ревизию ровно тогда, когда действительно меняет величину.
UPDATE kacho_iam.limits
   SET limit_value = 12
 WHERE id = 'lim-00000000000000033'
   AND kind = 'iam.user.credential'
   AND limit_value <> 12;

UPDATE kacho_iam.limits
   SET limit_value = 24
 WHERE id = 'lim-00000000000000034'
   AND kind = 'iam.serviceAccount.credential'
   AND limit_value <> 24;

-- ── 2. Отбор уборщика идёт ПО ИНДЕКСУ ────────────────────────────────────────
--
-- Частичный индекс по сроку. Он покрывает НЕОБХОДИМОЕ условие отбора
-- (`expires_at <= now() - пол`); точная отсрочка зависит от двух колонок одной
-- строки, по ней планировщик диапазона не строит, и она применяется фильтром
-- ПОВЕРХ отобранного.
--
-- `WHERE expires_at IS NOT NULL` — бессрочные строки в отбор не входят никогда:
-- они ДЕЙСТВУЮТ, их поверхность реальна, и место они занимают по праву.
CREATE INDEX IF NOT EXISTS user_oauth_clients_expires_at_reclaim_idx
    ON kacho_iam.user_oauth_clients (expires_at)
 WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS sa_oauth_clients_expires_at_reclaim_idx
    ON kacho_iam.service_account_oauth_clients (expires_at)
 WHERE expires_at IS NOT NULL;

-- ── 3. Отсечка не порождается там, где она заведомо бессмысленна ─────────────
--
-- Снятие строки удостоверения порождает строку отсечки на предъявлении
-- (`minted_token_revocations`), и таблица эта не убирается ничем. Сегодня строка
-- отсечки появляется только при ОТЗЫВЕ, поэтому тот, кто не отзывает, мусора в
-- ней не делает. Автоснятие сделало бы его КАЖДЫМ: темп роста отсечек стал бы
-- равен темпу выдачи удостоверений.
--
-- Отсечка `revoke_before = now()` отсекает токены, отчеканенные ДО этого
-- момента. Если строка уже истекла, то после истечения она не могла отчеканить
-- ничего, а всё отчеканенное до — мертво: срок токена урезается до остатка срока
-- клиента. Значит при снятии УЖЕ ИСТЁКШЕЙ строки отсечка доказуемо не отсекает
-- ни одного живого токена.
--
-- Условие стоит в объявлении (`WHEN`), а не в теле функции: так отбор виден там,
-- где принимается решение, и не платит вызовом. Та же форма, что у второго
-- триггера миграции 898002.
--
-- ВЕЛИЧИНЫ В УСЛОВИИ НЕТ НИ ОДНОЙ, И ЭТО ВЫБОР. Предикат — `expires_at > now()`,
-- то есть «строка ещё действовала в момент снятия». Условие с допуском
-- расхождения часов потребовало бы ЧИСЛА в SQL, а гейт, стерегущий однократность
-- объявления величин политики, обходит только файлы Go: работа вышла бы из-под
-- него молча. Здесь второго объявления не появляется by construction.
--
-- Побочное следствие названо явно: то же условие снимает бессмысленную отсечку и
-- при РУЧНОМ отзыве истёкшего удостоверения. Это не «заодно починили» — это одно
-- правило, у которого два вызывающих.
DROP TRIGGER IF EXISTS user_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.user_oauth_clients;
CREATE TRIGGER user_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.user_oauth_clients
    FOR EACH ROW
    WHEN (OLD.expires_at IS NULL OR OLD.expires_at > now())
    EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();

DROP TRIGGER IF EXISTS sa_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.service_account_oauth_clients;
CREATE TRIGGER sa_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.service_account_oauth_clients
    FOR EACH ROW
    WHEN (OLD.expires_at IS NULL OR OLD.expires_at > now())
    EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();

-- ЛОЖНАЯ ПОСЫЛКА В ПРИМЕНЁННОЙ МИГРАЦИИ — НАЗВАНА ВСЛУХ, ПРАВИТЬ ЕЁ НЕЛЬЗЯ.
--
-- Шапка 898002 объявляет: «Истечение срока клиента не порождает НИЧЕГО и не
-- должно: срок выдаваемого токена не превышает остатка срока клиента, поэтому
-- токенов, переживших клиента, не существует». Для полосы КЛЮЧЕВОЙ ПАРЫ это
-- верно. Для ДОКЕРНОЙ — нет: её токен чеканится с фиксированным сроком и
-- остатком срока строки не урезается, поэтому переживает её на срок до этой
-- величины.
--
-- На вывод настоящего раздела это не влияет: отсечка ключуется идентификатором
-- СТРОКИ удостоверения, а докерный токен несёт субъектом идентификатор
-- ПРИНЦИПАЛА и с ключом отсечки совпасть не может by construction — то есть на
-- докерной полосе отсечка не работала и до сужения. Но величина эта входит
-- слагаемым в технический пол отсрочки, и потому названа здесь.

COMMENT ON TRIGGER user_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.user_oauth_clients IS
    'cuts tokens minted by a credential row that was still LIVE when removed. An '
    'already-expired row cannot have minted anything after it expired, and what it '
    'minted before is dead by then — the token TTL is trimmed to the remainder of '
    'the client lifetime. A cut-off row for it would be a permanent row about a '
    'transient nothing, and this table has no sweeper of its own';

COMMENT ON TRIGGER sa_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.service_account_oauth_clients IS
    'mirror of the user-side trigger: only a credential that was LIVE at removal '
    'leaves a cut-off row';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- Откат ВОЗВРАЩАЕТ, а не оставляет другую форму: откат, оставляющий иное
-- правило, тихо сменил бы его вместо того, чтобы вернуть.
DROP TRIGGER IF EXISTS user_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.user_oauth_clients;
CREATE TRIGGER user_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.user_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();

DROP TRIGGER IF EXISTS sa_oauth_client_removal_cuts_minted_tokens
    ON kacho_iam.service_account_oauth_clients;
CREATE TRIGGER sa_oauth_client_removal_cuts_minted_tokens
    AFTER DELETE ON kacho_iam.service_account_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.minted_cutoff_on_client_removal();

DROP INDEX IF EXISTS kacho_iam.user_oauth_clients_expires_at_reclaim_idx;
DROP INDEX IF EXISTS kacho_iam.sa_oauth_clients_expires_at_reclaim_idx;

UPDATE kacho_iam.limits SET limit_value = 10
 WHERE id = 'lim-00000000000000033' AND limit_value <> 10;
UPDATE kacho_iam.limits SET limit_value = 20
 WHERE id = 'lim-00000000000000034' AND limit_value <> 20;
-- +goose StatementEnd
