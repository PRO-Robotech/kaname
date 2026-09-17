-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- second_factor_rows_carry_state_and_step — ВТОРОЙ ФАКТОР становится строками
-- хранилища способов входа (фаза Ф12, задача PRO-Robotech/kacho#1281).
--
-- Санкция: одобренная Ф12
-- (`docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`,
-- Р1, Р5, Р6, Р9; §4.1 п.1) над одобренной Ф2 П1 (шапка миграции
-- `20260915111233_login_methods_live_in_their_own_rows.sql` отдала СОСТОЯНИЕ
-- строки этой фазе) и Ф11 Р8 (словарь способов один). Доводы там; здесь — то,
-- что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ, А НЕ ПРАВКА ПРИМЕНЁННОЙ
-- =============================================================================
-- Мигратор сверяет версию, а не содержимое: правка применённого файла до базы
-- не доезжает. Словарь вида расширяется ЗДЕСЬ — ограничение снимается и
-- ставится заново ПОД ТЕМ ЖЕ ИМЕНЕМ, потому что имя — координата, которую
-- объявляет гейт сдерживания (`lmDeclaredConstraints`) и сверяет со словарём
-- гейт `TestAssuranceMethodVocabularyIsDeclaredOnce`.
--
-- =============================================================================
-- ЧТО ПРИБАВЛЯЕТСЯ К СТРОКЕ — И ЧЕГО НЕ ПРИБАВЛЯЕТСЯ
-- =============================================================================
-- ВИДЫ: `password` · `totp` · `lookup_secret` — имена словаря Ф11 Р8 дословно,
-- подмножество словаря способов предъявления. Ключ доступа (`webauthn`) строкой
-- этой таблицы НЕ является — его хранилище заводит Ф7 своей приёмкой.
--
-- СОСТОЯНИЕ (`state`): `pending` — секрет чеканен, первый код не предъявлен;
-- `active` — подтверждён. Умолчание `active` — ради лежащих строк пароля: они
-- получают состояние БЕЗ переноса, ровно как обещала шапка Ф2 П1 («колонка с
-- умолчанием добавляется потом без переноса строк»). Строка `pending` способом
-- входа НЕ является: её не читает ни правило уровня, ни полоса входа; живёт она
-- не дольше окна свежести правки своих данных от момента заведения (`created_at`,
-- Ф12 Р8) и снимается уборкой либо заменяется новым заведением.
--
-- «`pending` — ТОЛЬКО У `totp`» — одно ограничение на два вида (Н4 круга 1):
-- набор запасных кодов чеканится вместе с подтверждением и бывает только
-- `active`; пароль — тем более.
--
-- ПОСЛЕДНИЙ ПРИНЯТЫЙ ШАГ (`last_accepted_step`): состояние сверки кода по
-- времени, не секрет. NULL — шага ещё не было (строка `pending`, либо чужой
-- вид). Код шага НЕ СТАРШЕ него отвергается повтором, и запись шага — условный
-- оператор («старше последнего принятого»), он же арбитр двух одновременных
-- предъявлений одной ступени (Ф12 Р5, Ф12-22). Свойство СТРОКИ, то есть
-- человека, а не сессии: код, принятый в одной сессии, отвергается из любой.
--
-- МОМЕНТ (`created_at`) у `pending` — момент заведения (от него срок), у
-- `active` — момент подтверждения; оба пишет ВЫЗЫВАЮЩИЙ своими часами (форма
-- Ф-ж), а не `now()` базы: срок судится часами полосы.
--
-- МАТЕРИАЛ остаётся ОДНОЙ колонкой того же типа: у `totp` — секрет, ОБЁРНУТЫЙ
-- (Ф12 Р2, `internal/keywrap` под своим перечнем ключей), у `lookup_secret` —
-- проверочный материал набора (медленный хеш той же дисциплины, что пароль,
-- Ф12 Р6). Копий, индексов, статистики — как у пароля: ничего; гейт
-- `TestLoginVerifierStaysInsideTheSchema` судит все три вида одним предметом.
--
-- ОГРАНИЧЕНИЙ СВЕРХ ОБЪЯВЛЕННЫХ — ДВА, И ОБА НАЗВАНЫ РЕШЕНИЕМ (приёмка §4.1
-- п.1): `user_login_methods_state_check`, `user_login_methods_pending_only_totp_check`.
-- Оба судят `kind`/`state` и материала не касаются; объявленный набор гейта
-- сдерживания расширен ими тем же изменением, инъекция «чужое ограничение»
-- повторена.
--
-- =============================================================================
-- ПРИЧИНА СНЯТИЯ СЕССИИ — ТРЕТЬЕ ЗНАЧЕНИЕ
-- =============================================================================
-- Снятие фактора самим человеком гасит ПРОЧИЕ его сессии (Ф12 Р9, форма Ф3 Р6
-- п.2), и журнал обязан отличать это от выхода и от смены пароля: словарь
-- `human_sessions_ended_reason_check` получает `second-factor-removed`.
-- Сброс распорядителем (Р10) строк сессии не помечает — он пишет отсечку
-- существующим писателем принудительного выхода, и её читает край.

-- +goose Up

ALTER TABLE kaname.user_login_methods
    DROP CONSTRAINT user_login_methods_kind_check;
ALTER TABLE kaname.user_login_methods
    ADD CONSTRAINT user_login_methods_kind_check
        CHECK ((kind = ANY (ARRAY['password'::text, 'totp'::text, 'lookup_secret'::text])));

ALTER TABLE kaname.user_login_methods
    ADD COLUMN state text NOT NULL DEFAULT 'active',
    ADD COLUMN last_accepted_step bigint;

ALTER TABLE kaname.user_login_methods
    ADD CONSTRAINT user_login_methods_state_check
        CHECK ((state = ANY (ARRAY['pending'::text, 'active'::text]))),
    ADD CONSTRAINT user_login_methods_pending_only_totp_check
        CHECK (((state = 'active'::text) OR (kind = 'totp'::text)));

COMMENT ON COLUMN kaname.user_login_methods.state IS
  'Состояние строки (Ф12 Р1): pending — секрет чеканен, первый код не предъявлен (только у totp; способом входа не является); active — подтверждён.';
COMMENT ON COLUMN kaname.user_login_methods.last_accepted_step IS
  'Последний принятый шаг кода по времени (Ф12 Р5): состояние сверки, не секрет. Код шага не старше него — повтор. NULL — шага ещё не было.';

ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text]))));

-- +goose Down

-- Откат снимает строки второго фактора ВМЕСТЕ с их состоянием — это те же
-- секреты, что у пароля, и та же мера (шапка Ф2 П1): секрет, снятый откатом,
-- восстанавливается только новым заведением каждым держателем. Откат поэтому
-- ОТКАЗЫВАЕТСЯ, пока строки видов `totp` и `lookup_secret` есть; сессии,
-- снятые причиной `second-factor-removed`, уже не обслуживаются никем и
-- переводятся в прежний словарь без потери смысла: они сняты, и остаются
-- снятыми.
LOCK TABLE kaname.user_login_methods IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
DECLARE
  v_rows bigint;
BEGIN
  SELECT count(*) INTO v_rows FROM kaname.user_login_methods WHERE kind IN ('totp', 'lookup_secret');
  IF v_rows > 0 THEN
    RAISE EXCEPTION 'refusing to roll back: kaname.user_login_methods holds % second-factor row(s) (totp / lookup_secret); a rollback would destroy them irreversibly (a lost second factor is recoverable only by every holder enrolling again). WAY OUT: if losing them is the intent, delete those rows deliberately first; the rollback is safe exactly when the count is 0', v_rows
      USING ERRCODE = 'restrict_violation';
  END IF;
END;
$$;
-- +goose StatementEnd

UPDATE kaname.human_sessions SET ended_reason = 'password-change' WHERE ended_reason = 'second-factor-removed';
ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text]))));

ALTER TABLE kaname.user_login_methods
    DROP CONSTRAINT user_login_methods_pending_only_totp_check,
    DROP CONSTRAINT user_login_methods_state_check;
ALTER TABLE kaname.user_login_methods
    DROP COLUMN last_accepted_step,
    DROP COLUMN state;
ALTER TABLE kaname.user_login_methods
    DROP CONSTRAINT user_login_methods_kind_check;
ALTER TABLE kaname.user_login_methods
    ADD CONSTRAINT user_login_methods_kind_check
        CHECK ((kind = ANY (ARRAY['password'::text])));
