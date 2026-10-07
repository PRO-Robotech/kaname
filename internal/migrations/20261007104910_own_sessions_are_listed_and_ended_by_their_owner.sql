-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- own_sessions_are_listed_and_ended_by_their_owner — ЗАПИСЬ СЕССИИ получает
-- описание клиента, СЛОВАРЬ ПРИЧИН СНЯТИЯ — шестое значение
-- `ended-from-another-session` (задача PRO-Robotech/kaname#634).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`
-- (редакция 4, SHA-256
-- `63333cc2f8a0a99588f0f7c3cc01218e12fc6a11c553be0c9f81096a093e2878`; решения
-- Р3, Р6; §6 инв. 5, 6). Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ОПИСАНИЕ КЛИЕНТА (`user_agent`, Р3)
-- =============================================================================
-- Заголовок `User-Agent` запроса, ВЫДАВШЕГО сессию, приведённый службой:
-- байты вне UTF-8 заменены руной U+FFFD, значение урезано до 512 рун (единица
-- — руна, `char_length` базы в кодировке UTF8 считает их же). Пишет столбец
-- только операция выдачи; перевыпуск носителя его не трогает. Читатель — ровно
-- перечень своих сессий человека.
--
-- Отсутствие — NULL, а не пустая строка: клиент не назвался, либо запись выдана
-- до этого изменения. Пустой строки ограничение не принимает — у отсутствия одна
-- форма. Обратного заполнения нет: значения о прежних записях никто не знал, и
-- «не знаем» — честный ответ о них.
--
-- =============================================================================
-- ПРИЧИНА `ended-from-another-session` (Р6)
-- =============================================================================
-- Человек снял свою запись из другой своей сессии: выход из выбранной либо из
-- всех, кроме текущей. Ограничение снимается и ставится заново ПОД ТЕМ ЖЕ ИМЕНЕМ
-- (`human_sessions_ended_reason_check`) одной транзакцией: первый оператор
-- берёт таблицу исключительным захватом до конца транзакции, и окна
-- «ограничения нет» не видит ни один писатель. Значение ДОБАВЛЯЕТСЯ, лежащих
-- строк накат не трогает. Перечень в домене (`HumanSessionEndReasons`) правится
-- тем же изменением; согласие держит проба KN-SER-07.

-- +goose Up

ALTER TABLE kaname.human_sessions
    ADD COLUMN user_agent text;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_user_agent_check
        CHECK (((user_agent IS NULL) OR ((user_agent <> ''::text) AND (char_length(user_agent) <= 512))));
COMMENT ON COLUMN kaname.human_sessions.user_agent IS
    'Описание клиента, каким его назвал запрос выдачи сессии (заголовок User-Agent, приведённый службой: байты вне UTF-8 — U+FFFD, не длиннее 512 рун). Пишет только выдача; NULL — клиент не назвался либо запись старше столбца (kaname#634, Р3).';

ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text, 'ended-from-another-session'::text]))));

-- +goose Down

-- Откат возвращает словарь из пяти значений и переводит строки, снятые из
-- другой сессии, в `logout` (§6 инв. 5): различение теряется, факт и момент
-- снятия — нет; `ended_at` откат не трогает. `logout` — ближайшее слово
-- прежнего словаря: снятие самим человеком.
--
-- ЗАХВАТ ТАБЛИЦЫ — ПЕРВЫМ оператором, до перевода: без него между переводом и
-- заведением ограничения помещается писатель, ещё знающий новое слово, и откат
-- отказал бы целиком. Откат берёт ТОЛЬКО эту таблицу — писатели снятия держат
-- порядок «личность → строки сессии», и захват личности здесь создал бы с ними
-- цикл ожидания. Описание клиента снимается вместе со столбцом: прежний код его
-- не пишет и не читает.
LOCK TABLE kaname.human_sessions IN ACCESS EXCLUSIVE MODE;

UPDATE kaname.human_sessions SET ended_reason = 'logout' WHERE ended_reason = 'ended-from-another-session';

ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_ended_reason_check;
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_ended_reason_check
        CHECK (((ended_reason IS NULL) OR (ended_reason = ANY (ARRAY['logout'::text, 'password-change'::text, 'second-factor-removed'::text, 'admin-force-logout'::text, 'email-verified'::text]))));

ALTER TABLE kaname.human_sessions
    DROP CONSTRAINT human_sessions_user_agent_check;
ALTER TABLE kaname.human_sessions
    DROP COLUMN user_agent;
