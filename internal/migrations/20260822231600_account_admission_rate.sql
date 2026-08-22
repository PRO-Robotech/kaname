-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- =============================================================================
-- Потолок ТЕМПА заведения аккаунтов одной личностью.
-- =============================================================================
-- Задача `PRO-Robotech/kacho#618`.
--
-- ЧЕГО НЕ БЫЛО. Потолок на ЧИСЛО аккаунтов личности заведён (484002) и работает.
-- Он держит объём и не держит скорость: пять заводятся за секунду, затем ещё
-- пять с новой подтверждённой почты, и так далее. Стоимость обхода равна
-- стоимости нового подтверждённого адреса — не ноль, но и не барьер.
--
-- ПРЕДМЕТ ЗДЕСЬ — «не больше N заведений за окно с одной личности». Носитель тот
-- же, что у объёма: внешний идентификатор входа. Выдумывать его не пришлось.
--
-- ПОЧЕМУ ОТДЕЛЬНАЯ ТАБЛИЦА УЧЁТА, А НЕ СТОЛБЕЦ В СТРОКЕ ОБЪЁМА. Счёт «за окно»
-- требует ВРЕМЕНИ, а не только числа, и строка учёта объёма времени не несёт.
-- Дописать столбец туда нельзя: та таблица общая на шесть владельцев и её форму
-- читает единственный производитель отказа платформы — своя форма у одного
-- владельца означала бы расхождение контракта отказа.
--
-- ПОЧЕМУ ОКНО ФИКСИРОВАННОЕ, А НЕ СКОЛЬЗЯЩЕЕ, И ЧТО ЭТО СТОИТ. Скользящее окно
-- требует хранить отметку КАЖДОГО заведения — то есть таблицу, растущую с
-- нагрузкой, и её уборку. Фиксированное окно живёт в ОДНОЙ строке на личность и
-- убирать нечего. Плата названа прямо, а не скрыта: на стыке двух окон личность
-- способна завести до 2N штук (N в конце одного окна и N в начале следующего).
-- Для предела, чей предмет — сделать автоматизацию дорогой, а не невозможной,
-- двукратный всплеск на границе приемлем; для предела, обязанного держать
-- жёсткую величину, он был бы неприемлем, и тогда нужна другая форма.
--
-- ПОЧЕМУ ЭТО ТРИГГЕР, А НЕ ПРОВЕРКА В USE-CASE. Ровно та же причина, что у
-- объёма: аккаунт заводится ДВУМЯ путями — явным созданием и первым входом, —
-- и проверка в коде обязана была бы стоять в обоих. Плюс «посчитал за окно →
-- вставил» есть check-then-act через границу оператора: между чтением и вставкой
-- помещается чужая запись, и оба создателя видят одно и то же свободное место
-- окна (ban #10).
--
-- ПОЧЕМУ ТРИГГЕР ЗОВЁТСЯ ПОСЛЕ ТРИГГЕРА ОБЪЁМА. Имя выбрано так, что при равном
-- событии он идёт вторым (`accounts_quota_count` < `accounts_rate_admission`).
-- Это решение о том, ЧТО УВИДИТ АРЕНДАТОР, когда нарушено и то и другое: отказ по
-- объёму терминален («подними предел»), отказ по темпу временен («подожди»).
-- Сообщать сначала терминальный полезнее — временный на исчерпанном объёме
-- отправил бы ждать того, кому ожидание не поможет никогда.
--
-- ПЕРВЫЙ ВХОД НЕ ЛОМАЕТСЯ, И ЭТО СВОЙСТВО ПОСТРОЕНИЯ, А НЕ ВЕТКА. Личная область
-- заводится сама, и отказ по темпу на первом входе есть отказ во входе. Первая
-- запись личности проходит ВЕТВЬЮ ВСТАВКИ единственного оператора ниже — то есть
-- до всякого сравнения с величиной, — поэтому не отвергается ни при какой её
-- величине, включая ноль. Затравка ниже заводит ряд каждой УЖЕ существующей
-- личности, поэтому «ряда нет» означает ровно «аккаунтов не заводила».

-- +goose Up
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- -----------------------------------------------------------------------------
-- Авторитет: величина и окно.
-- -----------------------------------------------------------------------------
-- Величины ПРОДУКТОВЫЕ, поэтому лежат строкой, а не константой в коде: иначе
-- администратор облака не сможет их изменить, и возможность «настроить темп»
-- была бы объявлена и не исполнима — тот самый класс «принято-и-проигнорировано»
-- на уровне подсистемы.
--
-- ОТДЕЛЬНО ОТ `kacho_iam.limits`, и это не дублирование механизма. Там величина
-- СКАЛЯР (`limit_value`), а здесь ПАРА (сколько и за сколько), и вид там обязан
-- состоять в закрытом каталоге считаемых, каждая запись которого называет
-- реальный тип модели прав. Темп типом не является: считать в нём нечего, и
-- запись о нём сломала бы гейт каталога справедливо.
--
-- Дисциплина при этом ТА ЖЕ: отзыв надгробием, а не удалением строки; тройка
-- уникальна среди действующих; величина читается на пути записи.
CREATE TABLE IF NOT EXISTS kacho_iam.account_admission_rate_limits (
    id             bigserial   PRIMARY KEY,
    kind           text        NOT NULL,

    -- Сколько заведений допускается за окно.
    max_events     bigint      NOT NULL,
    -- Длина окна. В секундах, а не интервалом: сравнение и правка одним числом,
    -- и величина читается администратором без разбора синтаксиса интервалов.
    window_seconds bigint      NOT NULL,

    -- Отзыв надгробием, а не удалением строки: величину, снятую по ошибке, надо
    -- уметь назначить заново, а частичный уникальный индекс ниже это позволяет.
    -- Читается триггером на каждом списании.
    withdrawn_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),

    -- Форма вида — та же, что у величин объёма. Членство в каталоге здесь НЕ
    -- проверяется намеренно: каталог перечисляет то, что СЧИТАЮТ, а темп не
    -- считают ни в чём.
    CONSTRAINT account_admission_rate_limits_kind_ck
        CHECK (kind ~ '^[a-z][a-z0-9]*\.[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)?$'),

    -- Ноль — законная величина: «за окно ни одного, кроме первого». Отрицательное
    -- бессмысленно.
    CONSTRAINT account_admission_rate_limits_max_ck    CHECK (max_events >= 0),
    -- Нулевое окно сделало бы предел бессодержательным (всякое окно уже истекло),
    -- и выглядело бы это как работающий потолок.
    CONSTRAINT account_admission_rate_limits_window_ck CHECK (window_seconds > 0)
);

-- ЧЕГО ЗДЕСЬ НАМЕРЕННО НЕТ: ни `updated_at`, ни монотонной ревизии.
--
-- `updated_at`, который обновляла бы только вставка, ЛГАЛ БЫ: читающий принял бы
-- его за «когда величину меняли в последний раз», а он говорил бы «когда её
-- завели». Значение, которое пишут и не читают, — отдельный класс дефекта, и
-- заводить его ради симметрии с соседней таблицей не стоит. Кому нужно «кто и
-- когда менял потолок», тому нужен журнал аудита, а не столбец.
--
-- Ревизии нет по той же мерке: она существует у величин объёма затем, чтобы
-- владельцы типов тянули дельту и догоняли снимок. Здесь тянуть некому —
-- авторитет лежит в этой же базе и читается тем же оператором, который списывает,
-- поэтому отставания снимка не существует как понятия.

COMMENT ON TABLE kacho_iam.account_admission_rate_limits IS
    'the ceiling on the RATE at which one identity may create accounts: how many '
    'per window. Separate from kacho_iam.limits because the value here is a PAIR '
    'and because the closed catalogue of countable kinds admits only real authz '
    'object types — a rate is not a thing one counts instances of';

-- Тройка уникальна СРЕДИ ДЕЙСТВУЮЩИХ. Частичность не оптимизация: без неё отзыв
-- навсегда занимал бы слот, и величину, снятую по ошибке, нельзя было бы назначить
-- заново.
CREATE UNIQUE INDEX IF NOT EXISTS account_admission_rate_limits_kind_uk
    ON kacho_iam.account_admission_rate_limits (kind)
    WHERE withdrawn_at IS NULL;

-- +goose StatementEnd
-- +goose StatementBegin

-- Величина умолчания: три заведения в час.
--
-- Выбрана так, чтобы НЕ КАСАТЬСЯ никого, кто ведёт себя как человек: аккаунтов у
-- одной личности потолок объёма и так допускает пять, а заводить их четыре за час
-- — уже не работа, а автоматизация. И одновременно она делает перебор дорогим:
-- пять аккаунтов вместо секунды занимают часы, а обход через новые адреса
-- оплачивается каждым адресом отдельно.
--
-- ВЗАИМОДЕЙСТВИЕ С ПОТОЛКОМ ОБЪЁМА НАЗВАНО, А НЕ ОБНАРУЖЕНО ПОТОМ. Объём — пять
-- аккаунтов, темп — три в час, значит выбрать весь объём одним заходом нельзя:
-- пятый аккаунт приходит во втором окне. Это НАМЕРЕННО и есть предмет предела —
-- три в час, равные пяти или больше, не замедлили бы ничего, потому что весь
-- объём по-прежнему брался бы за секунду. Цена — человек, которому пять аккаунтов
-- нужны сразу, ждёт час; величина на то и вынесена строкой, чтобы владелец облака
-- решил эту цену иначе, если сочтёт нужным.
--
-- Следствие для проб: утверждение о потолке ОБЪЁМА обязано поднять потолок темпа
-- из-под ног, иначе оно судит не свою полосу и краснеет по чужой причине.
--
-- Это УМОЛЧАНИЕ, а не догма: величина и окно на то и вынесены строкой, чтобы
-- владелец облака менял их без миграции и без выката.
INSERT INTO kacho_iam.account_admission_rate_limits (kind, max_events, window_seconds)
SELECT 'iam.account', 3, 3600
 WHERE NOT EXISTS (
       SELECT 1 FROM kacho_iam.account_admission_rate_limits
        WHERE kind = 'iam.account' AND withdrawn_at IS NULL);

-- +goose StatementEnd
-- +goose StatementBegin

-- -----------------------------------------------------------------------------
-- Учёт: одно окно на личность и вид.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kacho_iam.identity_admission_windows (
    carrier_id        text        NOT NULL,
    kind              text        NOT NULL,

    -- Начало действующего окна. Двигается только при переходе в следующее окно.
    window_started_at timestamptz NOT NULL DEFAULT now(),
    -- Сколько заведений принято В ЭТОМ окне.
    admitted          bigint      NOT NULL DEFAULT 0,

    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT identity_admission_windows_pkey PRIMARY KEY (carrier_id, kind),
    CONSTRAINT identity_admission_windows_carrier_ck  CHECK (carrier_id <> ''),
    CONSTRAINT identity_admission_windows_admitted_ck CHECK (admitted >= 0)
);

COMMENT ON TABLE kacho_iam.identity_admission_windows IS
    'one row per identity and kind: when the current window started and how many '
    'admissions it has taken. A fixed window, not a sliding one — a sliding window '
    'needs a row per event and a sweeper. The cost is named rather than hidden: '
    'across a window boundary up to 2N admissions are possible';

COMMENT ON COLUMN kacho_iam.identity_admission_windows.carrier_id IS
    'the external login subject (users.external_id), the same carrier the volume '
    'ceiling counts by — a user row is a membership and would hand out the bypass';

-- -----------------------------------------------------------------------------
-- Затравка по УЖЕ существующим личностям.
-- -----------------------------------------------------------------------------
-- Без неё каждая существующая личность получила бы ветвь вставки, то есть одно
-- безусловное заведение сверх потолка. «Ряда нет» обязано означать ровно
-- «аккаунтов не заводила», и затравка — единственное, чем это достигается на
-- живой платформе.
--
-- Окно начинается СЕЙЧАС и пустым: прошлые заведения этому потолку не
-- принадлежат — его тогда не существовало, — и вменять их арендатору значило бы
-- ввести предел задним числом.
INSERT INTO kacho_iam.identity_admission_windows (carrier_id, kind, window_started_at, admitted)
SELECT DISTINCT u.external_id, 'iam.account', now(), 0
  FROM kacho_iam.accounts a
  JOIN kacho_iam.users u ON u.id = a.owner_user_id
 WHERE u.external_id <> ''
ON CONFLICT (carrier_id, kind) DO NOTHING;

-- +goose StatementEnd
-- +goose StatementBegin

-- -----------------------------------------------------------------------------
-- Производитель отказа по темпу.
-- -----------------------------------------------------------------------------
-- ОТДЕЛЬНЫЙ от `kacho_quota_refuse`, и это не вторая копия контракта. Тот
-- рендерится из общего шаблона платформы для ШЕСТИ владельцев и отказывает по
-- строке учёта ОБЪЁМА; полоса темпа существует у одного владельца, читает другую
-- таблицу и требует другого действия от администратора. Внести её в общий шаблон
-- значило бы раздать пяти владельцам ветку, предмета которой у них нет.
--
-- Исходов два, и различие несущее ровно так же, как у объёма: «окно полно»
-- требует ПОДОЖДАТЬ, «величина не названа» требует ЗАВЕСТИ её. Один код на оба
-- отправил бы администратора ждать там, где ждать бесполезно.
CREATE OR REPLACE FUNCTION kacho_iam.kacho_rate_refuse(
    v_carrier_id text,
    v_kind       text
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    v_max    bigint;
    v_window bigint;
BEGIN
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kacho_iam.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF FOUND THEN
        RAISE EXCEPTION 'identity % has reached its admission rate of % % per % seconds',
                        v_carrier_id, v_max, v_kind, v_window
            USING ERRCODE = 'KQ004',
                  DETAIL  = jsonb_build_object(
                                'carrier_type',   'identity',
                                'carrier_id',     v_carrier_id,
                                'kind',           v_kind,
                                'max_events',     v_max,
                                'window_seconds', v_window)::text;
    END IF;

    RAISE EXCEPTION 'identity % has no admission rate stated for %', v_carrier_id, v_kind
        USING ERRCODE = 'KQ005',
              DETAIL  = jsonb_build_object(
                            'carrier_type', 'identity',
                            'carrier_id',   v_carrier_id,
                            'kind',         v_kind)::text;
END;
$$;

COMMENT ON FUNCTION kacho_iam.kacho_rate_refuse(text, text) IS
    'the only producer of a rate refusal: KQ004 = the window is full (wait), '
    'KQ005 = no rate stated (the administrator must state one). Separate from '
    'kacho_quota_refuse because that one is rendered from a template shared by six '
    'owners and speaks about the VOLUME row — this lane exists for one owner only';

-- +goose StatementEnd
-- +goose StatementBegin

-- -----------------------------------------------------------------------------
-- Списание темпа.
-- -----------------------------------------------------------------------------
-- ОТЛОЖЕННЫЙ ограничительный триггер по той же причине, что у объёма: личность
-- резолвится строкой владельца, а внешний ключ на владельца объявлен
-- `DEFERRABLE INITIALLY DEFERRED` — схема ЯВНО разрешает вставить аккаунт раньше
-- его пользователя. Триггер, срабатывающий сразу, отверг бы вставку, которую
-- схема считает законной.
CREATE OR REPLACE FUNCTION kacho_iam.kacho_admission_rate_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_identity text;
    v_max      bigint;
    v_window   bigint;
BEGIN
    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
     WHERE u.id = NEW.owner_user_id;

    -- Владелец БЕЗ личности — законное состояние схемы (строка в состоянии
    -- приглашения внешнего идентификатора не несёт), и такой аккаунт не считается
    -- ни объёмом, ни темпом. Решение здесь то же и по той же причине: счётчик не
    -- вправе запрещать состояния, которых схема не запрещает. Молчаливым оно не
    -- является — предупреждение об этом уже производит триггер объёма, и второе
    -- на то же событие было бы шумом.
    IF v_identity IS NULL OR v_identity = '' THEN
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не «сколько
    -- угодно». Не названная величина означает отказ, как и у объёма: «не сказано»
    -- на пути безопасности читается закрыто.
    SELECT max_events, window_seconds INTO v_max, v_window
      FROM kacho_iam.account_admission_rate_limits
     WHERE withdrawn_at IS NULL AND kind = v_kind;

    IF NOT FOUND THEN
        PERFORM kacho_iam.kacho_rate_refuse(v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- ЕДИНСТВЕННЫЙ оператор, принимающий решение.
    --
    -- Ветвь ВСТАВКИ — первое заведение этой личности: проходит безусловно, до
    -- всякого сравнения с величиной. Это и есть «первый вход не ломается».
    --
    -- Ветвь ПРАВКИ берёт блокировку строки, поэтому второй писатель ждёт коммита
    -- первого и видит его результат: гонку разрешает база, а не порядок. Переход
    -- в следующее окно и списание считаются ОДНИМ выражением — посчитать «истекло
    -- ли окно» отдельно значило бы вернуть check-then-act через границу оператора.
    INSERT INTO kacho_iam.identity_admission_windows AS w
        (carrier_id, kind, window_started_at, admitted)
    VALUES (v_identity, v_kind, now(), 1)
    ON CONFLICT (carrier_id, kind) DO UPDATE
       SET window_started_at = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN now() ELSE w.window_started_at END,
           admitted = CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END,
           updated_at = now()
     WHERE CASE
               WHEN now() >= w.window_started_at + make_interval(secs => v_window)
               THEN 1 ELSE w.admitted + 1 END <= v_max;

    -- `FOUND` после INSERT истинно, когда затронута хотя бы одна строка: и на
    -- ветви вставки, и на ветви правки, чьё условие выполнилось. Ноль строк
    -- означает ровно одно — правка отвергнута условием, то есть окно полно.
    IF FOUND THEN
        RETURN NULL;
    END IF;

    -- Ноль строк означает ровно одно: окно полно. Это не check-then-act —
    -- решение уже принято атомарным оператором выше, а производитель отказа лишь
    -- облекает случившееся в контракт.
    PERFORM kacho_iam.kacho_rate_refuse(v_identity, v_kind);
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION kacho_iam.kacho_admission_rate_count() IS
    'charges one admission of the current window, in the same transaction as the '
    'account row. The first ever admission of an identity goes through the INSERT '
    'branch and is therefore unconditional: a rate refusal on first login would be '
    'a refusal to log in. Refusals come from kacho_rate_refuse';

-- Имя выбрано так, что при равном событии этот триггер идёт ПОСЛЕ триггера
-- объёма: отказ по объёму терминален, отказ по темпу временен, и сообщать
-- сначала терминальный полезнее.
DROP TRIGGER IF EXISTS accounts_rate_admission ON kacho_iam.accounts;
CREATE CONSTRAINT TRIGGER accounts_rate_admission
    AFTER INSERT ON kacho_iam.accounts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_admission_rate_count('iam.account');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

DROP TRIGGER IF EXISTS accounts_rate_admission ON kacho_iam.accounts;
DROP FUNCTION IF EXISTS kacho_iam.kacho_admission_rate_count();
DROP FUNCTION IF EXISTS kacho_iam.kacho_rate_refuse(text, text);
DROP TABLE IF EXISTS kacho_iam.identity_admission_windows;
DROP TABLE IF EXISTS kacho_iam.account_admission_rate_limits;
-- +goose StatementEnd
