// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_repo.go — слой доступа СОБСТВЕННОЙ ЦЕРЕМОНИИ OAuth: код
// авторизации, семейство выданного по нему, обновляющий токен и согласие
// субъекта (задача PRO-Robotech/kaname#313; миграции
// `20260920175117_authorization_code_is_our_record.sql`,
// `20260920175118_interactive_client_carries_its_secret_verifier.sql`,
// `20260920175119_consent_is_our_record.sql`).
//
// # ОДНА ИНСТРУКЦИЯ — ЭТО ИНВАРИАНТ, А НЕ АККУРАТНОСТЬ
//
// «Жив ли код» и «погасить его» здесь НЕДЕЛИМЫ, и неделимыми их делает сам
// движок: условие на ПРЕЖНЕЕ состояние стоит в `WHERE` того же `UPDATE`,
// который пишет новое, и строчный замок держит обоих. Пара «SELECT, потом
// UPDATE» была бы ровно тем check-then-act, который запрещает ban #10: две
// одновременные копии запроса промахнулись бы обе мимо чужой ещё не
// зафиксированной записи и выдали бы по одному коду ДВА набора токенов.
//
// Дефект этот НЕЗАМЕТЕН по положительному пути: последовательный прогон такой
// реализации зелен целиком. Отличает её только проба с конкурирующими
// транзакциями — `oauth_ceremony_race_integration_test.go`.
//
// # НОЛЬ ЗАТРОНУТЫХ СТРОК — ЭТО ТРИ РАЗНЫХ ИСХОДА, А НЕ ОДИН
//
// Ноль строк означает, что условие не выполнилось; ПОЧЕМУ — говорит разбор,
// идущий ПОСЛЕ отката транзакции выдачи:
//
//   - строки нет вовсе → `domain.ErrAuthorizationCodeUnknown`;
//   - строка есть и НЕАКТИВНА → ПОВТОР. Кодом уже воспользовались, второй
//     предъявитель — либо похититель, либо тот, у кого похитили, и различить их
//     нельзя. Поэтому отзывается ВСЁ семейство (RFC 6819 §5.2.1.1);
//   - строка активна, но срок вышел → истечение. Отзыва не влечёт: это не
//     признак похищения.
//
// Ради этого различения использованный код и отротированный токен ПОМЕЧАЮТСЯ
// неактивными и ЖИВУТ до истечения. Удалить строку значило бы сделать повтор
// неотличимым от неизвестного кода — то есть снять отзыв семейства с
// единственного признака, по которому похищение вообще наблюдаемо.
//
// # ЧТО ДЕРЖИТ БАЗА, А НЕ ЭТОТ ФАЙЛ
//
//   - неделимость обмена и ротации — условный `UPDATE … RETURNING` на
//     НАЗВАННОМ уровне изоляции (`ceremonyWriterTx`, решение записано у
//     оператора обмена): исход проигравшего решает перепроверка условия, и
//     умолчание сессии его не меняет;
//   - согласие контекста церемонии между семейством, кодом и токеном —
//     СОСТАВНОЙ внешний ключ `<t>_family_context_fk` по ПЯТИ столбцам сразу
//     (`family_id` плюс четыре столбца контекста: клиент, человек, сессия,
//     область). `ON UPDATE` у него НЕТ намеренно: строка выданного —
//     свидетельство о предъявленном, а не кэш семейства, и переписать её
//     контекст обновлением родителя нельзя — попытка отвергается 23503;
//   - «живая запись при отозванном семействе» — НЕПРЕДСТАВИМА. Живость
//     семейства стоит в СВОЁМ ключе (`token_families_live_uk (id, live)`), дети
//     ссылаются на неё ОТДЕЛЬНЫМ ключом `<t>_family_live_fk` с
//     `ON UPDATE CASCADE`, а их `active` — ПРОИЗВОДНАЯ колонка от собственной
//     отметки снятия и этой живости. Поэтому отзыв стал обновлением КЛЮЧА и
//     движок сам разводит его со вставкой ребёнка: успел отзыв — вставка
//     получает 23503 и транзакция выдачи откатывается; успела вставка — каскад
//     проставляет свежей строке признак. Гасить `active` руками не может НИКТО:
//     запись в неё отвергается кодом 428C9;
//   - ПОРЯДОК ЗАМКОВ «родитель → ребёнок» на обоих путях: обмен и ротация берут
//     семейство первыми (`lockFamilyOfCodeSQL`, `lockFamilyOfRefreshSQL`), иначе
//     встречный порядок с каскадом отзыва даёт цикл, жертвой которого движок
//     выбирал сам отзыв;
//   - «одно поколение на номер в семействе» — `refresh_tokens_generation_uk`;
//   - «одно согласие на тройку субъект-клиент-область» —
//     `consent_grants_subject_client_scope_uk`;
//   - форма свёрток, испытания PKCE и словари причин — ограничения схемы.

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// consentIDPrefix — префикс идентификатора согласия; форма закрыта
// ограничением `consent_grants_id_form_ck`.
const consentIDPrefix = "cg"

// refuseNoSuchClient — ЕДИНСТВЕННЫЙ производитель отказа «интерактивного
// клиента с таким идентификатором в реестре нет».
//
// Отказ несёт ПРИЗНАК `iamerr.ErrNotFound`, а не только текст. Причина
// прикладная: снятие клиента идёт ПОСЛЕ удаления его строки, поэтому
// «строки нет» — ожидаемое состояние, а не неполадка, и отличить его от
// неполадки хранилища вызывающий обязан машинно. Разбор прозы вместо признака
// сделал бы идемпотентность снятия зависящей от формулировки.
func refuseNoSuchClient(clientID string) error {
	return iamerr.Wrapf(iamerr.ErrNotFound, "interactive client %s: not found", clientID)
}

// OAuthCeremonyRepo — хранилище собственной церемонии.
type OAuthCeremonyRepo struct{ pool *pgxpool.Pool }

// NewOAuthCeremonyRepo — построение над пулом.
func NewOAuthCeremonyRepo(pool *pgxpool.Pool) *OAuthCeremonyRepo {
	return &OAuthCeremonyRepo{pool: pool}
}

// NewAuthorizationCode — что нужно знать, чтобы завести код и его семейство.
type NewAuthorizationCode struct {
	Context             domain.CeremonyContext
	CodeDigest          string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	// TTL — срок жизни кода. Приходит ВХОДОМ, а не константой этого файла: у
	// величины нет владельца в слое доступа, и копия разошлась бы с политикой.
	TTL time.Duration
}

// CodeExchange — предъявление кода к обмену вместе со свёрткой обновляющего
// токена, который встанет в семейство ПЕРВЫМ поколением.
//
// Свёртка преемника приходит ВХОДОМ, а не чеканится здесь: сам токен уходит
// вызывающему, и слой доступа его не видит — он видит только свёртку.
type CodeExchange struct {
	CodeDigest         string
	RefreshTokenDigest string
	RefreshTokenTTL    time.Duration
}

// RefreshRotation — предъявление обновляющего токена к ротации.
type RefreshRotation struct {
	PresentedDigest string
	SuccessorDigest string
	TTL             time.Duration
}

// ── Порядок замков заведения ────────────────────────────────────────────────
//
// # ОДИН ПОРЯДОК НА ВСЕХ, И ОН — ПОРЯДОК КАСКАДА
//
// Удаления ходят по внешним ключам СВЕРХУ ВНИЗ: человек → сессия → семейство →
// дети; клиент → семейство → дети. Значит и заведение обязано брать те же
// строки сверху вниз, иначе встречные порядки дают цикл.
//
// Уровень здесь ЗАКРЫТ, а не продлён на один этаж: вершин у каскада ровно две —
// `users` и `interactive_clients`. Выше человека стоит аккаунт, но оба ребра
// туда — `users_account_fk` и `accounts_owner_fk` — объявлены `ON DELETE
// RESTRICT` (измерено в `0001_initial.sql`), то есть удаление аккаунта вниз НЕ
// каскадирует и в этот порядок не входит. У `interactive_clients` родителей нет
// вовсе.
//
// Четвёртое ребро в этот порядок ВХОДИТ, но вершин не добавляет:
// `users_invited_by_fk` — человек ссылается на человека (`invited_by`), и
// снятие пригласившего ПИШЕТ строку приглашённого. Безвреден он по трём
// измеренным причинам, и ни одна из них не «кажется»:
//
//   - объявлен `ON DELETE SET NULL`, а не каскадом: до таблицы семейств ребро
//     не доходит вовсе, поэтому новой вершины в порядок не приносит;
//   - пишет он `invited_by`, а тот не входит ни в один уникальный индекс —
//     значит это НЕключевое обновление, совместимое с `FOR KEY SHARE`, который
//     выдача держит на строке того же человека. Ждать тут нечему;
//   - объявлен `DEFERRABLE INITIALLY DEFERRED`: запись ложится на ФИКСАЦИИ,
//     когда все упорядоченные замки уже взяты, и перевернуть порядок посреди
//     транзакции не может.
//
// Измерено на сцене «выдача приглашённому × снятие пригласившего»: 6
// столкновений, 0 взаимных блокировок, обе транзакции зафиксированы,
// отложенная запись отработала (`invited_by` стал NULL).
//
// Названо оно здесь не ради полноты ради полноты: перепись, неполная на одно
// ребро, читается как полная — и завтра окажется неполной на решающее, а
// перепроверять её будет некому.
//
// ЗДЕСЬ СТОЯЛ ЗАМОК ОДНОЙ ЛИШЬ СЕССИИ, и он завёл СВОЙ цикл этажом выше:
// сессия бралась первым оператором и держалась до фиксации, а родители ключей —
// только вставкой, то есть позже. Против удаления человека, идущего
// «человек → сессия», это встречный порядок: измерено 9 прогонов из 9 — взаимная
// блокировка, жертвой каждый раз транзакция УДАЛЕНИЯ. Контрольная рука на форме
// без замка сессии: 0 из 3, и исход обратный — удаление проходит.
//
// Отсюда правило, которое нельзя ослабить перестановкой строк: родители внешних
// ключей берутся НЕ ПОЗЖЕ строки сессии.
//
// # ПОЧЕМУ РАЗНАЯ СИЛА
//
// Человек и клиент берутся `FOR KEY SHARE` — ровно тем замком, который взяла бы
// сама вставка по внешнему ключу. Сила не повышена намеренно: цель здесь —
// ВРЕМЯ взятия, а не строгость. `FOR KEY SHARE` конфликтует с удалением строки,
// и этого достаточно.
//
// # ЦЕНА ОЖИДАНИЯ: ЧЕМ ОНА ЕСТЬ И ЧЕМ ОНА НЕ ИЗМЕРЯЕТСЯ
//
// ЗДЕСЬ БЫЛО НАЗВАНО «выход ждёт 658–665 мс», и число мерило НЕ ТО: это была
// длина искусственного сна в сцене замера, а не цена механизма. Действительная
// длительность операторов выдачи — около 1 мс (измерено `clock_timestamp()`
// внутри транзакции, 6 прогонов из 6), столько выход и ждёт в здоровом случае.
//
// Настоящий предмет не в величине, а в том, что У ЭТОЙ ВЫДАЧИ ОГРАНИЧИТЕЛЯ
// ОЖИДАНИЯ НЕТ: своего `lock_timeout` она не ставит, и её ожидание ограничивает
// только потолок одного оператора пула (`statement_timeout` 30 с,
// `corelib/db.NewPool`) — то есть ждущий ждёт СТОЛЬКО, СКОЛЬКО ЖИВЁТ ЧУЖАЯ
// ТРАНЗАКЦИЯ в пределах этого потолка, а не сколько отведено. Свой предел в
// непроверочном коде дерева ставит одна транзакция — принудительного выхода
// (`HumanSessionRepo.ForceLogoutWriter`, kaname#340), локально себе.
//
// И ждущих на строке сессии — писатели, берущие её замком, несовместимым с
// `FOR SHARE`: свой выход (`EndSession`), снятие прочих записей
// (`endSessionsOfSQL`; вызывающие — перепись у `lockPersonForSessionSetSQL`) и
// перепредъявление (`RotateBearer`, `Present`); к ним эта выдача добавляется
// участником. Уборка (`SweepUnservableSessions`) занятую строку не ждёт, а
// пропускает (kaname#340). Бюджет ожидания здесь не
// назначается: он предмет отдельного ревью распределённых свойств, и решать его
// перестановкой этих строк нельзя.
//
// Замок человека (`lockUserForKeySQL`) берёт и транзакция принудительного
// выхода — первым оператором, до строк сессии, по тому же правилу порядка.
//
// Сессия берётся `FOR SHARE`, и это измерено, а не выбрано: `ended_at` не входит
// ни в один уникальный индекс (у таблицы их два — `human_sessions_pkey` и
// `human_sessions_bearer_digest_uniq`), поэтому снятие сессии берёт
// `FOR NO KEY UPDATE`. С ним `FOR KEY SHARE` СОВМЕСТИМ — его совместимость и
// открывала гонку, — а `FOR SHARE` конфликтует и держит снятие (измерено: все
// 2002 мс до `lock_timeout`). `FOR UPDATE` держал бы тоже, но развёл бы заодно
// две одновременные выдачи в одной сессии, которым расходиться незачем.
const (
	lockUserForKeySQL = `
SELECT 1 FROM kaname.users WHERE id = $1 FOR KEY SHARE`

	lockCeremonyClientSQL = `
SELECT 1 FROM kaname.interactive_clients WHERE client_id = $1 FOR KEY SHARE`

	lockSessionOfCeremonySQL = `
SELECT 1 FROM kaname.human_sessions WHERE id = $1 FOR SHARE`
)

// insertFamilyOnLiveSessionSQL — заведение семейства С УСЛОВИЕМ НА ЖИВОСТЬ
// сессии, выраженным В ТОМ ЖЕ операторе, что запись, и с РАЗЛИЧЕНИЕМ трёх
// исходов по двум числам.
//
// # ЗАМОК И УСЛОВИЕ — НЕ АЛЬТЕРНАТИВЫ, А СЛОИ: ОНИ ЗАКРЫВАЮТ РАЗНЫЕ ЧЕРЕДОВАНИЯ
//
// ЗДЕСЬ СТОЯЛО, что условия достаточно и замок лишний. Это опровергнуто
// замером, по руке на каждую половину:
//
//   - ТОЛЬКО УСЛОВИЕ, снятие сессии ещё НЕ зафиксировано: 6 прогонов из 6 —
//     семейство заведено и ЖИВО при снятой сессии. Снимок чужой
//     незафиксированной записи не видит, и никакое условие её увидеть не может;
//     ждать — единственный способ, а ждать заставляет замок;
//   - ТОЛЬКО ЗАМОК, снятие уже зафиксировано: 6 прогонов из 6 — семейство
//     заведено в снятую сессию. Ждать тут нечего, замок берётся свободно, и
//     отвергнуть строку может только условие.
//
// Полная форма в обеих сценах — 6 из 6 чисто. Половины закрывают РАЗНЫЕ
// чередования, и ни одна не лишняя.
//
// # ПОЧЕМУ УСЛОВИЕ ШИРЕ ОТМЕТКИ СНЯТИЯ
//
// Истечение сессии ключом невыразимо В ПРИНЦИПЕ, и это свойство движка, а не
// нехватка усилия: производная колонка `GENERATED ALWAYS AS (expires_at >
// now()) STORED` отвергается — «generation expression is not immutable».
// Обход через обёртку, объявленную `IMMUTABLE`, движок принимает, но колонка
// ЗАМЕРЗАЕТ НА ВСТАВКЕ: измерено — строка со сроком в две секунды через три
// секунды говорит о себе `live = t`, тогда как `expires_at > now()` даёт `f`.
// Такой признак в ключе был бы хуже отсутствия — он утверждал бы «жива» об
// истёкшей строке.
//
// Поэтому признак снятия в ключ ложится, а истечение — никогда, и отсекается
// оно ровно здесь. Ban #10 не нарушен: условие и запись исполняет ОДИН оператор
// под строчным замком, ноль затронутых строк — отказ.
//
// # ТРИ ИСХОДА, А НЕ ДВА
//
// Возвращаются ДВА числа: сколько строк сессии нашлось и сколько семейств
// вставлено. Ноль первых — сессии НЕТ (прежняя форма давала здесь отказ с
// именем внешнего ключа, и терять это различение нельзя); ноль вторых при
// единице первых — сессия есть, но не жива.
const insertFamilyOnLiveSessionSQL = `
WITH s AS (
    SELECT ended_at, expires_at FROM kaname.human_sessions WHERE id = $4
), ins AS (
    INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
    SELECT $1, $2, $3, $4, $5 FROM s
     WHERE s.ended_at IS NULL AND s.expires_at > now()
    RETURNING 1
)
SELECT (SELECT count(*) FROM s)::int, (SELECT count(*) FROM ins)::int`

// IssueAuthorizationCode заводит семейство и его код ОДНОЙ транзакцией.
//
// Одной, а не двумя: семейство без кода — сирота, которую не обменяет никто и
// не уберёт ничто, а код без семейства схема попросту отвергает составным
// ключом. Промежуточного состояния, наблюдаемого читателем, здесь не бывает.
func (r *OAuthCeremonyRepo) IssueAuthorizationCode(ctx context.Context, in NewAuthorizationCode) error {
	if err := in.Context.Validate(); err != nil {
		return err
	}
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", in.CodeDigest); err != nil {
		return err
	}
	if err := domain.ValidatePKCEChallenge(in.CodeChallenge, in.CodeChallengeMethod); err != nil {
		return err
	}
	if in.RedirectURI == "" {
		return fmt.Errorf("Illegal argument authorization_code.redirect_uri: required")
	}
	if in.TTL <= 0 {
		return fmt.Errorf("Illegal argument authorization_code.ttl: must be positive")
	}

	tx, err := r.beginWriter(ctx)
	if err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// ЗАМКИ — СВЕРХУ ВНИЗ ПО КАСКАДУ, и порядок этих трёх операторов НЕСУЩИЙ:
	// родители внешних ключей берутся НЕ ПОЗЖЕ строки сессии, иначе выдача идёт
	// навстречу удалению человека и даёт с ним цикл (см. раздел выше).
	// Переставить их местами нельзя.
	if _, err = tx.Exec(ctx, lockUserForKeySQL, in.Context.UserID); err != nil {
		return wrapPgErr(err, "User", in.Context.UserID)
	}
	if _, err = tx.Exec(ctx, lockCeremonyClientSQL, in.Context.ClientID); err != nil {
		return wrapPgErr(err, "InteractiveClient", in.Context.ClientID)
	}
	if _, err = tx.Exec(ctx, lockSessionOfCeremonySQL, in.Context.SessionID); err != nil {
		return wrapPgErr(err, "HumanSession", in.Context.SessionID)
	}

	var sessionRows, inserted int
	if err = tx.QueryRow(ctx, insertFamilyOnLiveSessionSQL,
		in.Context.FamilyID, in.Context.ClientID, in.Context.UserID,
		in.Context.SessionID, in.Context.Scope).Scan(&sessionRows, &inserted); err != nil {
		return wrapPgErr(err, "TokenFamily", in.Context.FamilyID)
	}
	switch {
	case sessionRows == 0:
		// Сессии НЕТ. Отдельный исход, а не «не жива»: прежняя форма отвергала
		// это внешним ключом, называя его имя, и слить два разных факта в один
		// отказ значило бы потерять различение, которое уже было.
		return fmt.Errorf("%w: session %s", domain.ErrCeremonySessionUnknown, in.Context.SessionID)
	case inserted == 0:
		// Сессия ЕСТЬ, но не жива. Снятую и истёкшую предъявителю различать
		// незачем: обе означают «входа, в котором идёт церемония, больше нет».
		return fmt.Errorf("%w: session %s", domain.ErrCeremonySessionNotLive, in.Context.SessionID)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.authorization_codes
		       (code_digest, family_id, client_id, user_id, session_id, scope, redirect_uri,
		        code_challenge, code_challenge_method, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $10))`,
		in.CodeDigest, in.Context.FamilyID, in.Context.ClientID, in.Context.UserID,
		in.Context.SessionID, in.Context.Scope, in.RedirectURI,
		in.CodeChallenge, in.CodeChallengeMethod, in.TTL.Seconds()); err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	return nil
}

// lockFamilyOfCodeSQL — ЗАМОК, А НЕ ПРОВЕРКА. Оператор не читает состояния и ни
// на что не влияет своим результатом: ноль строк — законный исход, разбираемый
// ниже по нулю строк самого обмена.
//
// # ЗАЧЕМ ОН СТОИТ ЗДЕСЬ И ПОЧЕМУ ЕГО НЕЛЬЗЯ СНЕСТИ
//
// Отзыв семейства ходит от РОДИТЕЛЯ К ДЕТЯМ: он берёт ключевой замок на строке
// семейства, а `ON UPDATE CASCADE` затем идёт за замками всех его детей. Обмен
// без этого оператора шёл НАВСТРЕЧУ — условный `UPDATE` брал замок на РЕБЁНКЕ,
// и лишь вставка преемника бралась за семейство. Два встречных порядка дают
// цикл, и движок снимал одного из двоих.
//
// Снимал он ОТЗЫВ: 6 прогонов из 6 на postgres:16-alpine жертвой становилась
// транзакция отзыва — семейство оставалось живым, токен активным. Проигрывал не
// запрос арендатора, а контроль безопасности, у которого повтора нет: повторить
// обязан клиент, а похититель не повторяет.
//
// Поэтому замок на семействе берётся ПЕРВЫМ, и оба порядка становятся
// «родитель → ребёнок». Повтор лечил бы симптом и оставлял бы контроль
// зависимым от поведения клиента.
//
// # ЭТО НЕ НАРУШАЕТ ban #10
//
// Условие сравнения-и-записи осталось ЦЕЛИКОМ в `UPDATE` ниже: здесь не
// читается ни `active`, ни срок, ни живость семейства, и ни одно решение по
// результату этого оператора не принимается. Пары «проверил, затем записал» тут
// нет — есть упорядочивание замков, которое движок иначе выстроить не может.
const lockFamilyOfCodeSQL = `
SELECT 1 FROM kaname.token_families
 WHERE id = (SELECT family_id FROM kaname.authorization_codes WHERE code_digest = $1)
   FOR KEY SHARE`

// exchangeCodeSQL — ТОТ САМЫЙ оператор: условие на прежнее состояние и возврат
// затронутой строки. Стоит ОДНОЙ константой: второе написание разошлось бы с
// первым молча, а разойтись ему есть куда — условие здесь и есть инвариант.
//
// Пишется ОТМЕТКА снятия, а не признак: `active` — производная колонка, и запись
// в неё база отвергает (428C9). Отдельного условия «семейство не отозвано» здесь
// тоже НЕТ и быть не должно: живость семейства входит в саму производную, и
// второе её написание разошлось бы с первым молча.
const exchangeCodeSQL = `
UPDATE kaname.authorization_codes AS c
   SET deactivated_at = now(), deactivated_reason = 'redeemed'
 WHERE c.code_digest = $1
   AND c.active
   AND c.expires_at > now()
RETURNING c.family_id, c.client_id, c.user_id, c.session_id, c.scope,
          c.redirect_uri, c.code_challenge, c.code_challenge_method`

// ceremonyWriterTx — УРОВЕНЬ ИЗОЛЯЦИИ, на котором исполняется потребление кода
// (`exchangeCodeSQL` выше) и КАЖДЫЙ другой писатель этого порта (kaname#316).
//
// Он НАЗВАН здесь, а не унаследован. Умолчание сессии задаёт не этот файл —
// конфигурация сервера, `ALTER DATABASE … SET`, `ALTER ROLE … SET`, параметр
// подключения, — и писатель, чей исход от умолчания зависит, менял бы поведение
// по чужой настройке, ничем этого не показав.
//
// # ПОЧЕМУ READ COMMITTED
//
// Одноинструкционный обмен держит строчный замок, и проигравший, СТОЯВШИЙ на
// строке победителя, после фиксации победителя перепроверяет условие `WHERE` по
// НОВОЙ версии строки: код уже неактивен — затронуто ноль строк. Ноль строк
// разбирает `refuseCode`, перечитывая помеченную строку, и исход проигравшего —
// ПОВТОР (LINE-A-1-13, LINE-A-1-17). Перепроверку по новой версии делает ТОЛЬКО
// этот уровень: при REPEATABLE READ и SERIALIZABLE движок ту же строку не
// перепроверяет, а отказывает транзакции целиком (40001), и разбору нуля строк
// вход не достаётся вовсе.
//
// Устройство то же у остальных писателей порта, и потому решение одно на всех:
// ротация, отзыв семейства (второй отзыв — пустой, а не отказ), выдача против
// снятия сессии, согласие и его отзыв, проверочное значение клиента. Исход
// каждого под конкуренцией — перепроверка условия, а не отказ сериализации.
//
// # ВЕТВИ «40001 → ПОВТОР» НЕТ, И ЭТО РЕШЕНИЕ, А НЕ УПУЩЕНИЕ
//
// На названном уровне эти операторы отказа сериализации не дают. 40001 (как и
// 40P01) разбирает общий `wrapPgErr` — «повторите запрос», — и ни в какой исход
// церемонии он не отображается: на этом уровне такая ветвь не получала бы входа,
// а на ином подменяла бы разбор строки догадкой о том, что случилось.
//
// Держит решение `oauth_ceremony_isolation_integration_test.go`: каждый писатель
// исполняется под умолчанием продукта и под `serializable`, и ожидание на строке
// там доказывается состоянием движка, а не паузой.
var ceremonyWriterTx = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}

// beginWriter — ЕДИНСТВЕННОЕ открытие транзакции писателя в этом порту.
func (r *OAuthCeremonyRepo) beginWriter(ctx context.Context) (pgx.Tx, error) {
	return r.pool.BeginTx(ctx, ceremonyWriterTx)
}

// execWriter — одиночный оператор писателя на названном уровне.
//
// Оператор, исполненный пулом без транзакции, шёл бы на умолчании сессии — то
// есть уровень снова был бы унаследован. Цена названного — начало и фиксация
// лишними репликами; пути, которые ею платят (согласие, проверочное значение
// клиента), горячими не являются.
func (r *OAuthCeremonyRepo) execWriter(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx, err := r.beginWriter(ctx)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return pgconn.CommandTag{}, err
	}
	return tag, nil
}

// ExchangeAuthorizationCode обменивает код на первое поколение обновляющего
// токена семейства.
//
// Транзакция — на названном уровне (`ceremonyWriterTx`): исход проигравшего
// одновременного обмена решает именно он.
//
// Гашение и выдача идут ОДНОЙ транзакцией: ноль затронутых строк означает
// откат ВСЕЙ транзакции выдачи — токена в семействе не появляется. Разбор
// причины идёт ПОСЛЕ отката, по пулу: откаченная транзакция читать уже не
// вправе, а держать её открытой ради разбора значило бы держать замок на время
// разбора.
func (r *OAuthCeremonyRepo) ExchangeAuthorizationCode(ctx context.Context, in CodeExchange) (domain.RedeemedCode, error) {
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", in.CodeDigest); err != nil {
		return domain.RedeemedCode{}, err
	}
	if err := domain.ValidateCeremonyDigest("refresh_token.token_digest", in.RefreshTokenDigest); err != nil {
		return domain.RedeemedCode{}, err
	}
	if in.RefreshTokenTTL <= 0 {
		return domain.RedeemedCode{}, fmt.Errorf("Illegal argument refresh_token.ttl: must be positive")
	}

	tx, err := r.beginWriter(ctx)
	if err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// ЗАМОК СЕМЕЙСТВА — ПЕРВЫМ. Порядок замков, а не проверка: см.
	// `lockFamilyOfCodeSQL`. Ноль строк здесь законен и ничего не решает.
	if _, err = tx.Exec(ctx, lockFamilyOfCodeSQL, in.CodeDigest); err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "TokenFamily", "")
	}

	var out domain.RedeemedCode
	err = tx.QueryRow(ctx, exchangeCodeSQL, in.CodeDigest).Scan(
		&out.Context.FamilyID, &out.Context.ClientID, &out.Context.UserID,
		&out.Context.SessionID, &out.Context.Scope,
		&out.RedirectURI, &out.CodeChallenge, &out.CodeChallengeMethod)
	if stderrors.Is(err, pgx.ErrNoRows) {
		// Транзакция выдачи откачена ЗДЕСЬ, до разбора: разбор идёт по пулу.
		_ = tx.Rollback(ctx)
		return domain.RedeemedCode{}, r.refuseCode(ctx, in.CodeDigest)
	}
	if err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", "")
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,0, now() + make_interval(secs => $7))`,
		in.RefreshTokenDigest, out.Context.FamilyID, out.Context.ClientID, out.Context.UserID,
		out.Context.SessionID, out.Context.Scope, in.RefreshTokenTTL.Seconds()); err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", out.Context.FamilyID)
	}
	return out, nil
}

// refuseCode называет ПРИЧИНУ, по которой условие обмена не выполнилось, и —
// если это ПОВТОР — отзывает всё семейство.
//
// Корзины «прочее» у разбора нет, и исходов РОВНО ТРИ: строка либо
// отсутствует, либо неактивна, либо истекла. Четвёртого на сегодняшней схеме не
// существует, и появление его означало бы, что условие обмена и этот разбор
// разошлись — поэтому он отдельный ГРОМКИЙ отказ, а не тихое «повтор».
//
// ОТОЗВАННОЕ СЕМЕЙСТВО ОТДЕЛЬНОЙ ВЕТВЬЮ НЕ СТОИТ, И ЭТО НЕ УПУЩЕНИЕ: признак
// активности строки ПРОИЗВОДЕН от живости семейства, поэтому отозванное
// семейство наблюдается здесь как `!active` и разбирается первой же ветвью.
// Ветвь, стоявшая ниже неё, не получала управления ни при каком входе — а
// закрытый `switch` с ветвью, которой не достаётся вход, читается следующим как
// живая. Семейство больше не опрашивается вовсе: соединение с ним отвечало на
// вопрос, ответ на который теперь несёт сама строка.
func (r *OAuthCeremonyRepo) refuseCode(ctx context.Context, digest string) error {
	var (
		active   bool
		expired  bool
		familyID string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT c.active, c.expires_at <= now(), c.family_id
		  FROM kaname.authorization_codes c
		 WHERE c.code_digest = $1`, digest).Scan(&active, &expired, &familyID)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: digest not found", domain.ErrAuthorizationCodeUnknown)
	}
	if err != nil {
		return wrapPgErr(err, "AuthorizationCode", "")
	}
	switch {
	case !active:
		// ПОВТОР. Отзыв семейства — следствие, неотделимое от решения: вернуть
		// «повтор», не отозвав, значило бы объявить похищение и ничего по нему
		// не сделать.
		if rErr := r.RevokeFamily(ctx, familyID, domain.FamilyRevokedByCodeReplay); rErr != nil {
			return fmt.Errorf("authorization code replay on family %s: revoking the family: %w", familyID, rErr)
		}
		return fmt.Errorf("%w: family %s revoked", domain.ErrAuthorizationCodeReplayed, familyID)
	case expired:
		return fmt.Errorf("%w: family %s", domain.ErrAuthorizationCodeExpired, familyID)
	default:
		return fmt.Errorf("authorization code %s: exchange affected no row while the row is live "+
			"and unexpired — the exchange condition and this adjudication have diverged", familyID)
	}
}

// lockFamilyOfRefreshSQL — ЗАМОК, А НЕ ПРОВЕРКА, и по той же причине, что
// `lockFamilyOfCodeSQL`: ротация обязана брать семейство ПЕРВОЙ, иначе её
// порядок замков встречен порядку отзыва и жертвой цикла становится отзыв.
const lockFamilyOfRefreshSQL = `
SELECT 1 FROM kaname.token_families
 WHERE id = (SELECT family_id FROM kaname.refresh_tokens WHERE token_digest = $1)
   FOR KEY SHARE`

// rotateRefreshSQL — ТОТ ЖЕ механизм, что у обмена кода: условие на прежнее
// состояние и возврат затронутой строки.
const rotateRefreshSQL = `
UPDATE kaname.refresh_tokens AS t
   SET deactivated_at = now(), deactivated_reason = 'rotated',
       successor_digest = $2
 WHERE t.token_digest = $1
   AND t.active
   AND t.expires_at > now()
RETURNING t.family_id, t.client_id, t.user_id, t.session_id, t.scope, t.generation`

// RotateRefreshToken ротирует обновляющий токен: предъявленный помечается
// отротированным, преемник встаёт следующим поколением — ОДНОЙ транзакцией.
func (r *OAuthCeremonyRepo) RotateRefreshToken(ctx context.Context, in RefreshRotation) (domain.RotatedRefreshToken, error) {
	if err := domain.ValidateCeremonyDigest("refresh_token.token_digest", in.PresentedDigest); err != nil {
		return domain.RotatedRefreshToken{}, err
	}
	if err := domain.ValidateCeremonyDigest("refresh_token.successor_digest", in.SuccessorDigest); err != nil {
		return domain.RotatedRefreshToken{}, err
	}
	if in.PresentedDigest == in.SuccessorDigest {
		return domain.RotatedRefreshToken{}, fmt.Errorf(
			"Illegal argument refresh_token.successor_digest: must differ from the presented one")
	}
	if in.TTL <= 0 {
		return domain.RotatedRefreshToken{}, fmt.Errorf("Illegal argument refresh_token.ttl: must be positive")
	}

	tx, err := r.beginWriter(ctx)
	if err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// ЗАМОК СЕМЕЙСТВА — ПЕРВЫМ, по той же причине, что у обмена.
	if _, err = tx.Exec(ctx, lockFamilyOfRefreshSQL, in.PresentedDigest); err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "TokenFamily", "")
	}

	var out domain.RotatedRefreshToken
	err = tx.QueryRow(ctx, rotateRefreshSQL, in.PresentedDigest, in.SuccessorDigest).Scan(
		&out.Context.FamilyID, &out.Context.ClientID, &out.Context.UserID,
		&out.Context.SessionID, &out.Context.Scope, &out.Generation)
	if stderrors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		return domain.RotatedRefreshToken{}, r.refuseRefresh(ctx, in.PresentedDigest)
	}
	if err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", "")
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(secs => $8))`,
		in.SuccessorDigest, out.Context.FamilyID, out.Context.ClientID, out.Context.UserID,
		out.Context.SessionID, out.Context.Scope, out.Generation+1, in.TTL.Seconds()); err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	out.Generation++
	return out, nil
}

// refuseRefresh — разбор нуля затронутых строк ротации, тот же по устройству,
// что и у обмена кода: исходов РОВНО ТРИ, и отозванное семейство приходит сюда
// как `!active` — признак производен от его живости.
func (r *OAuthCeremonyRepo) refuseRefresh(ctx context.Context, digest string) error {
	var (
		active   bool
		expired  bool
		familyID string
	)
	err := r.pool.QueryRow(ctx, `
		SELECT t.active, t.expires_at <= now(), t.family_id
		  FROM kaname.refresh_tokens t
		 WHERE t.token_digest = $1`, digest).Scan(&active, &expired, &familyID)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: digest not found", domain.ErrRefreshTokenUnknown)
	}
	if err != nil {
		return wrapPgErr(err, "RefreshToken", "")
	}
	switch {
	case !active:
		if rErr := r.RevokeFamily(ctx, familyID, domain.FamilyRevokedByRefreshReplay); rErr != nil {
			return fmt.Errorf("refresh token replay on family %s: revoking the family: %w", familyID, rErr)
		}
		return fmt.Errorf("%w: family %s revoked", domain.ErrRefreshTokenReplayed, familyID)
	case expired:
		return fmt.Errorf("%w: family %s", domain.ErrRefreshTokenExpired, familyID)
	default:
		return fmt.Errorf("refresh token of family %s: rotation affected no row while the row is "+
			"live and unexpired — the rotation condition and this adjudication have diverged", familyID)
	}
}

// RevokeFamily отзывает семейство целиком ОДНОЙ транзакцией: отметка на
// семействе и снятие всего живого, что по нему выдано.
//
// Отзыв ИДЕМПОТЕНТЕН: условие `revoked_at IS NULL` делает повторный отзыв
// пустым, а не вторым — на названном уровне (`ceremonyWriterTx`), где второй,
// стоявший на строке первого, перепроверяет условие, а не получает отказ. Два одновременных обнаружения повтора — обычное дело
// (проигравших гонку больше одного), и второй из них не вправе ни отказать, ни
// переписать причину первого.
func (r *OAuthCeremonyRepo) RevokeFamily(ctx context.Context, familyID string, reason domain.FamilyRevocationReason) error {
	if familyID == "" {
		return fmt.Errorf("Illegal argument token_family.id: required")
	}
	if err := reason.Validate(); err != nil {
		return err
	}
	tx, err := r.beginWriter(ctx)
	if err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// `live` идёт В ТОМ ЖЕ операторе, что отметка: пара держится ограничением
	// `token_families_live_pair_ck`, и оператор, тронувший одну половину, второй
	// попытки не получает. Именно эта колонка делает отзыв обновлением КЛЮЧА.
	if _, err = tx.Exec(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = $2, live = false
		 WHERE id = $1 AND revoked_at IS NULL`, familyID, string(reason)); err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	// ВЫДАННОЕ СНЯЛ КАСКАД, И БОЛЬШЕ ЗДЕСЬ ДЕЛАТЬ НЕЧЕГО.
	//
	// ЗДЕСЬ СТОЯЛИ два оператора, дописывавших детям причину `'family-revoked'`.
	// Их больше нет, и это не упущение: основание смерти ребёнка ПРИНАДЛЕЖИТ
	// СЕМЕЙСТВУ (`token_families.revoked_reason`), а копия на ребёнке была
	// вторым написанием одного факта. Читается основание соединением.
	//
	// Снятое вместе с ними: одно место двойной записи и ДВА оператора из
	// транзакции отзыва, которая идёт под ключевым замком семейства и стоила
	// O(поколений) — на 20 000 детей это 241 мс дописывания поверх 698 мс
	// каскада.
	//
	// Что ребёнок мёртв — говорит `active`, производный от `family_live`,
	// который снёс каскад. Своя отметка `deactivated_at` осталась означать
	// СОБСТВЕННОЕ событие строки: погашение либо ротацию.
	if err = tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	return nil
}

// revokeFamiliesOfSessionsTx отзывает семейства, привязанные к НАЗВАННЫМ
// сессиям, — в транзакции вызывающего.
//
// # ПОЧЕМУ ЭТОТ ПИСАТЕЛЬ ОБЯЗАН СУЩЕСТВОВАТЬ
//
// Привязка семейства к сессии есть внешний ключ с каскадом НА УДАЛЕНИИ строки.
// Снятие сессии строку не удаляет — оно ставит отметку, а удаляет строку уборка
// спустя порог удержания. Значит без этого писателя обновляющий токен снятой
// сессии живёт и ротируется в свежие, а окно равно величине УДЕРЖАНИЯ, то есть
// настройке хранения, а не решению о безопасности.
//
// Словарь причин отзыва объявлен ЗАКРЫТЫМ, и до этой полосы у четырёх его
// значений не было ни одного писателя. Объявленная возможность, которой никто
// не исполняет, — долг, а не будущее: она читается как работающая и не
// работает ни при каком входе.
//
// # ВЫБОР И ПОМЕТКА — ОДИН ОПЕРАТОР
//
// ЗДЕСЬ СТОЯЛО, что порядок операторов несущий и семейства обязаны выбираться
// ПЕРВЫМИ, а пометка идти следом. Предмет у этого объяснения был — отдельная
// выборка, — и предмета больше нет: выбор и пометка исполняются ОДНИМ
// `UPDATE … RETURNING`. Вопроса «что раньше» он не задаёт.
//
// Разведёнными они были не только многословны, но и НЕВЕРНЫ в переписи: два
// одновременных снятия сессий одного человека выбирали бы одни и те же живые
// семейства и оба возвращали бы их числом, хотя отозвал каждое ровно один.
// `RETURNING` отдаёт строку ТОМУ, чей оператор её изменил, и число, которое
// уходит вызывающему, считает сделанное этим вызовом, а не увиденное им.
//
// # ИДЕМПОТЕНТНОСТЬ — УСЛОВИЕМ, А НЕ ПРОВЕРКОЙ
//
// Уже снятую отметку и её причину повтор не переписывает: условие `revoked_at
// IS NULL` стоит в том же операторе и делает второй отзыв пустым, а не вторым.
func revokeFamiliesOfSessionsTx(ctx context.Context, tx pgx.Tx,
	sessionIDs []string, reason domain.FamilyRevocationReason,
) (int, error) {
	if len(sessionIDs) == 0 {
		return 0, nil
	}
	if err := reason.Validate(); err != nil {
		return 0, err
	}
	// КУРСОР ЗАКРЫВАЕТСЯ РУКАМИ, А НЕ `defer`, И ЭТО НЕ НЕБРЕЖНОСТЬ: следом на
	// ТОЙ ЖЕ транзакции исполняются ещё операторы, а pgx не допускает работы с
	// соединением, пока курсор открыт. Отложенное закрытие сработало бы ПОСЛЕ
	// них — то есть слишком поздно.
	//
	// `live = false` идёт тем же оператором, что отметка: пара держится
	// ограничением `token_families_live_pair_ck`, и она же делает отзыв
	// обновлением КЛЮЧА, конфликтующим со вставкой ребёнка.
	rows, err := tx.Query(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = $2, live = false
		 WHERE session_id = ANY($1) AND revoked_at IS NULL
		RETURNING id`, sessionIDs, string(reason))
	if err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	var families []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, wrapPgErr(err, "TokenFamily", "")
		}
		families = append(families, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	if len(families) == 0 {
		return 0, nil
	}

	// Выданное снял КАСКАД: здесь, как и в `RevokeFamily`, дописывающих
	// операторов больше нет — основание принадлежит семейству, а не копии на
	// ребёнке.
	return len(families), nil
}

// ── Согласие ────────────────────────────────────────────────────────────────

// GrantConsent записывает согласие человека клиенту на перечисленные области.
//
// ИДЕМПОТЕНТНО и ОДНИМ оператором на весь перечень: уникальность тройки держит
// `consent_grants_subject_client_scope_uk`, и конфликт по ней — не отказ, а
// «согласие уже стоит»: отметка отзыва снимается, момент согласия обновляется
// на ТОЙ ЖЕ строке. Пара «посмотреть, есть ли согласие — записать» дала бы под
// гонкой две строки на одну тройку, после чего отзыв снимал бы ОДНУ из них.
func (r *OAuthCeremonyRepo) GrantConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if userID == "" {
		return fmt.Errorf("Illegal argument consent_grant.user_id: required")
	}
	if clientID == "" {
		return fmt.Errorf("Illegal argument consent_grant.client_id: required")
	}
	if len(scopes) == 0 {
		return fmt.Errorf("Illegal argument consent_grant.scope: required")
	}
	// Повтор области в перечне — ОДНА область, а не две: `ON CONFLICT DO UPDATE`
	// не вправе задеть одну и ту же строку дважды в одном операторе и ответил бы
	// отказом хранилища на то, что отказом не является. Свёртка повторов идёт
	// здесь, ДО оператора, а не разбором его отказа.
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]bool, len(scopes))
	for i, s := range scopes {
		if s == "" {
			return fmt.Errorf("Illegal argument consent_grant.scope[%d]: must not be empty", i)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		unique = append(unique, s)
	}
	rowIDs := make([]string, 0, len(unique))
	for range unique {
		rowIDs = append(rowIDs, ids.NewHyphenID(consentIDPrefix))
	}
	// Идентификаторы чеканятся на КАЖДУЮ область, но лягут только те, чья
	// строка заводится впервые: конфликтующая строка сохраняет свой.
	if _, err := r.execWriter(ctx, `
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		SELECT s.id, $2, $3, s.scope
		  FROM unnest($1::text[], $4::text[]) AS s(id, scope)
		ON CONFLICT (user_id, client_id, scope)
		DO UPDATE SET revoked_at = NULL, granted_at = now()`,
		rowIDs, userID, clientID, unique); err != nil {
		return wrapPgErr(err, "ConsentGrant", userID)
	}
	return nil
}

// WithdrawConsent отзывает согласие на одну область: ОТМЕТКА на той же строке.
//
// Строка остаётся: «согласия не было» и «согласие отозвано» — разные ответы, и
// удалённая строка их не различает.
func (r *OAuthCeremonyRepo) WithdrawConsent(ctx context.Context, userID, clientID, scope string) error {
	if userID == "" || clientID == "" || scope == "" {
		return fmt.Errorf("Illegal argument consent_grant: user_id, client_id and scope are required")
	}
	tag, err := r.execWriter(ctx, `
		UPDATE kaname.consent_grants
		   SET revoked_at = now()
		 WHERE user_id = $1 AND client_id = $2 AND scope = $3 AND revoked_at IS NULL`,
		userID, clientID, scope)
	if err != nil {
		return wrapPgErr(err, "ConsentGrant", userID)
	}
	if tag.RowsAffected() == 0 {
		// Отзывать нечего — и это НЕ отказ: согласия либо не было, либо оно уже
		// отозвано, и в обоих случаях состояние ровно то, которого просили.
		return nil
	}
	return nil
}

// ConsentedScopes — области, на которые согласие ДЕЙСТВУЕТ, в устойчивом
// порядке. Отозванные не попадают: отметка отзыва и есть предикат.
func (r *OAuthCeremonyRepo) ConsentedScopes(ctx context.Context, userID, clientID string) ([]string, error) {
	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("Illegal argument consent_grant: user_id and client_id are required")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT scope FROM kaname.consent_grants
		 WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
		 ORDER BY scope`, userID, clientID)
	if err != nil {
		return nil, wrapPgErr(err, "ConsentGrant", userID)
	}
	defer rows.Close()
	out := make([]string, 0, 8)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, wrapPgErr(err, "ConsentGrant", userID)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr(err, "ConsentGrant", userID)
	}
	return out, nil
}

// ── Проверочное значение секрета интерактивного клиента ─────────────────────

// SetClientSecretVerifier кладёт проверочное значение секрета клиента.
//
// Материал уходит в базу АРГУМЕНТОМ оператора и в этом файле больше нигде не
// участвует: разрешение на выход `domain.LoginVerifier.Reveal` дано ЭТОМУ файлу
// с причиной в `internal/check/login_verifier_containment_test.go`.
//
// Снятие значения — отдельный глагол (`ClearClientSecretVerifier`), а не пустой
// вход сюда: «положить пустое» и «снять» читались бы одинаково, и опечатка
// вызывающего молча разоружала бы клиента.
func (r *OAuthCeremonyRepo) SetClientSecretVerifier(ctx context.Context, clientID string, verifier domain.LoginVerifier) error {
	if clientID == "" {
		return fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	if verifier.IsZero() {
		return fmt.Errorf("Illegal argument interactive_client.secret_verifier: required")
	}
	// Транзакция СВОЯ, а не `execWriter`: материал уходит аргументом ровно
	// этого оператора, и разрешение гейта удержания стоит на нём, а не на
	// общем исполнителе, которому материал мог бы прийти откуда угодно.
	tx, err := r.beginWriter(ctx)
	if err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE kaname.interactive_clients
		   SET secret_verifier = $2, secret_verifier_set_at = now()
		 WHERE client_id = $1`, clientID, verifier.Reveal())
	if err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	if tag.RowsAffected() == 0 {
		return refuseNoSuchClient(clientID)
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	return nil
}

// ClearClientSecretVerifier снимает проверочное значение: клиент становится
// публичным, и секрета у него нет.
func (r *OAuthCeremonyRepo) ClearClientSecretVerifier(ctx context.Context, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	tag, err := r.execWriter(ctx, `
		UPDATE kaname.interactive_clients
		   SET secret_verifier = '', secret_verifier_set_at = NULL
		 WHERE client_id = $1`, clientID)
	if err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	if tag.RowsAffected() == 0 {
		return refuseNoSuchClient(clientID)
	}
	return nil
}

// ClientSecretVerifier — проверочное значение клиента и признак «секрет есть».
//
// Признак отдельным значением, а не «пустая строка означает нет»: отсутствие
// представимо отдельно от значения, и вызывающий, забывший его прочесть, не
// уйдёт сверять предъявленный секрет с пустым материалом.
func (r *OAuthCeremonyRepo) ClientSecretVerifier(ctx context.Context, clientID string) (domain.LoginVerifier, bool, error) {
	if clientID == "" {
		return domain.LoginVerifier{}, false, fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	var material string
	err := r.pool.QueryRow(ctx, `
		SELECT secret_verifier FROM kaname.interactive_clients WHERE client_id = $1`,
		clientID).Scan(&material)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.LoginVerifier{}, false, refuseNoSuchClient(clientID)
	}
	if err != nil {
		return domain.LoginVerifier{}, false, wrapPgErr(err, "InteractiveClient", clientID)
	}
	if material == "" {
		return domain.LoginVerifier{}, false, nil
	}
	verifier, vErr := domain.NewLoginVerifier(material)
	if vErr != nil {
		return domain.LoginVerifier{}, false, vErr
	}
	return verifier, true, nil
}
