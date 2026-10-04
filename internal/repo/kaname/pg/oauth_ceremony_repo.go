// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_repo.go — слой доступа СОБСТВЕННОЙ ЦЕРЕМОНИИ OAuth: код
// авторизации, семейство выданного по нему и обновляющий токен (задача
// PRO-Robotech/kaname#313; миграции
// `20260920175117_authorization_code_is_our_record.sql`,
// `20260920175118_interactive_client_carries_its_secret_verifier.sql`).
//
// Обмен кода и оборот токена обновления исполняет движок фундамента над
// хранилищами церемонии (`oauth_ceremony_vaults.go`, kaname#423). Своих
// композиций обмена и оборота у этого файла НЕТ (kaname#434): здесь лежат
// операторы, которые хранилища исполняют, — погашение (`exchangeCodeSQL`),
// оборот (`rotateRefreshSQL`), замки семейства, заведение токена
// (`insertRefreshSQL`), разбор нуля строк, — и писатели без копий у хранилищ:
// выдача кода, отзыв семейства, запись выпуска, проверочное значение клиента.
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
// # «НЕ ОБМЕНЯЛОСЬ» — НЕ ОДИН ИСХОД
//
// Порт фундамента различает исходы предъявления, и различение стоит на строке,
// а не на тексте отказа:
//
//   - строки нет вовсе либо она жива, но срок вышел → «записи нет»
//     (`oauthceremony.ErrGrantNotFound` у выборки хранилищ). Отзыва не влечёт:
//     истечение — не признак похищения;
//   - строка ПОГАШЕНА (обёрнута) → ПОВТОР. Кодом уже воспользовались, второй
//     предъявитель — либо похититель, либо тот, у кого похитили, и различить их
//     нельзя. Поэтому движок отзывает ВСЁ семейство (RFC 6819 §5.2.1.1):
//     выборка отдаёт запись вместе с признаком погашения, а ноль строк
//     решающей записи после живой выборки — одновременный повтор;
//   - сессия строки отрезана отсечкой субъекта → тоже «записи нет», на
//     решающей записи — с причиной `domain.ErrCeremonySubjectCutOff` в цепочке.
//     Это не повтор, и семейство по нему не отзывается.
//
// Ради этого различения использованный код и отротированный токен ПОМЕЧАЮТСЯ
// неактивными и ЖИВУТ до истечения. Удалить строку значило бы сделать повтор
// неотличимым от неизвестного кода — то есть снять отзыв семейства с
// единственного признака, по которому похищение вообще наблюдаемо.
//
// # ЧТО ДЕРЖИТ БАЗА, А НЕ ЭТОТ ФАЙЛ
//
//   - неделимость обмена и ротации — условный `UPDATE … RETURNING` на
//     НАЗВАННОМ уровне изоляции (`ceremonyWriterTx()`, решение записано у
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
//   - ПОРЯДОК ЗАМКОВ «родитель → ребёнок» на обоих путях: погашение кода и оборот
//     токена обновления берут семейство первыми (`lockFamilyOfCodeSQL`,
//     `lockFamilyOfRefreshSQL`), иначе встречный порядок с каскадом отзыва даёт
//     цикл, жертвой которого движок выбирал сам отзыв;
//   - «одно поколение на номер в семействе» — `refresh_tokens_generation_uk`;
//   - форма свёрток, испытания PKCE и словари причин — ограничения схемы.

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/journalwrite"
)

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
	// ACR — уровень аутентификации ГРАНТА: снимок уровня сессии на выдаче кода
	// (колонка `token_families.acr`, миграция `20260925121413`). Приходит от
	// того, кто выдаёт, — у сессии уровень подвижен (шаг вверх), и прочитать его
	// там при обмене значило бы перенести в токен уровень, которого код не нёс.
	ACR string
	// TTL — срок жизни кода. Приходит ВХОДОМ, а не константой этого файла: у
	// величины нет владельца в слое доступа, и копия разошлась бы с политикой.
	TTL time.Duration
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
//
// # ЖИВОСТЬ СЕССИИ ВКЛЮЧАЕТ ОТСЕЧКУ СУБЪЕКТА
//
// Сессия, отрезанная отсечкой своего человека (`sessionCutOffBySubjectSQL`), —
// тоже «не жива», хотя отметки снятия на ней нет: отсечку кладут и писатели,
// сессий не снимающие. Условие стоит в том же операторе, что запись.
const insertFamilyOnLiveSessionSQL = `
WITH s AS (
    SELECT user_id, authenticated_at, ended_at, expires_at FROM kaname.human_sessions WHERE id = $4
), ins AS (
    INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope, acr)
    SELECT $1, $2, $3, $4, $5, $6 FROM s
     WHERE s.ended_at IS NULL AND s.expires_at > now() AND NOT ` + sessionCutOffBySubjectSQL + `
    RETURNING 1
)
SELECT (SELECT count(*) FROM s)::int, (SELECT count(*) FROM ins)::int`

// sessionCutOffBySubjectSQL — сессия `s` отрезана отсечкой своего субъекта:
// аутентифицирована НЕ ПОЗЖЕ `user_token_revocations.revoke_before`. Правило то
// же, что у края на браузерной полосе: действительна сессия, аутентифицированная
// строго ПОЗЖЕ отсечки.
//
// Выдача церемонии читает его на КАЖДОМ своём ходе тем же оператором, что
// живость: заведение семейства, выборка кода и токена обновления к обмену
// (`oauth_ceremony_vaults.go`) и РЕШАЮЩИЕ условные записи — погашение кода
// (`exchangeCodeSQL`), замок оборота (`lockRefreshForRotationSQL`) и сам оборот
// (`rotateRefreshSQL`). Предъявление судит токены по отметке выпуска, и выпуск
// после отсечки из сессии, аутентифицированной до неё, предъявление
// пропустило бы. Чтения одного мало: движок читает строку ДО записи, и
// отсечка, зафиксированная между чтением и записью, чтением не видна — судит
// её запись (возврат ревью схемы сборки 425, N1). Строку отсечки пишет
// `UserTokenRevocationRepo`; этот предикат её только читает, и написан он один
// раз — на алиас сессии `s`.
const sessionCutOffBySubjectSQL = `EXISTS (
    SELECT 1 FROM kaname.user_token_revocations r
     WHERE r.user_id = s.user_id AND r.revoke_before >= s.authenticated_at)`

// codeSessionCutOffSQL, refreshSessionCutOffSQL — тот же предикат на сессии
// предъявленной строки: кода (алиас `c`) и токена обновления (алиас `t`).
// Условная запись и разбор её нуля строк читают ОДИН текст: разойдись они, ноль
// строк от отсечки разбирался бы как «условие и разбор разошлись».
const (
	codeSessionCutOffSQL = `EXISTS (
    SELECT 1 FROM kaname.human_sessions s
     WHERE s.id = c.session_id AND ` + sessionCutOffBySubjectSQL + `)`
	refreshSessionCutOffSQL = `EXISTS (
    SELECT 1 FROM kaname.human_sessions s
     WHERE s.id = t.session_id AND ` + sessionCutOffBySubjectSQL + `)`
)

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
	if err := domain.ValidateCeremonyLevel(in.ACR); err != nil {
		return err
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
		in.Context.SessionID, in.Context.Scope, in.ACR).Scan(&sessionRows, &inserted); err != nil {
		return wrapPgErr(err, "TokenFamily", in.Context.FamilyID)
	}
	switch {
	case sessionRows == 0:
		// Сессии НЕТ. Отдельный исход, а не «не жива»: прежняя форма отвергала
		// это внешним ключом, называя его имя, и слить два разных факта в один
		// отказ значило бы потерять различение, которое уже было.
		return fmt.Errorf("%w: session %s", domain.ErrCeremonySessionUnknown, in.Context.SessionID)
	case inserted == 0:
		// Сессия ЕСТЬ, но не жива. Снятую, истёкшую и отрезанную отсечкой
		// субъекта предъявителю различать незачем: все три означают «входа, в
		// котором идёт церемония, больше нет».
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
// семейства, а `ON UPDATE CASCADE` затем идёт за замками всех его детей.
// Погашение без этого оператора шло НАВСТРЕЧУ — условный `UPDATE` брал замок на
// РЕБЁНКЕ, и лишь вставка первого поколения бралась за семейство. Два встречных порядка дают
// цикл, и движок снимал одного из двоих.
//
// Снимал он ОТЗЫВ: 6 прогонов из 6 на postgres:16-alpine жертвой становилась
// транзакция отзыва — семейство оставалось живым, токен активным. Проигрывал не
// запрос арендатора, а контроль безопасности, у которого повтора нет: повторить
// обязан клиент, а похититель не повторяет.
//
// Поэтому замок на семействе берётся ПЕРВЫМ, и оба порядка становятся
// «родитель → ребёнок». Повтор лечил бы симптом и оставлял бы контроль
// зависимым от поведения клиента. Держит `TestOAuthExchangeTakesTheFamilyBeforeTheChild`
// на прод-пути хранилищ.
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
//
// Отсечка субъекта сессии кода — в том же операторе (`codeSessionCutOffSQL`):
// зафиксированная после выборки кода, она отказывает погашению здесь, а не
// проходит мимо.
const exchangeCodeSQL = `
UPDATE kaname.authorization_codes AS c
   SET deactivated_at = now(), deactivated_reason = 'redeemed'
 WHERE c.code_digest = $1
   AND c.active
   AND c.expires_at > now()
   AND NOT ` + codeSessionCutOffSQL + `
RETURNING c.family_id, c.client_id, c.user_id, c.session_id, c.scope,
          c.redirect_uri, c.code_challenge, c.code_challenge_method`

// ceremonyWriterTx — УРОВЕНЬ ИЗОЛЯЦИИ, на котором исполняется потребление кода
// (`exchangeCodeSQL` выше), КАЖДЫЙ другой писатель этого порта и транзакция
// писателя сессии, отзывающая семейства при снятии (kaname#316).
//
// Он НАЗВАН здесь, а не унаследован. Умолчание сессии задаёт не этот файл —
// конфигурация сервера, `ALTER DATABASE … SET`, `ALTER ROLE … SET`, параметр
// подключения, — и писатель, чей исход от умолчания зависит, менял бы поведение
// по чужой настройке, ничем этого не показав.
//
// # ПОЧЕМУ READ COMMITTED
//
// Одноинструкционное погашение держит строчный замок, и проигравший, СТОЯВШИЙ
// на строке победителя, после фиксации победителя перепроверяет условие `WHERE`
// по НОВОЙ версии строки: код уже неактивен — затронуто ноль строк. Ноль строк
// разбирает `adjudicatePresented` в той же транзакции и отдаёт порту фундамента
// нулём, а движок читает его одновременным ПОВТОРОМ (LINE-A-1-13, LINE-A-1-17).
// Перепроверку по новой версии делает ТОЛЬКО этот уровень: при REPEATABLE READ
// и SERIALIZABLE движок ту же строку не перепроверяет, а отказывает транзакции
// целиком (40001), и разбору нуля строк вход не достаётся вовсе.
//
// Устройство то же у остальных писателей, и потому решение одно на всех:
// оборот токена обновления (единица работы хранилищ открывается этим же
// уровнем), отзыв семейства (вторая отметка — пустая, а не отказ), запись
// выпуска токена доступа (заведение, стоявшее на отзыве своего семейства,
// перепроверяет ключ и получает «семейство не живо», kaname#319),
// проверочное значение клиента. Исход каждого под конкуренцией — перепроверка
// условия, а не отказ сериализации. Уборка записей выпуска строку, которую
// держит другой, пропускает (`SKIP LOCKED`), а не ждёт; уровень у неё тот же.
//
// # ВЫДАЧА ПРОТИВ СНЯТИЯ СЕССИИ — ПАРА ДВУХ ТРАНЗАКЦИЙ
//
// Исход этой пары решает уровень ОБЕИХ сторон, и потому уровень назван у
// обеих. Выдача — писатель этого порта; снятие исполняется в транзакции
// писателя сессии, которую открывает `beginHumanSessionWriter` — на этом же
// уровне, и её отзыв семейств (`revokeFamiliesOfSessionsTx`) судится вместе с
// ней. Выдача, стоявшая на снятии, перечитывает строку сессии по новой версии
// и получает «сессия не жива». Снятие, стоявшее на выдаче, которая строку
// сессии лишь держала, отзывает семейства СЛЕДУЮЩИМ оператором со своим новым
// снимком — и видит семейство, заведённое выдачей. При унаследованном
// `repeatable read` или `serializable` у снятия снимок один на транзакцию:
// семейство выдачи он не видит, а отказа сериализации при выдаче на этом
// уровне нет, и снятие фиксируется без отзыва заведённого в сессии.
//
// # ВЕТВИ «40001 → ПОВТОР» НЕТ, И ЭТО РЕШЕНИЕ, А НЕ УПУЩЕНИЕ
//
// На названном уровне эти операторы отказа сериализации не дают. 40001 (как и
// 40P01) разбирает общий `wrapPgErr` — «повторите запрос», — и ни в какой исход
// церемонии он не отображается: на этом уровне такая ветвь не получала бы входа,
// а на ином подменяла бы разбор строки догадкой о том, что случилось.
//
// Держит решение `oauth_ceremony_isolation_integration_test.go`: каждый писатель
// и каждая дверь писателя сессии исполняются под умолчанием продукта и под
// `serializable`, и ожидание на строке там доказывается состоянием движка, а
// не паузой. У уборки сцены нет: не ожидая, она чередования «стоит на строке
// держателя» не даёт. Что транзакции писателей и уборки открываются ТОЛЬКО
// здесь названным уровнем, держит перепись по разбору пакета
// (`ceremony_writer_openers_test.go`).
//
// Функция, а не переменная пакета: значение названо один раз и переписано
// быть не может.
func ceremonyWriterTx() pgx.TxOptions { return pgx.TxOptions{IsoLevel: pgx.ReadCommitted} }

// beginWriter — ЕДИНСТВЕННОЕ открытие транзакции писателя в этом порту.
func (r *OAuthCeremonyRepo) beginWriter(ctx context.Context) (pgx.Tx, error) {
	return journalwrite.BeginTx(ctx, r.pool, ceremonyWriterTx())
}

// execWriter — одиночный оператор писателя на названном уровне.
//
// Оператор, исполненный пулом без транзакции, шёл бы на умолчании сессии — то
// есть уровень снова был бы унаследован. Цена названного — начало и фиксация
// лишними репликами. Платят ею снятие проверочного значения клиента, уборка
// записей выпуска и запись выпуска токена доступа. Последняя стоит на выдаче
// (один раз на выпущенный токен, вслед за подписью), а не на предъявлении:
// предъявление читает запись одним оператором пула.
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

// insertRefreshSQL — заведение обновляющего токена в семейство: ОДИН
// литерал на оба пути, которыми токен ложится в семейство, — первое поколение
// обмена кода и преемник оборота, оба в единице работы церемонии фундамента
// (`oauth_ceremony_vaults.go`). Согласие контекста с семейством
// держит составной ключ `refresh_tokens_family_context_fk`, живость семейства —
// `refresh_tokens_family_live_fk`: писатель их не проверяет.
const insertRefreshSQL = `
INSERT INTO kaname.refresh_tokens
       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(secs => $8))`

// insertRefreshTokenTx — заведение обновляющего токена в транзакции
// вызывающего. Срок — от времени БАЗЫ: сравнивают его тоже операторы базы.
func insertRefreshTokenTx(ctx context.Context, tx pgx.Tx, digest string, c domain.CeremonyContext,
	generation int32, ttl time.Duration,
) error {
	if _, err := tx.Exec(ctx, insertRefreshSQL,
		digest, c.FamilyID, c.ClientID, c.UserID, c.SessionID, c.Scope, generation, ttl.Seconds()); err != nil {
		return wrapPgErr(err, "RefreshToken", c.FamilyID)
	}
	return nil
}

// ConsumeAuthorizationCode гасит код — ТЕМ ЖЕ оператором, что обмен
// (`exchangeCodeSQL`), после замка семейства (`lockFamilyOfCodeSQL`), на
// названном уровне (`ceremonyWriterTx()`). Возвращает число погашенных строк:
// 1 — погасил этот вызов; 0 — условие не выполнилось (уже погашен, истёк либо
// семейство отозвано). Разбор нуля — забота вызывающего: у церемонии
// фундамента (`oauth_ceremony_vaults.go`) повтор узнаётся выборкой кода, а ноль
// строк после живой выборки — одновременный повтор (контракт
// `oauthceremony.AuthorizationCodeVault`).
//
// Первого поколения обновляющего токена здесь нет, и это не сокращение: движок
// фундамента гасит код при ПРЕДЪЯВЛЕНИИ, до сверки доказательства, а пару
// кладёт позже, своей единицей работы (`CeremonyVaults.StoreRefreshToken`).
func (r *OAuthCeremonyRepo) ConsumeAuthorizationCode(ctx context.Context, digest string) (int64, error) {
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", digest); err != nil {
		return 0, err
	}
	tx, err := r.beginWriter(ctx)
	if err != nil {
		return 0, wrapPgErr(err, "AuthorizationCode", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	consumed, err := consumeCodeTx(ctx, tx, digest)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, wrapPgErr(err, "AuthorizationCode", "")
	}
	return consumed, nil
}

// consumeCodeTx — погашение кода в транзакции вызывающего: замок семейства
// ПЕРВЫМ (`lockFamilyOfCodeSQL`, порядок «родитель → ребёнок»), затем оператор
// обмена (`exchangeCodeSQL`). Число погашенных строк — 1 либо 0.
//
// Ноль строк от ОТСЕЧКИ СУБЪЕКТА — не ноль, а отказ
// `domain.ErrCeremonySubjectCutOff`: ноль строк у порта фундамента — повтор, и
// повтор отзывает семейство, а журнал назвал бы атакой отзыв доступа. Причина
// читается ТЕМ ЖЕ предикатом, что в условии (`codeRefusalSQL`), в той же
// транзакции — второй связи из пула погашение не берёт.
func consumeCodeTx(ctx context.Context, tx pgx.Tx, digest string) (int64, error) {
	if _, err := tx.Exec(ctx, lockFamilyOfCodeSQL, digest); err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	rows, err := tx.Query(ctx, exchangeCodeSQL, digest)
	if err != nil {
		return 0, wrapPgErr(err, "AuthorizationCode", "")
	}
	var consumed int64
	for rows.Next() {
		consumed++
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, wrapPgErr(err, "AuthorizationCode", "")
	}
	if consumed != 0 {
		return consumed, nil
	}
	why, familyID, err := adjudicatePresented(ctx, tx, codeRefusalSQL, digest, "AuthorizationCode")
	if err != nil {
		return 0, err
	}
	if why == presentedCutOff {
		return 0, fmt.Errorf("%w: family %s", domain.ErrCeremonySubjectCutOff, familyID)
	}
	return 0, nil
}

// presentedRefusal — чем предъявленная строка не прошла условную запись
// погашения либо оборота. Корзины «прочее» нет: пятая причина на этой схеме —
// расхождение условия и разбора, и она названа своим значением.
//
// Вызывающие различают ОДНУ причину — отсечку (`consumeCodeTx`,
// `refuseCutOffRefresh`): она отказ «записи нет», а не ноль строк. Прочие
// уходят порту фундамента нулём строк, и движок читает его одновременным
// повтором. Разбор нужен и им: без него неактивная строка отрезанной сессии
// читалась бы отсечкой, и повтор остался бы без отзыва (порядок —
// `adjudicatePresented`).
type presentedRefusal int

const (
	presentedUnknown  presentedRefusal = iota // строки нет
	presentedReplay                           // строка неактивна: погашена, обёрнута либо семейство отозвано
	presentedCutOff                           // сессия строки отрезана отсечкой субъекта
	presentedExpired                          // строка активна, но срок вышел
	presentedDiverged                         // жива, в сроке и не отрезана — условие и разбор разошлись
)

// codeRefusalSQL, refreshRefusalSQL — разбор нуля строк условной записи: те же
// признаки, что в её условии, и тот же предикат отсечки. Читает их транзакция
// решающей записи: второй связи из пула разбор не берёт.
const (
	codeRefusalSQL = `
SELECT c.active, ` + codeSessionCutOffSQL + `, c.expires_at <= now(), c.family_id
  FROM kaname.authorization_codes c
 WHERE c.code_digest = $1`
	refreshRefusalSQL = `
SELECT t.active, ` + refreshSessionCutOffSQL + `, t.expires_at <= now(), t.family_id
  FROM kaname.refresh_tokens t
 WHERE t.token_digest = $1`
)

// adjudicatePresented называет причину нуля строк. Порядок — от решения,
// которое дороже всего потерять: неактивная строка — повтор (по нему отзывается
// семейство) при любой отсечке; живая, но отрезанная — отсечка; затем срок.
func adjudicatePresented(ctx context.Context, q rowQuerier, sql, digest, entity string) (presentedRefusal, string, error) {
	var (
		active, cutOff, expired bool
		familyID                string
	)
	err := q.QueryRow(ctx, sql, digest).Scan(&active, &cutOff, &expired, &familyID)
	switch {
	case stderrors.Is(err, pgx.ErrNoRows):
		return presentedUnknown, "", nil
	case err != nil:
		return 0, "", wrapPgErr(err, entity, "")
	case !active:
		return presentedReplay, familyID, nil
	case cutOff:
		return presentedCutOff, familyID, nil
	case expired:
		return presentedExpired, familyID, nil
	}
	return presentedDiverged, familyID, nil
}

// lockFamilyOfRefreshSQL — ЗАМОК, А НЕ ПРОВЕРКА, и по той же причине, что
// `lockFamilyOfCodeSQL`: оборот (`CeremonyVaults.RotateRefreshToken`) обязан
// брать семейство ПЕРВЫМ, иначе его порядок замков встречен порядку отзыва и
// жертвой цикла становится отзыв. Держит
// `TestOAuthRotationTakesTheFamilyBeforeTheChild`.
const lockFamilyOfRefreshSQL = `
SELECT 1 FROM kaname.token_families
 WHERE id = (SELECT family_id FROM kaname.refresh_tokens WHERE token_digest = $1)
   FOR KEY SHARE`

// rotateRefreshSQL — ТОТ ЖЕ механизм, что у погашения кода: условие на
// прежнее состояние и возврат затронутой строки. Исполняет его второй шаг
// оборота хранилищ (`CeremonyVaults.StoreRefreshToken`). Отсечка субъекта
// сессии токена — в том же операторе (`refreshSessionCutOffSQL`): замок оборота
// строку токена держит, а строку отсечки нет, и отсечка, зафиксированная между
// замком и оборотом, отказывает обороту здесь.
const rotateRefreshSQL = `
UPDATE kaname.refresh_tokens AS t
   SET deactivated_at = now(), deactivated_reason = 'rotated',
       successor_digest = $2
 WHERE t.token_digest = $1
   AND t.active
   AND t.expires_at > now()
   AND NOT ` + refreshSessionCutOffSQL + `
RETURNING t.family_id, t.client_id, t.user_id, t.session_id, t.scope, t.generation`

// RevokeFamily отзывает семейство целиком ОДНОЙ транзакцией: отметка на
// семействе и снятие всего живого, что по нему выдано, — включая записи
// выпуска токенов доступа (`access_tokens`), по которым о семействе судит место
// предъявления (kaname#319): их живость — тот же ключ `(family_id, live)`, и
// отметку до них доносит каскад, а не второй оператор.
//
// Отзыв ИДЕМПОТЕНТЕН: условие `revoked_at IS NULL` делает повторную отметку
// пустой, а не второй — на названном уровне (`ceremonyWriterTx()`), где
// второй, стоявший на строке первого, перепроверяет условие, а не получает
// отказ. Два одновременных обнаружения повтора — обычное дело (проигравших
// гонку больше одного), и второй из них не вправе ни отказать, ни переписать
// причину первого.
//
// Возвращается число строк отметки: 1 — отозвано этим вызовом, 0 — уже было.
func (r *OAuthCeremonyRepo) RevokeFamily(ctx context.Context, familyID string, reason domain.FamilyRevocationReason) (int64, error) {
	if familyID == "" {
		return 0, fmt.Errorf("Illegal argument token_family.id: required")
	}
	if err := reason.Validate(); err != nil {
		return 0, err
	}
	tx, err := r.beginWriter(ctx)
	if err != nil {
		return 0, wrapPgErr(err, "TokenFamily", familyID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// `live` идёт В ТОМ ЖЕ операторе, что отметка: пара держится ограничением
	// `token_families_live_pair_ck`, и оператор, тронувший одну половину, второй
	// попытки не получает. Именно эта колонка делает отзыв обновлением КЛЮЧА.
	tag, err := tx.Exec(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = $2, live = false
		 WHERE id = $1 AND revoked_at IS NULL`, familyID, string(reason))
	if err != nil {
		return 0, wrapPgErr(err, "TokenFamily", familyID)
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
		return 0, wrapPgErr(err, "TokenFamily", familyID)
	}
	return tag.RowsAffected(), nil
}

// revokeFamiliesOfSessionsTx отзывает семейства, привязанные к НАЗВАННЫМ
// сессиям, — в транзакции вызывающего.
//
// Вызывающий — писатель сессии, и транзакцию ему открывает
// `beginHumanSessionWriter` на уровне писателей церемонии (`ceremonyWriterTx()`):
// оператор ниже видит семейство, заведённое выдачей, на которой стояло снятие,
// только при новом снимке у КАЖДОГО оператора (раздел «Выдача против снятия
// сессии» у `ceremonyWriterTx`).
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
	// ребёнке. Записи выпуска токенов доступа — тоже ребёнок семейства, и место
	// предъявления судит по ним (kaname#319).
	return len(families), nil
}

// ── Проверочное значение секрета интерактивного клиента ─────────────────────

// ПИСАТЕЛЯ проверочного значения в этом файле НЕТ, и это решение (задача
// kaname#405, Р5). Значение кладёт вставка строки клиента ТЕМ ЖЕ оператором
// (`InteractiveClientRepo.Insert`): отдельная запись после вставки открывала бы
// окно «клиент со способом секретом есть, предъявить нечего», а сбой между
// двумя операторами оставлял бы клиента, которого нельзя доказать никогда.
// Прежний глагол записи снят вместе с разрешением гейта удержания; второго
// писателя держит гейт `TestInteractiveClientSecretMaterialHasOneWriter`.

// ClearClientSecretVerifier снимает проверочное значение: секрета у клиента
// больше нет. Способ аутентификации при этом НЕ меняется — публичным клиента
// делает способ `none`, а не пустота значения (kaname#317).
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
