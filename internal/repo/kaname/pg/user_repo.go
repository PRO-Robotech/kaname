// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// user_repo.go — pgxpool-impl для user.ReaderIface / WriterIface.
//
// User is scoped per-Account (один Kratos identity → N User-row); поля
// {account_id, invite_status, invited_by} живут в users.
//
// Within-service refs — DB-level invariants:
//   - UNIQUE (lower(email))                                  → 23505 / iamerr.ErrAlreadyExists
//   - UNIQUE (external_id) WHERE external_id<>''             → 23505 / iamerr.ErrAlreadyExists
//   - DEFERRABLE FK users.account_id → accounts(id)          → 23503 на COMMIT
//   - DEFERRABLE FK accounts.owner_user_id → users(id)       → 23503 на COMMIT
//   - CHECK users_invite_status_consistency (PENDING ⇔ external_id='')
//   - InsertPending: атомарный ON CONFLICT (lower(email)) DO UPDATE — строка
//                    возвращается и на конфликте, поэтому конкурентное первое
//                    появление сериализуется, а не отказывает.
//   - ActivateInvite: атомарный UPDATE … WHERE invite_status='PENDING' RETURNING — 0 rows ⇒ NotFound.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/filter"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
)

type userReader struct {
	tx pgx.Tx
}

// userCols — полный набор колонок. `labels` (D-3) — tenant-facing метки,
// делающие User label-selectable наравне с account/project (iam-direct ARM_LABELS).
const userCols = "id, account_id, external_id, email, display_name, invite_status, invited_by, created_at, labels"

func (r *userReader) Get(ctx context.Context, id domain.UserID) (domain.User, error) {
	row := r.tx.QueryRow(ctx, fmt.Sprintf(`SELECT %s FROM users WHERE id = $1`, userCols), string(id))
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
		}
		return domain.User{}, mapErr(err, "", string(id))
	}
	return u, nil
}

// GetByEmail — cross-Account lookup, возвращает старейшую row с этим адресом
// (любого invite_status). Caller должен знать target Account — используй
// GetByAccountEmail.
//
// `ORDER BY created_at ASC, id ASC` СОХРАНЁН, хотя строк по адресу теперь не
// больше одной: ключ `users_identity_email_uniq` (миграция 20260823050000)
// сделал адрес глобально уникальным, и спора о выборе не бывает.
//
// Упорядочивание остаётся защитой для данных, заведённых ДО ключа, и стоит
// ровно поэтому — не потому, что «один адрес принадлежит N строкам»: это было
// верно, пока уникальность была парной с аккаунтом, и перестало быть верным.
// Снять его значило бы вернуть выбор физическому порядку строк на любой базе,
// которую ключ ещё не прошёл.
func (r *userReader) GetByEmail(ctx context.Context, email domain.Email) (domain.User, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE lower(email) = lower($1) ORDER BY created_at ASC, id ASC LIMIT 1`, userCols),
		string(email))
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User with email %s not found", email)
		}
		return domain.User{}, mapErr(err, "", string(email))
	}
	return u, nil
}

// GetByAccountEmail — поиск user-row в конкретном Account.
// Используется для idempotent Invite path: если row уже существует (любого
// статуса), use-case делает idempotent return / re-attach.
func (r *userReader) GetByAccountEmail(ctx context.Context, accountID domain.AccountID, email domain.Email) (domain.User, error) {
	// Принадлежность читается из ЧЛЕНСТВА, а не из колонки строки (kacho#470):
	// один человек состоит в скольких угодно аккаунтах, и «его строка в этом
	// аккаунте» перестала существовать как понятие. Вопрос теперь другой и
	// честный: есть ли человек с такой почтой и состоит ли он ЗДЕСЬ.
	//
	// Отказ остаётся прежним по тону и адресату: спрашивающий про аккаунт
	// получает ответ про аккаунт, а не «человека нет вообще» — иначе он узнал бы
	// о существовании чужой строки.
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM users
		              WHERE lower(email) = lower($2)
		                AND EXISTS (SELECT 1 FROM memberships m
		                             WHERE m.user_id = users.id AND m.account_id = $1)`, userCols),
		string(accountID), string(email))
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User with email %s not found in account %s", email, accountID)
		}
		return domain.User{}, mapErr(err, "", string(email))
	}
	return u, nil
}

// MembershipExists — состоит ли человек в НАЗВАННОМ аккаунте.
//
// Вопрос задаётся паре, а не строке: `users.account_id` называет ОДИН аккаунт
// человека из многих (легаси-поле перехода IAM-ID-1), и ответ по ней был бы
// ответом про другой аккаунт.
func (r *userReader) MembershipExists(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (bool, error) {
	var exists bool
	err := r.tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM memberships WHERE user_id = $1 AND account_id = $2)`,
		string(userID), string(accountID)).Scan(&exists)
	if err != nil {
		return false, mapErr(err, "", string(userID))
	}
	return exists, nil
}

// FindPendingByEmail — приглашённые строки по адресу.
//
// Строк по адресу больше не бывает больше одной (`users_identity_email_uniq`,
// миграция 20260823050000), поэтому «все через все аккаунты» — снятая посылка:
// у человека одна строка, а аккаунтов столько, сколько членств. Возвращаемый
// срез остаётся срезом намеренно — сигнатура порта принадлежит вызывающим, и
// сужать её здесь значило бы менять контракт ради формы.
//
// Использует partial index `users_email_pending_idx`.
func (r *userReader) FindPendingByEmail(ctx context.Context, email domain.Email) ([]domain.User, error) {
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE invite_status = 'PENDING' AND lower(email) = lower($1) ORDER BY created_at ASC`, userCols),
		string(email))
	if err != nil {
		return nil, mapErr(err, "", string(email))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// FindActiveByExternalID — все ACTIVE-row'ы по identity (Kratos sub) через
// все Account'ы. Использует partial index `users_active_external_id_idx`.
func (r *userReader) FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error) {
	if externalID == "" {
		return nil, nil
	}
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE invite_status = 'ACTIVE' AND external_id = $1 ORDER BY created_at ASC`, userCols),
		string(externalID))
	if err != nil {
		return nil, mapErr(err, "", string(externalID))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// FindByExternalIDInStatuses — все row'ы по identity (Kratos sub) через все
// Account'ы, ограниченные множеством invite_status'ов, ORDER BY created_at ASC.
// В отличие от FindActiveByExternalID (ACTIVE-only), видит и BLOCKED-row'ы —
// recovery обязан их находить и re-enable'ить (OnRecoveryCompleted).
// Пустой externalID / пустой statuses → nil-срез.
func (r *userReader) FindByExternalIDInStatuses(ctx context.Context, externalID domain.ExternalSubject, statuses []domain.InviteStatus) ([]domain.User, error) {
	if externalID == "" || len(statuses) == 0 {
		return nil, nil
	}
	statusStrs := make([]string, 0, len(statuses))
	for _, s := range statuses {
		statusStrs = append(statusStrs, string(s))
	}
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE external_id = $1 AND invite_status = ANY($2) ORDER BY created_at ASC`, userCols),
		string(externalID), statusStrs)
	if err != nil {
		return nil, mapErr(err, "", string(externalID))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// FindActiveByEmail — все ACTIVE-row'ы по email (case-insensitive) через все
// Account'ы. ORDER BY created_at ASC — actives[0] и есть каноническая строка
// личности: тот же выбор делает FindByExternalIDInStatuses (тот же ORDER) и,
// следовательно, api-gateway через InternalIAMService.LookupSubject.
// Используется invite-flow'ом для привязки project-scoped AccessBinding к
// канонической identity-row.
func (r *userReader) FindActiveByEmail(ctx context.Context, email domain.Email) ([]domain.User, error) {
	if email == "" {
		return nil, nil
	}
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE invite_status = 'ACTIVE' AND lower(email) = lower($1) ORDER BY created_at ASC`, userCols),
		string(email))
	if err != nil {
		return nil, mapErr(err, "", string(email))
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// ListAccountsForUser — все Account'ы, где человек СОСТОИТ либо которыми
// владеет. Снимок «мои аккаунты» собственного профиля (`AuthorizeService.WhoAmI`).
//
// Полный набор =
//
//	(1) аккаунты АКТИВНЫХ ЧЛЕНСТВ активной личности (kaname.memberships)
//	UNION
//	(2) аккаунты, где principal является owner (accounts.owner_user_id = $1) —
//	    владеть не значит состоять (решение по PRO-Robotech/kacho#610), поэтому
//	    источник самостоятельный, а не следствие первого
//	UNION
//	(3) аккаунты, на которые у principal есть ACTIVE AccessBinding
//	    (resource_type='account', subject_type='user', subject_id=$1) — сюда
//	    попадает приглашённый, чьё членство ещё «приглашён»
//
// UNION автоматически устраняет дубли.
//
// ─────────────────────────────────────────────────────────────────────────────
// СОСТОЯНИЕ ЛИЧНОСТИ ОТСЕКАЕТ, СОСТОЯНИЕ ЧЛЕНСТВА — НЕТ, И ЭТО НЕ ИЗБЫТОЧНОСТЬ
//
// Источник (1) прежде читал `users.account_id … AND invite_status = 'ACTIVE'`,
// то есть отсекал по состоянию ЛИЧНОСТИ. Зеркало 470001 переводит состояние
// строки в состояние членства правилом «PENDING → PENDING, ИНАЧЕ → ACTIVE»,
// поэтому у ЗАБЛОКИРОВАННОГО человека членство остаётся `ACTIVE` — намеренно:
// блокировка есть свойство личности, а не членства.
//
// Следствие: замена отбора `users.invite_status = 'ACTIVE'` на
// `memberships.state = 'ACTIVE'` НЕ эквивалентна — она начала бы называть
// аккаунты заблокированному, то есть расширила бы видимость под видом переноса
// источника. Поэтому соединение с личностью здесь обязательно, и оба условия
// стоят вместе. Держит это `TestBlockedIdentityGainsNoAccountThroughMembership`.
func (r *userReader) ListAccountsForUser(ctx context.Context, userID domain.UserID) ([]domain.AccountID, error) {
	rows, err := r.tx.Query(ctx, `
		SELECT m.account_id
		  FROM memberships m
		  JOIN users u ON u.id = m.user_id
		 WHERE m.user_id = $1 AND m.state = 'ACTIVE' AND u.invite_status = 'ACTIVE'
		UNION
		SELECT id FROM accounts WHERE owner_user_id = $1
		UNION
		SELECT resource_id FROM access_bindings
		  WHERE subject_type = 'user' AND subject_id = $1
		    AND resource_type = 'account' AND status = 'ACTIVE'`,
		string(userID))
	if err != nil {
		return nil, mapErr(err, "", string(userID))
	}
	defer rows.Close()
	var out []domain.AccountID
	for rows.Next() {
		var acc string
		if err := rows.Scan(&acc); err != nil {
			return nil, mapErr(err, "", "")
		}
		out = append(out, domain.AccountID(acc))
	}
	return out, rows.Err()
}

// membershipInAny — «человек состоит хотя бы в одном из НАЗВАННЫХ аккаунтов»,
// одним предикатом над таблицей членств.
//
// ЕДИНСТВЕННОЕ написание этого вопроса в списке пользователей. Три места
// спрашивали его тремя разными выражениями над колонкой `users.account_id`
// (фильтр запроса, множественный фильтр, сужение кандидатов), и после отрыва
// (kacho#471) они разошлись бы поодиночке — а расхождение здесь наблюдаемо
// только составом страницы, то есть тем, что читателю показали не тех людей.
//
// Полусоединение, а не соединение: строка человека обязана прийти в ответ ОДИН
// раз, сколько бы членств ни попало в названный набор. Индекс под предикат —
// `memberships_user_account_unique (user_id, account_id)` (470001).
func membershipInAny(argIdx int) string {
	return fmt.Sprintf(
		"EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = users.id AND m.account_id = ANY($%d))",
		argIdx)
}

func (r *userReader) List(ctx context.Context, f user.ListFilter) ([]domain.User, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // #184: reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1

	// AccountID filter (single). Читается ЧЛЕНСТВО, а не колонка: вопрос «кто
	// состоит в этом аккаунте» есть вопрос о членстве, и после отрыва (kacho#471)
	// у него не одна пара на человека. При одном членстве оба источника дают одно
	// и то же by construction — зеркало 470001 держит их в согласии.
	if f.AccountID != "" {
		conditions = append(conditions, membershipInAny(argIdx))
		args = append(args, []string{string(f.AccountID)})
		argIdx++
	}
	// AccountIDs filter (multi). Применяется только если AccountID не задан.
	//
	// ПИСАТЕЛЯ У ЭТОГО ПОЛЯ В ПРОДЕ НЕТ — единственный, кто его заполняет, это
	// интеграционная проба соседнего файла. Ветка сохранена, а не снята, потому
	// что снятие поля порта — отдельный предмет; здесь она приведена к той же
	// семантике, что и одиночная, чтобы два выражения одного вопроса не разошлись.
	if f.AccountID == "" && len(f.AccountIDs) > 0 {
		accounts := make([]string, 0, len(f.AccountIDs))
		for _, acc := range f.AccountIDs {
			accounts = append(accounts, string(acc))
		}
		conditions = append(conditions, membershipInAny(argIdx))
		args = append(args, accounts)
		argIdx++
	}

	if f.Filter != "" {
		// Whitelist is closed; an expression outside it is refused by name rather
		// than dropped (#445). This resource dispatches on the parsed field instead
		// of emitting ast.ToSQL, because none of the four terms is addressed as the
		// field is written: `email` is compared case-insensitively, and `search` is
		// not a column at all — it is a term spanning two of them. The switch is
		// what keeps that mapping in one place. A field added to the whitelist
		// without a case here would parse and then match nothing, so the default arm
		// refuses instead of silently widening the page.
		ast, ferr := parseListFilter(f.Filter, "email", "external_id", "invite_status", "search")
		if ferr != nil {
			return nil, "", ferr
		}
		if ast != nil {
			// The grammar carries an OPERATOR, and this switch reads only ast.Value —
			// so before #460 `email CONTAINS "acme"` was answered as `email = "acme"`:
			// the caller asked for everyone at that domain and got the single exact
			// match under a 200, with nothing in the response to tell the two apart.
			// api-conventions.md §"Принято-и-проигнорировано — ЗАПРЕЩЕНО" allows
			// implement, refuse by name, or drop from the contract; this is the second.
			//
			// Refusing rather than implementing is the deliberate choice, not the cheap
			// one: substring search on User already EXISTS and is published as
			// `search="…"` (ListUsersRequest.filter), spanning email and id. Adding
			// LIKE to `email` / `external_id` / `invite_status` would give one question
			// two spellings that must then be kept in step forever, and on
			// `invite_status` — a closed enum — a substring means nothing at all. So the
			// message names the operator, the field, AND where substring search lives,
			// because a caller told only "invalid" tries the same expression again.
			if ast.Op != filter.OpEquals {
				return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg,
					`Operator %s is not supported for filter field %q. Substring search on User is spelled search="<value>"`,
					ast.Op, ast.Field)
			}
			switch ast.Field {
			case "email":
				conditions = append(conditions, fmt.Sprintf("lower(email) = lower($%d)", argIdx))
				args = append(args, ast.Value)
			case "external_id":
				conditions = append(conditions, fmt.Sprintf("external_id = $%d", argIdx))
				args = append(args, ast.Value)
			case "invite_status":
				conditions = append(conditions, fmt.Sprintf("invite_status = $%d", argIdx))
				args = append(args, ast.Value)
			case "search":
				// Поиск по ПОДСТРОКЕ — по тому, чем пользователя знают: почта и
				// идентификатор. `name` у пользователя нет вовсе, а полное совпадение
				// `email="…"` отвечает только тому, кто уже знает адрес целиком.
				//
				// Сузить список на клиенте нельзя: клиент видит только загруженную
				// страницу и о том, что в неё не поместилось, врёт молча.
				//
				// Индекса под этот предикат нет намеренно. Строки таблицы сужены
				// аккаунтом вызывающего условием выше, и разбор здесь идёт по уже
				// суженному набору; триграммный индекс заводится ЗАМЕРОМ на боевом
				// объёме, а не догадкой о нём — заведённый вслепую, он стоил бы
				// расширения и записи на каждой правке почты, ничего не ускорив.
				conditions = append(conditions, fmt.Sprintf(
					`(lower(email) LIKE $%d ESCAPE '\' OR lower(id) LIKE $%d ESCAPE '\')`, argIdx, argIdx))
				args = append(args, "%"+escapeLikePattern(strings.ToLower(ast.Value))+"%")
			default:
				return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg,
					"Bad expression at column 1. Unknown field: %q", ast.Field)
			}
			argIdx++
		}
	}
	// Курсор. Разобранный (After) имеет приоритет: путь, который его задаёт,
	// токена не передаёт вовсе, поэтому «оба заданы» здесь не встречается — но
	// порядок назван явно, чтобы это было свойством кода, а не совпадением.
	switch {
	case f.After != nil:
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, f.After.CreatedAt, f.After.ID)
		argIdx += 2
	case f.PageToken != "":
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// Сужение набора КАНДИДАТОВ (задача #645). Оно стоит здесь, в отборе строк, а
	// не после него: постфильтр по видимости теряет всякую запись, перед которой
	// лежит больше `page_size` невидимых предшественников — она до фильтра просто
	// не доезжает. Собственная строка вызывающего приходит в ObjectIDs (см. порт),
	// поэтому пол этой поверхности — тоже условие отбора, а не постфильтр.
	//
	// nil — не сужать (администратор облака, bootstrap); непустой указатель с
	// пустыми наборами не называет ни одной строки и потому не пропускает ни одной.
	//
	// Аккаунт кандидата берётся из ЧЛЕНСТВА. Отбор по СОСТОЯНИЮ членства здесь
	// запрещён и это не осторожность: набор кандидатов обязан быть НАДМНОЖЕСТВОМ
	// видимого (см. порт), а вердикт выносит модель. Колонка сегодня пропускает
	// кандидата при любом состоянии строки, включая «приглашён» и «заблокирован»;
	// добавив `state = 'ACTIVE'`, полусоединение сузило бы набор УЖЕ — то есть
	// потеряло бы строку до того, как её кто-либо осудил.
	if f.Candidates != nil {
		conditions = append(conditions,
			fmt.Sprintf("(%s OR id = ANY($%d))", membershipInAny(argIdx), argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM users %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		userCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

type userWriter struct {
	userReader
	// membershipHintSink — обратный указатель в объемлющую writeTx (ставится
	// `writeTx.UsersW`). Исключение из аккаунта отвергается ОТЛОЖЕННЫМ
	// триггером, то есть на COMMIT, а не на своём стейтменте: к моменту отказа
	// вызывающий из виду потерян, и назвать в тексте человека и аккаунт можно
	// только тем, что писатель оставил здесь. Тот же приём, что у
	// `ownerFKHintSink` соседа, и по той же причине.
	membershipHintSink *string
}

// Upsert — legacy path retained for backward-compat with integration tests
// that call Upsert directly (TestUser_2_0_15a/15b).
//
// Ключ по external_id — ГЛОБАЛЬНЫЙ (partial WHERE external_id<>”): один внешний
// субъект есть одна строка. Upsert делает INSERT с {AccountID +
// invite_status='ACTIVE'}; при дубле по external_id → UPDATE email/display_name
// и добавление членства в названном аккаунте.
//
// Production paths use InsertPending / ActivateInvite / InsertActive directly
// — not Upsert.
func (w *userWriter) Upsert(ctx context.Context, u domain.User) (domain.User, bool, error) {
	now := time.Now().UTC()
	accountID := nullableAccountID(u.AccountID)
	inviteStatus := string(u.InviteStatus)
	if inviteStatus == "" {
		inviteStatus = string(domain.InviteStatusActive)
	}
	invitedBy := nullableInvitedBy(u.InvitedBy)

	// Арбитр — ГЛОБАЛЬНЫЙ ключ внешнего субъекта
	// (`users_identity_external_id_uniq`, миграция 20260823050000), а не пара с
	// аккаунтом: человек есть одна строка, в скольких бы аккаунтах он ни
	// состоял. Пер-аккаунтный арбитр заводил бы ему вторую строку — второй
	// идентификатор, второй набор прав, из которых действует один.
	//
	// Предикат `WHERE external_id <> ''` выбирает ИМЕННО этот индекс: предикат
	// пер-состоянийного `users_active_external_id_uniq` им не подразумевается,
	// поэтому вывод индекса однозначен.
	//
	// Членство пишется ЯВНО и в той же транзакции: при попадании в конфликт
	// строка не переписывается, зеркалящий триггер не срабатывает, и членство в
	// названном аккаунте не появилось бы вовсе.
	q := fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, invited_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (external_id) WHERE external_id <> '' DO UPDATE
			   SET email = EXCLUDED.email,
			       display_name = EXCLUDED.display_name
			RETURNING %s, (xmax = 0) AS created
		), membership AS (
			INSERT INTO memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
			SELECT membership_mirror_id(i.id, $2), i.id, $2,
			       CASE WHEN i.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
			       $7, $8, $8
			  FROM ins i
			 WHERE $2 IS NOT NULL AND $2 <> ''
			ON CONFLICT (user_id, account_id) DO NOTHING
		)
		SELECT %s, created FROM ins`, userCols, userCols)
	row := w.tx.QueryRow(ctx, q,
		string(u.ID), accountID, string(u.ExternalID), string(u.Email), string(u.DisplayName),
		inviteStatus, invitedBy, now,
	)
	var (
		out     domain.User
		created bool
	)
	err := scanUserWithCreated(row, &out, &created)
	if err != nil {
		return domain.User{}, false, mapErr(err, "", string(u.ExternalID))
	}
	return out, created, nil
}

// InsertPending — «человек существует и приглашён в ЭТОТ аккаунт», атомарно и
// идемпотентно.
//
// Возвращает строку человека и признак того, что она ЗАВЕДЕНА этим вызовом.
// Признак несущий: после отрыва принадлежности приглашение известной почты во
// второй аккаунт строки НЕ заводит, и отличить «завёл» от «нашёл» вызывающему
// больше нечем — прежде это следовало из самого факта конфликта.
//
// Одним стейтментом делаются обе половины операции: строка человека (глобальный
// арбитр по почте) и его членство в названном аккаунте. Разнести их на два
// стейтмента нельзя — между ними встала бы точка, в которой человек есть, а
// приглашение потерялось.
func (w *userWriter) InsertPending(ctx context.Context, u domain.User) (domain.User, bool, error) {
	now := time.Now().UTC()
	invitedBy := nullableInvitedBy(u.InvitedBy)

	// Арбитр — ГЛОБАЛЬНЫЙ ключ почты (`users_identity_email_uniq`, миграция
	// 20260823050000), а не пара с аккаунтом: приглашение человека во второй
	// аккаунт обязано найти его СТРОКУ, а не завести вторую.
	//
	// `DO UPDATE`, а не `DO NOTHING`, и это несущее различие, а не стиль.
	// `DO NOTHING` строку не возвращает и не берёт на неё замок: конкурирующий
	// вызов не видит ещё не закоммиченную чужую вставку, добирающий SELECT
	// возвращает пусто, и вызывающий получает отказ на вводе, который заведомо
	// законен. `DO UPDATE` ждёт чужой транзакции и возвращает строку — то есть
	// СЕРИАЛИЗУЕТ конкурентное первое появление (IAM-ID-1-07).
	//
	// Присваивается СВОЁ ЖЕ значение: приглашающий не вправе переписать имя
	// человеку, который в платформе уже есть. Колонки `account_id`,
	// `invite_status` и `invited_by` в списке SET не названы — иначе сработал бы
	// зеркалящий триггер, объявленный `UPDATE OF` этих трёх, и переписал бы
	// членство по колонке строки вместо названного аккаунта.
	//
	// Членство пишется ЯВНО: при попадании в конфликт триггер не срабатывает
	// вовсе, и выразить «этот человек приглашён СЮДА» больше нечем.
	q := fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, invited_by, created_at)
			VALUES ($1, $2, '', $3, $4, 'PENDING', $5, $6)
			ON CONFLICT (lower(email)) DO UPDATE
			   SET display_name = users.display_name
			RETURNING %s, (xmax = 0) AS inserted
		), membership AS (
			INSERT INTO memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
			SELECT membership_mirror_id(i.id, $2), i.id, $2,
			       CASE WHEN i.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
			       $5, $6, $6
			  FROM ins i
			 WHERE $2 IS NOT NULL AND $2 <> ''
			ON CONFLICT (user_id, account_id) DO NOTHING
		)
		SELECT %s, inserted FROM ins`, userCols, userCols)

	row := w.tx.QueryRow(ctx, q,
		string(u.ID), string(u.AccountID), string(u.Email), string(u.DisplayName),
		invitedBy, now,
	)
	var (
		out      domain.User
		inserted bool
	)
	if err := scanUserWithInserted(row, &out, &inserted); err != nil {
		return domain.User{}, false, mapErr(err, "", string(u.Email))
	}
	return out, inserted, nil
}

// ActivateInvite — атомарный UPDATE PENDING → ACTIVE с set external_id +
// (optional) display_name.
//
// 0 rows RETURNING → ErrNotFound (либо row не существует, либо уже не PENDING
// — race с параллельной активацией). NULL-проверка дисплейнейма:
// `COALESCE(NULLIF($2,”), display_name)` — пустой displayName не перезаписывает.
func (w *userWriter) ActivateInvite(ctx context.Context, userID domain.UserID, externalID domain.ExternalSubject, displayName domain.DisplayName) (domain.User, error) {
	q := fmt.Sprintf(`
		UPDATE users
		   SET external_id = $1,
		       display_name = COALESCE(NULLIF($2, ''), display_name),
		       invite_status = 'ACTIVE'
		 WHERE id = $3 AND invite_status = 'PENDING'
		RETURNING %s`, userCols)
	row := w.tx.QueryRow(ctx, q, string(externalID), string(displayName), string(userID))
	out, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound,
				"User %s not found in PENDING state", userID)
		}
		return domain.User{}, mapErr(err, "", string(userID))
	}
	return out, nil
}

// InsertActive — INSERT ACTIVE-row напрямую (для bootstrap-flow).
// AccountID обязателен; FK violation на account_id (DEFERRABLE) проверяется
// на COMMIT транзакции.
func (w *userWriter) InsertActive(ctx context.Context, u domain.User) (domain.User, error) {
	now := time.Now().UTC()
	invitedBy := nullableInvitedBy(u.InvitedBy)
	q := fmt.Sprintf(`
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, invited_by, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, $7)
		RETURNING %s`, userCols)
	row := w.tx.QueryRow(ctx, q,
		string(u.ID), string(u.AccountID), string(u.ExternalID),
		string(u.Email), string(u.DisplayName), invitedBy, now,
	)
	out, err := scanUser(row)
	if err != nil {
		return domain.User{}, mapErr(err, "", string(u.ExternalID))
	}
	return out, nil
}

// Delete — атомарный DELETE с гвардом NOT EXISTS на access_bindings +
// access_binding_subjects + group_members.
//
// The access_bindings guard covers the LEGACY subjects[0] projection; the
// access_binding_subjects guard covers subjects[1..N] — an independent grantee of a
// multi-subject binding (RBAC rules-model, migration 0028) whose reference the
// subjects[0]-only guard missed, orphaning a within-service ref + phantom FGA grant
// (SEC r8, hard-rule #10). The concurrent delete-vs-add-subject window is closed at
// the DB level by the BEFORE DELETE trigger (migration 0050); this software guard is
// the fast common-case reject + canonical error text.
func (w *userWriter) Delete(ctx context.Context, id domain.UserID) error {
	const q = `
		WITH del AS (
			DELETE FROM users u
			WHERE u.id = $1
			  AND NOT EXISTS (SELECT 1 FROM access_bindings         WHERE subject_type = 'user' AND subject_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM access_binding_subjects WHERE subject_type = 'user' AND subject_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM group_members           WHERE member_type  = 'user' AND member_id  = $1)
			RETURNING 1
		)
		SELECT
		  (SELECT count(*) FROM del)::int                                                                    AS deleted,
		  EXISTS(SELECT 1 FROM users WHERE id = $1)                                                          AS user_exists,
		  (EXISTS(SELECT 1 FROM access_bindings         WHERE subject_type='user' AND subject_id = $1)
		   OR EXISTS(SELECT 1 FROM access_binding_subjects WHERE subject_type='user' AND subject_id = $1))   AS has_bindings,
		  EXISTS(SELECT 1 FROM group_members WHERE member_type='user' AND member_id = $1)                    AS has_group_mems
	`
	var (
		deleted                               int
		userExists, hasBindings, hasGroupMems bool
	)
	err := w.tx.QueryRow(ctx, q, string(id)).Scan(&deleted, &userExists, &hasBindings, &hasGroupMems)
	if err != nil {
		return mapErr(err, "User.Delete", string(id))
	}
	if deleted == 1 {
		return nil
	}
	if !userExists {
		return iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	switch {
	case hasBindings:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"User %s has active access bindings and cannot be deleted", id)
	case hasGroupMems:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"User %s is a member of one or more groups and cannot be deleted", id)
	}
	return iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
}

// UpdateLabels — single-statement UPDATE tenant-facing меток. Row-lock на
// users-row сериализует конкурентные writer'ы (запрет #10 — last-writer-wins, не
// TOCTOU): параллельный writer ждет commit, видит обновленный row. 0 rows
// RETURNING → ErrNotFound. Identity-поля не затрагиваются.
func (w *userWriter) UpdateLabels(ctx context.Context, id domain.UserID, labels domain.Labels) (domain.User, error) {
	labelsJSON, err := marshalLabels(labels)
	if err != nil {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	q := fmt.Sprintf(`UPDATE users SET labels = $2 WHERE id = $1 RETURNING %s`, userCols)
	row := w.tx.QueryRow(ctx, q, string(id), labelsJSON)
	out, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
		}
		return domain.User{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// SetInviteStatus — писатель административного запрета участию и его снятия
// (`UserService.Block` / `Unblock`). Меняет состояние ОДНОЙ строки членства.
//
// Аргумент — целевое СОСТОЯНИЕ, а не переход, поэтому повтор проходит: строка
// оказывается там, где просили, независимо от того, была ли она там уже.
// Compare-and-set по прежнему состоянию не купил бы здесь ни одного инварианта
// и превратил бы повтор запрета в отказ — направление, которое обязано быть
// самым лёгким.
//
// ПОЧЕМУ ОДИН СТЕЙТМЕНТ, А НЕ ПРОВЕРКА-ДО-ЗАПИСИ. Инвариант «приглашение без
// подтверждённой личности не переводится ни в ACTIVE, ни в BLOCKED» выражен
// предикатом самого UPDATE (запрет #10). Такая строка не несёт внешнего
// идентификатора, и DB-CHECK users_invite_status_consistency отверг бы запись —
// то есть без предиката вместо внятного отказа приходило бы нарушение
// констрейнта из глубины драйвера.
//
// ПОЧЕМУ ВОЗВРАЩАЕТСЯ ПРИЗНАК СУЩЕСТВОВАНИЯ. Предикат состояния даёт ноль строк
// в ДВУХ разных случаях — строки нет вовсе и строка есть, но PENDING. Ответы
// на них разные («User %s not found» против «is not active»), и различить их
// обязана сама запись: иначе строка, удалённая между синхронным пречеком
// use-case'а и работой воркера, получила бы FAILED_PRECONDITION там, где
// контракт-тон требует NOT_FOUND. LEFT JOIN на однострочный источник
// гарантирует ровно одну строку ответа, поэтому это по-прежнему один
// round-trip, а не «попробовал, потом уточнил».
func (w *userWriter) SetInviteStatus(ctx context.Context, id domain.UserID, st domain.InviteStatus) (domain.User, error) {
	if err := st.Validate(); err != nil {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	// Целевое состояние — bind-параметр: значение решает вызывающий, а SQL несёт
	// только инвариант.
	const q = `
		WITH upd AS (
			UPDATE users
			   SET invite_status = $2
			 WHERE id = $1 AND invite_status <> 'PENDING'
			RETURNING id, account_id, external_id, email, display_name,
			          invite_status, invited_by, created_at, labels
		)
		SELECT EXISTS(SELECT 1 FROM users WHERE id = $1) AS row_exists,
		       u.id, u.account_id, u.external_id, u.email, u.display_name,
		       u.invite_status, u.invited_by, u.created_at, u.labels
		  FROM (SELECT 1) AS one
		  LEFT JOIN upd u ON true`
	row := w.tx.QueryRow(ctx, q, string(id), string(st))

	out, updated, rowExists, err := scanUserStateWrite(row)
	if err != nil {
		return domain.User{}, mapErr(err, "User.SetInviteStatus", string(id))
	}
	switch {
	case updated:
		return out, nil
	case !rowExists:
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	default:
		// Строка есть, но её состояние записи не допускает — единственный
		// оставшийся случай при этом предикате.
		return domain.User{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s is not active", id)
	}
}

// ---- helpers ---------------------------------------------------------------

// scanUserStateWrite читает ответ SetInviteStatus: признак существования строки
// плюс её колонки, которые NULL, когда UPDATE не сматчился.
func scanUserStateWrite(row scanner) (domain.User, bool /*updated*/, bool /*rowExists*/, error) {
	var (
		rowExists    bool
		userID       sql.NullString
		accountID    sql.NullString
		externalID   sql.NullString
		email        sql.NullString
		displayName  sql.NullString
		inviteStatus sql.NullString
		invitedBy    sql.NullString
		createdAt    sql.NullTime
		labelsJSON   []byte
	)
	if err := row.Scan(&rowExists, &userID, &accountID, &externalID, &email,
		&displayName, &inviteStatus, &invitedBy, &createdAt, &labelsJSON); err != nil {
		return domain.User{}, false, false, err
	}
	if !userID.Valid {
		return domain.User{}, false, rowExists, nil
	}
	u := domain.User{
		ID:           domain.UserID(userID.String),
		AccountID:    domain.AccountID(accountID.String),
		ExternalID:   domain.ExternalSubject(externalID.String),
		Email:        domain.Email(email.String),
		DisplayName:  domain.DisplayName(displayName.String),
		InviteStatus: domain.InviteStatus(inviteStatus.String),
		InvitedBy:    domain.UserID(invitedBy.String),
		CreatedAt:    createdAt.Time,
	}
	labels, err := unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.User{}, false, rowExists, err
	}
	u.Labels = labels
	return u, true, rowExists, nil
}

func scanUser(row scanner) (domain.User, error) {
	var u domain.User
	if err := scanUserInto(row, &u); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// scanUserInto — ЕДИНСТВЕННОЕ объявление порядка назначений под userCols.
// `extra` — приёмники, дописанные запросом ПОСЛЕ проекции (признак вставки у
// CTE-форм InsertPending/Upsert); без них это обычное чтение userCols.
//
// Порядок объявлен один раз намеренно. Прежде его несли два независимых списка
// — `scanUser` и этот, — и компилятор их не связывал: расхождение выражалось бы
// только отказом живой Postgres на пути чтения. Ровно так у роли колонка,
// добавленная в проекцию и не добавленная во вторую копию списка, положила
// правку КАЖДОЙ роли (#1943). Заводя колонку в userCols, правь список здесь.
func scanUserInto(row scanner, out *domain.User, extra ...any) error {
	var (
		accountID    sql.NullString
		externalID   sql.NullString
		displayName  sql.NullString
		inviteStatus sql.NullString
		invitedBy    sql.NullString
		labelsJSON   []byte
	)
	dest := append([]any{
		(*string)(&out.ID),
		&accountID,
		&externalID,
		(*string)(&out.Email),
		&displayName,
		&inviteStatus,
		&invitedBy,
		&out.CreatedAt,
		&labelsJSON,
	}, extra...)
	if err := row.Scan(dest...); err != nil {
		return err
	}
	if accountID.Valid {
		out.AccountID = domain.AccountID(accountID.String)
	}
	if externalID.Valid {
		out.ExternalID = domain.ExternalSubject(externalID.String)
	}
	if displayName.Valid {
		out.DisplayName = domain.DisplayName(displayName.String)
	}
	if inviteStatus.Valid {
		out.InviteStatus = domain.InviteStatus(inviteStatus.String)
	}
	if invitedBy.Valid {
		out.InvitedBy = domain.UserID(invitedBy.String)
	}
	labels, err := unmarshalLabels(labelsJSON)
	if err != nil {
		return err
	}
	out.Labels = labels
	return nil
}

func scanUserWithCreated(row scanner, out *domain.User, created *bool) error {
	return scanUserInto(row, out, created)
}

func scanUserWithInserted(row scanner, out *domain.User, inserted *bool) error {
	return scanUserWithCreated(row, out, inserted)
}

func nullableAccountID(id domain.AccountID) any {
	if id == "" {
		return nil
	}
	return string(id)
}

func nullableInvitedBy(id domain.UserID) any {
	if id == "" {
		return nil
	}
	return string(id)
}

// escapeLikePattern экранирует служебные знаки LIKE, чтобы образец искался как
// СИМВОЛЫ.
//
// Без этого ввод `%` находил бы всех, а `_` — любой одиночный знак: поиск
// отвечал бы не на тот вопрос, который задали, и выглядел бы при этом
// работающим. Обратный слэш экранируется первым — иначе экранирующий знак,
// добавленный следующими заменами, сам оказался бы экранирован.
var likePatternEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func escapeLikePattern(s string) string { return likePatternEscaper.Replace(s) }

// RemoveMembership — снять членство человека в названном аккаунте.
//
// Один стейтмент: «человека здесь больше нет» выражается отсутствием строки, и
// проверка-перед-снятием была бы check-then-act (ban #10) — между вопросом и
// снятием членство успевает появиться повторным приглашением.
//
// Идемпотентность здесь не свойство кода, а свойство предмета: снятие
// отсутствующего членства и есть достигнутая цель. Поэтому 0 строк — не ошибка,
// а второй законный исход, и вызывающий отличает их по признаку возврата.
//
// Строка `users` не читается и не пишется: исключение — действие над ЧЛЕНСТВОМ.
// Колонка `users.account_id` намеренно остаётся как есть — она легаси-поле
// перехода и называет один аккаунт из многих; править её отсюда значило бы
// менять предмет, которого этот вызов не касается.
func (w *userWriter) RemoveMembership(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (bool, error) {
	// Подсказка ставится ДО стейтмента: отказ придёт на COMMIT, и к тому моменту
	// ни человек, ни аккаунт из аргументов уже недоступны отображению ошибок.
	if w.membershipHintSink != nil {
		*w.membershipHintSink = string(userID) + "|" + string(accountID)
	}
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accountID))
	if err != nil {
		return false, mapErr(err, "Membership.Remove", string(userID)+"|"+string(accountID))
	}
	return tag.RowsAffected() > 0, nil
}
