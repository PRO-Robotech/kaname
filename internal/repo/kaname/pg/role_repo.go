// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// role_repo.go — pgxpool-impl для role.ReaderIface / WriterIface.
//
// Role: либо custom (account_id NOT NULL, is_system=false), либо system
// (account_id IS NULL, is_system=true).
//
// Within-service refs enforced at the DB level (ban #10):
//   - DB CHECK roles_system_xor_account (мутекс XOR).
//   - partial UNIQUE roles_custom_unique (account_id, name) WHERE is_system=false.
//   - partial UNIQUE roles_system_unique (name) WHERE is_system=true.
//   - FK roles_account_fk (custom only).
//   - DB CHECK iam_permissions_valid (regex + cardinality).
//   - Delete custom-role: atomic CAS WHERE NOT EXISTS access_bindings.role_id +
//     is_system=false (NotFound vs FailedPrecondition с verbatim text).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

type roleReader struct {
	tx pgx.Tx
}

// roleCols — canonical projection. It includes cluster_id + project_id so a
// read populates domain.Role's full scope (ClusterID for system, ProjectID for
// project-scoped custom) — the isRoleAssignable predicate
// (domain.IsRoleAssignable / ScopeGroupOf) reads those fields.
//
// `owner_module` стоит здесь с задачи #1032: без него политика послабления
// подстановки читалась бы из строки НЕПОЛНО — `PolicyOfRole` получал бы пустого
// владельца у роли, которая им обладает, и судила бы её платформенной, то есть
// САМОЙ МЯГКОЙ. Столбец, который пишут и не читают, невидим отовсюду; здесь цена
// такой невидимости — послабление, выданное молча.
const roleCols = "id, cluster_id, account_id, project_id, name, description, permissions, rules, is_system, owner_module, created_at, updated_at, labels"

// rulesToJSON / rulesFromJSON delegate to the domain codec (domain.EncodeRules /
// domain.DecodeRules) — the single source of truth for the roles.rules JSONB shape
// (snake_case, scalar module — CHECK iam_rules_valid, migrations 0025/0033). The seed
// layer (system-role selector projection) decodes the same shape via the same codec.
func rulesToJSON(rules domain.Rules) ([]byte, error) {
	return domain.EncodeRules(rules)
}

func rulesFromJSON(raw []byte) (domain.Rules, error) {
	return domain.DecodeRules(raw)
}

func (r *roleReader) Get(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM roles WHERE id = $1`, roleCols), string(id))
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return domain.Role{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetWithVersion returns the role + its xmin::text OCC token. roles
// has no version column, so the row's system xmin is the snapshot Role.Update
// echoes into UpdateCAS for the lost-update guard (the read-modify-write
// OCC-without-version-column pattern). xmin is selected first, then the canonical
// roleCols — scanRoleWithVersion prepends the xmin slot to the SAME destination
// list every other roleCols reader uses.
func (r *roleReader) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	var version string
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT xmin::text, %s FROM roles WHERE id = $1`, roleCols), string(id))
	out, err := scanRoleWithVersion(row, &version)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, "", iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return domain.Role{}, "", mapErr(err, "", string(id))
	}
	return out, version, nil
}

// UnresolvedSegments — сколько объявленных сегментов роли не имеют строки в
// проекции, которую читает вердикт.
//
// # Почему проба НА СЕГМЕНТ, а не одна выборка проекции страницы
//
// Форма выбрана замером, а не первым впечатлением. Хеш-полусоединение (одна
// выборка на страницу) выглядит вчетверо дешевле по блокам и СКАНИРУЕТ
// `role_verb` целиком — то есть дорожает с популяцией установки: при росте
// 2000 → 8000 ролей оно идёт 599 → 2015 блоков, тогда как форма ниже держится
// 2509 → 2511. Проба на сегмент вернее именно тем, чем на малой установке
// выглядит хуже: стоимость обязана следовать СТРАНИЦЕ, величина которой
// ограничена контрактом, а не популяции, которая не ограничена ничем.
//
// Каждая проба — поиск по `role_verb_pkey (role_id, object_type, verb)`;
// дополнительного индекса не требуется, ключ начинается с `role_id`.
//
// Пустой глагол — ЯКОРЬ (правило не сузило глаголы): годится любая строка
// своего типа. Это `d.verb = ”`, а не NULL: массивы приходят плотными.
func (r *roleReader) UnresolvedSegments(
	ctx context.Context, declared []domain.RoleSegment,
) (map[domain.RoleID][]domain.RoleSegment, error) {
	out := make(map[domain.RoleID][]domain.RoleSegment, len(declared))
	if len(declared) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(declared))
	types := make([]string, 0, len(declared))
	verbs := make([]string, 0, len(declared))
	for _, d := range declared {
		ids = append(ids, string(d.RoleID))
		types = append(types, d.ObjectType)
		verbs = append(verbs, d.Verb)
	}
	rows, err := r.tx.Query(ctx, `
		WITH d(role_id, object_type, verb) AS (
		  SELECT * FROM unnest($1::text[], $2::text[], $3::text[])
		)
		SELECT d.role_id, d.object_type, d.verb
		  FROM d
		 WHERE NOT EXISTS (
		   SELECT 1 FROM kaname.role_verb rv
		    WHERE rv.role_id     = d.role_id
		      AND rv.object_type = d.object_type
		      AND (d.verb = '' OR rv.verb = d.verb))`, ids, types, verbs)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var id, objectType, verb string
		if serr := rows.Scan(&id, &objectType, &verb); serr != nil {
			return nil, mapErr(serr, "", "")
		}
		rid := domain.RoleID(id)
		out[rid] = append(out[rid], domain.RoleSegment{RoleID: rid, ObjectType: objectType, Verb: verb})
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, mapErr(rerr, "", "")
	}
	return out, nil
}

// WithdrawnGrants — ЕДИНСТВЕННЫЙ путь чтения ведомости переселения (#1992).
//
// # Что было неверно
//
// Ведомость наполнялась применителем каталога и не читалась НИКЕМ: писателей
// два, читателей ноль. Заведена она затем, чтобы отобранное право было
// восстановимо и объяснимо, — и не давала этого, потому что цепочка обрывалась
// на пути чтения, а обрыв не наблюдался ниоткуда.
//
// # Почему ОДИН вопрос на страницу
//
// Тем же доводом, что у соседа выше: стоимость обязана следовать СТРАНИЦЕ,
// величина которой ограничена контрактом, а не популяции ролей, которая не
// ограничена ничем. Выборка идёт по началу первичного ключа ведомости
// (`role_id`), дополнительного индекса не требуется.
//
// # Почему исходное написание популяции НЕ уезжает наружу
//
// Столбец ведомости несёт написание закрытого набора схемы; наружу едет
// доменное состояние. Отдай мы строку как есть, написание схемы стало бы частью
// контракта чтения, и переименование столбца сделалось бы ломающим изменением.
// Неизвестное написание отвергается ОТКАЗОМ, а не молча становится нулевым
// состоянием: нулевое означает «не прочитано этим ответом», и выдать за него
// прочитанное-но-непонятое значило бы соврать ровно тем полем, которое эти два
// случая и разводит.
func (r *roleReader) WithdrawnGrants(
	ctx context.Context, roleIDs []domain.RoleID,
) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	out := make(map[domain.RoleID][]domain.WithdrawnGrant, len(roleIDs))
	if len(roleIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		ids = append(ids, string(id))
	}
	rows, err := r.tx.Query(ctx, `
		SELECT role_id, object_type, verb, source, reason, orphaned_at, applied_by, cause
		  FROM kaname.role_grant_orphan
		 WHERE role_id = ANY($1::text[])
		 ORDER BY role_id, object_type, verb, source, cause`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var id, source, cause string
		var g domain.WithdrawnGrant
		if serr := rows.Scan(&id, &g.ObjectType, &g.Verb, &source, &g.Reason,
			&g.WithdrawnAt, &g.AppliedBy, &cause); serr != nil {
			return nil, mapErr(serr, "", "")
		}
		// Причина читается ЗАКРЫТЫМ набором, без корзины «прочее»: непонятая
		// строка отвергается, а не выдаётся за невычисленную. Молча назвать её
		// «снят каталог» значило бы сказать арендатору, что при возврате
		// объявления она останется, — а этого мы не знаем.
		switch cause {
		case "catalog_retired":
			g.Cause = domain.WithdrawnGrantCauseCatalogRetired
		case "role_retired":
			g.Cause = domain.WithdrawnGrantCauseRoleRetired
		default:
			return nil, fmt.Errorf("ведомость переселения несёт неизвестную причину %q: "+
				"закрытый набор схемы разошёлся с разбором, и отдать такую строку "+
				"нулевой причиной значило бы выдать непонятое за невычисленное", cause)
		}
		switch source {
		case "role_verb":
			g.Source = domain.WithdrawnGrantSourceGrant
		case "rule_ref":
			g.Source = domain.WithdrawnGrantSourceRuleRef
		default:
			return nil, fmt.Errorf("ведомость переселения несёт неизвестную популяцию %q: "+
				"закрытый набор схемы разошёлся с разбором, и отдать такую строку "+
				"нулевым состоянием значило бы выдать непонятое за невычисленное", source)
		}
		g.WithdrawnAt = g.WithdrawnAt.Truncate(time.Second)
		out[domain.RoleID(id)] = append(out[domain.RoleID(id)], g)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, mapErr(rerr, "", "")
	}
	return out, nil
}

// PrunedSelectorTypes — ЕДИНСТВЕННЫЙ путь чтения ведомости вырезания (#1988).
//
// # Что было неверно
//
// Ведомость `role_selector_prune` наполнялась применителем каталога ТЕМ ЖЕ
// оператором, что вырезает, — и не читалась НИКЕМ: писатель один, прод-читателей
// ноль. Заведена она затем, чтобы необратимое вырезание перестало быть
// безмолвным, и не давала этого: цепочка обрывалась на пути чтения, а обрыв не
// наблюдался ниоткуда, потому что каждая половина по отдельности исправна.
//
// Это тот же класс и та же цена, что были у соседа выше: со стороны арендатора
// «правило перестало отбирать тип» неотличимо от «оно его и не отбирало».
//
// # Почему ОДИН вопрос на страницу
//
// Тем же доводом, что у обоих соседей: стоимость обязана следовать СТРАНИЦЕ,
// величина которой ограничена контрактом, а не популяции ролей, которая не
// ограничена ничем. Выборка идёт по началу первичного ключа ведомости
// (`role_id`), дополнительного индекса не требуется.
//
// # Почему DISTINCT, а не строка-в-строку
//
// Ведомость ключуется тройкой «роль + ОТПЕЧАТОК ПРАВИЛА + тип»: отпечаток нужен
// ХРАНЕНИЮ — без него два правила, потерявшие один тип, схлопнулись бы в одну
// строку, и второе вырезание осталось бы незаписанным. Читающему он не отдаётся
// (см. [domain.PrunedSelectorType]), поэтому строки, различавшиеся ТОЛЬКО им,
// для читающего есть ОДИН факт: отдай мы их как есть — арендатор увидел бы пару
// неотличимых записей об одном типе с одним исходом и прочёл бы её как дефект.
//
// Схлопывание безопасно ПО ПОСТРОЕНИЮ, а не по удаче: причина и момент
// функционально зависят от типа. Причина читается у той самой строки каталога,
// чьё снятие сделало элемент висячим, — она одна на точечный тип; момент есть
// время транзакции применения, а вернуться в отбор снятый тип не может — запись
// селектора, называющего неживой тип, отвергает страж живости. Значит две
// строки с одним типом и одним исходом совпадают и по остальным колонкам.
//
// АВТОР (#2005) входит в набор различения и кардинальности НЕ МЕНЯЕТ — по тому
// же доводу и в силу того же факта: он есть свойство ТРАНЗАКЦИИ применения, то
// есть функционально зависит от момента, который в наборе уже стоит. Две строки,
// совпавшие по типу, исходу и моменту, пришли из одного применения, а у одного
// применения автор один. Добавь он различий — это означало бы, что момент их не
// различил, то есть что вырезание одного типа случилось дважды в одну
// транзакцию; такого входа нет by construction.
//
// # Почему написание исхода НЕ уезжает наружу
//
// Столбец несёт написание закрытого набора схемы; наружу едет доменное
// состояние. Отдай мы строку как есть, написание столбца стало бы частью
// контракта чтения. Неизвестное написание отвергается ОТКАЗОМ, а не молча
// становится нулевым состоянием: нулевое означает «не прочитано этим ответом», и
// выдать за него прочитанное-но-непонятое значило бы соврать ровно тем полем,
// которое эти два случая и разводит.
//
// # Отсутствие причины отдаётся ПУСТОЙ строкой, и это не потеря
//
// Колонка нуллируема намеренно: под вырезание попадают и элементы, повисшие до
// заведения применителя, а строки каталога, снятые ранними миграциями, причины
// не несут. NULL там означает «строка каталога причины не несла» — то же самое,
// что пустая строка у читающего, и второго состояния здесь не требуется.
func (r *roleReader) PrunedSelectorTypes(
	ctx context.Context, roleIDs []domain.RoleID,
) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	out := make(map[domain.RoleID][]domain.PrunedSelectorType, len(roleIDs))
	if len(roleIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		ids = append(ids, string(id))
	}
	rows, err := r.tx.Query(ctx, `
		SELECT DISTINCT role_id, object_type, outcome,
		       coalesce(retired_reason, ''), pruned_at, applied_by
		  FROM kaname.role_selector_prune
		 WHERE role_id = ANY($1::text[])
		 ORDER BY role_id, object_type, outcome`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var id, outcome string
		var p domain.PrunedSelectorType
		if serr := rows.Scan(&id, &p.ObjectType, &outcome, &p.Reason, &p.PrunedAt,
			&p.AppliedBy); serr != nil {
			return nil, mapErr(serr, "", "")
		}
		switch outcome {
		case "shortened":
			p.Outcome = domain.SelectorPruneOutcomeShortened
		case "dropped":
			p.Outcome = domain.SelectorPruneOutcomeDropped
		default:
			return nil, fmt.Errorf("ведомость вырезания несёт неизвестный исход %q: "+
				"закрытый набор схемы разошёлся с разбором, и отдать такую строку "+
				"нулевым состоянием значило бы выдать непонятое за невычисленное", outcome)
		}
		p.PrunedAt = p.PrunedAt.Truncate(time.Second)
		out[domain.RoleID(id)] = append(out[domain.RoleID(id)], p)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, mapErr(rerr, "", "")
	}
	return out, nil
}

func (r *roleReader) List(ctx context.Context, f role.ListFilter) ([]domain.Role, string, error) {
	// page_size>MaxPageSize → InvalidArgument (no silent clamp); 0 → default.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1
	if f.AccountID != "" {
		// scope: system roles (catalog floor) OR this Account's custom roles.
		// System roles carry account_id IS NULL, so a plain `account_id = $X`
		// would wrongly drop them — keep them via the is_system disjunct.
		conditions = append(conditions, fmt.Sprintf("(is_system OR account_id = $%d)", argIdx))
		args = append(args, string(f.AccountID))
		argIdx++
	}
	if f.IsSystem != nil {
		conditions = append(conditions, fmt.Sprintf("is_system = $%d", argIdx))
		args = append(args, *f.IsSystem)
		argIdx++
	}
	if f.Filter != "" {
		// Whitelist `name="value"`; anything else is refused by name, never
		// accepted-and-ignored (#445). The predicate is built from the parsed
		// expression, so the column follows the whitelist instead of being
		// restated here and drifting from it.
		ast, ferr := parseListFilter(f.Filter, "name")
		if ferr != nil {
			return nil, "", ferr
		}
		if ast != nil {
			frag, fargs := ast.ToSQL(argIdx)
			conditions = append(conditions, frag)
			args = append(args, fargs...)
			argIdx += len(fargs)
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

	// Сужение набора КАНДИДАТОВ (задача #645), с ПОЛОМ этой поверхности внутри
	// условия отбора.
	//
	// `is_system` стоит здесь, а не в постфильтре, и это не оптимизация: каталог
	// системных ролей — самые старые строки таблицы и сам по себе заполняет
	// страницу по умолчанию. Пол, применённый ПОСЛЕ взятия окна, превращается в
	// «строка видна, если она в окно попала», то есть ровно в исходный дефект —
	// на этой поверхности наступавший с первого дня, без всякого населения.
	//
	// Системная роль несёт `account_id IS NULL`, поэтому `account_id = ANY(…)`
	// её не выбирает НИКОГДА: дизъюнкт обязателен, а не подстрахован.
	//
	// nil — не сужать (администратор облака); непустой указатель с пустыми
	// наборами оставляет только пол.
	if f.Candidates != nil {
		conditions = append(conditions,
			fmt.Sprintf("(is_system OR account_id = ANY($%d) OR id = ANY($%d))", argIdx, argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM roles %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		roleCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		ro, err := scanRole(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ro)
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

// ListAssignable — roles assignable on (resourceType, resourceID) per the
// assignability matrix. The WHERE clause is the SQL mirror of
// domain.IsRoleAssignable so keyset pagination stays correct over the filtered
// set:
//
//	system roles (is_system)                         → always
//	account-scoped custom (account_id = $resourceID) → only when type=account
//	project-scoped custom (project_id = $resourceID) → only when type=project
//	cluster                                          → system only
//
// resourceType is account|project|cluster (the use-case validates the whitelist
// + id format before calling). An unknown type yields system-only (defensive).
func (r *roleReader) ListAssignable(ctx context.Context, resourceType, resourceID string, f role.ListFilter) ([]domain.Role, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}

	// scopePred — the assignability predicate beyond is_system. For cluster
	// (and any non-account/project type) only system roles qualify, so the
	// extra disjunct is `false`.
	args := []any{}
	argIdx := 1
	var scopePred string
	switch resourceType {
	case "account":
		scopePred = fmt.Sprintf("(account_id = $%d)", argIdx)
		args = append(args, resourceID)
		argIdx++
	case "project":
		scopePred = fmt.Sprintf("(project_id = $%d)", argIdx)
		args = append(args, resourceID)
		argIdx++
	default:
		scopePred = "(false)"
	}

	conditions := []string{fmt.Sprintf("(is_system = true OR %s)", scopePred)}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM roles WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		roleCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		ro, serr := scanRole(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, ro)
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

type roleWriter struct {
	roleReader
}

// Insert — только custom-role (caller гарантирует is_system=false + exactly one
// of account_id / project_id set). Persists BOTH the authored rules (rules
// JSONB — public authority) and the caller-supplied compiled permissions
// (internal, derived from rules by the use-case in the same writer-tx; never
// recomputed in SQL — drift hazard). account_id / project_id are written via
// NULLIF($, ”) so the unset scope column is stored NULL (not ”) — required by
// the roles_definition_tier_xor CHECK and the roles_acc/prj_custom_unique partial indexes,
// and by the account_id/project_id FK (an ” would dangle).
func (w *roleWriter) Insert(ctx context.Context, r domain.Role) (domain.Role, error) {
	permsJSON, err := json.Marshal(stringSlice(r.Permissions))
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument permissions: %s", err.Error())
	}
	rulesJSON, err := rulesToJSON(r.Rules)
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument rules: %s", err.Error())
	}
	// labels — tenant-facing метки самого ресурса Role (own-resource); НЕ путать
	// с Rule.MatchLabels (object-selector внутри правила). Делают Role label-selectable.
	labelsJSON, err := marshalLabels(r.Labels)
	if err != nil {
		return domain.Role{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	// redesign-2026 F4: is_system is a GENERATED column (derived from cluster_id) —
	// it is NEVER inserted explicitly (Postgres rejects a non-DEFAULT value into a
	// generated column). Custom roles set account_id XOR project_id, cluster_id NULL,
	// so the generated is_system evaluates to false. System roles are seeded only.
	q := fmt.Sprintf(`
		INSERT INTO roles (id, account_id, project_id, name, description, permissions, rules, created_at, updated_at, labels)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7, $8, $8, $9)
		RETURNING %s`, roleCols)
	// `$8` стоит дважды намеренно: роль, которую никто не правил, «правлена» в
	// момент своего появления, и обе метки обязаны быть ОДНОЙ величиной, а не
	// двумя чтениями часов — иначе `updated_at` у свежей строки оказывается
	// позже `created_at` на случайную дельту, и сравнение «правилась ли роль»
	// перестаёт быть выразимым.
	row := w.tx.QueryRow(ctx, q,
		string(r.ID), string(r.AccountID), string(r.ProjectID), string(r.Name), string(r.Description),
		permsJSON, rulesJSON, now, labelsJSON,
	)
	out, err := scanRole(row)
	if err != nil {
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// UpsertSystemRole — единственный писатель строки СИСТЕМНОЙ роли, не
// являющийся миграцией (приёмка `roles-come-as-data-not-migrations.md` §3.1,
// §3.5).
//
// # Почему отдельный оператор, а не `Insert`
//
// `Insert` выше системную роль произвести НЕ МОЖЕТ: `cluster_id` в его перечне
// колонок отсутствует, а `is_system` вычисляется ровно из него
// (`GENERATED ALWAYS AS (cluster_id IS NOT NULL) STORED`, миграция 0056). Это не
// дефект `Insert`, а решение: путь пользовательской роли не вправе писать
// кластерный ярус.
//
// # `is_system` в перечне колонок ОТСУТСТВУЕТ намеренно
//
// Вставка значения в вычисляемую колонку — ошибка 428C9. Ярус задаётся
// непустым `cluster_id`, и только им.
//
// # Приведение — при отличии, и это свойство ОПЕРАТОРА
//
// Предикат отличия стоит в `WHERE` ветви `DO UPDATE`: совпало всё — строк
// затронуто ноль, `RETURNING` пуст, вызывающий получает `changed=false`.
// Сравнение в коде было бы software check-then-act (запрет #10).
//
// `labels` и `created_at` приведением НЕ трогаются: манифест их не объявляет,
// и стирать метки арендатора значило бы объявить владение тем, чего манифест не
// несёт.
//
// # Время правки эта строка НЕСЁТ — и цена ошибки здесь измерена
//
// Столбца `kaname.roles.updated_at` не существовало, а присваивание
// `updated_at = $7` здесь стояло. Неизвестный столбец в `ON CONFLICT DO UPDATE
// SET` — ошибка РАЗБОРА всего оператора (`42703`), а не его ветви: отказ
// приходил на первом же вызове, включая вставку, и применитель не записал бы ни
// одной роли ни при каком входе.
//
// Появилось присваивание не само: его породил комментарий соседнего писателя,
// утверждавший «`updated_at` is bumped on every applied mutation». Это класс
// `architecture.md` §doc-truthfulness в чистом виде — следующий читатель чинит
// КОД под неверный текст.
//
// Столбец с тех пор ЗАВЕДЁН — новой миграцией, как этот абзац и предписывал
// (задача #1873): `roleCols` его выбирает, путь чтения заполняет, и здесь он
// присваивается в обеих ветвях — при вставке одной величиной с `created_at`, при
// конфликте из `EXCLUDED`. Присваивание стоит ВНУТРИ `DO UPDATE SET`, а значит
// под тем же предикатом отличия: повторное применение неизменившейся роли строку
// не трогает и метку не двигает.
//
// Держится это `module_role_upsert_integration_test.go`: оператор доводится до
// настоящего сервера. Дублёр писателя (`moduleroles/apply_test.go`) перечня
// столбцов не видит НИКОГДА — он переписывает семантику на Go, и потому был
// зелёным при неисполнимом операторе.
func (w *roleWriter) UpsertSystemRole(ctx context.Context, r domain.Role) (domain.Role, bool, error) {
	permsJSON, err := json.Marshal(stringSlice(r.Permissions))
	if err != nil {
		return domain.Role{}, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument permissions: %s", err.Error())
	}
	rulesJSON, err := rulesToJSON(r.Rules)
	if err != nil {
		return domain.Role{}, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument rules: %s", err.Error())
	}
	labelsJSON, err := marshalLabels(r.Labels)
	if err != nil {
		return domain.Role{}, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO roles (id, cluster_id, name, description, permissions, rules, owner_module, created_at, updated_at, labels)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8, $9)
		ON CONFLICT (id) DO UPDATE
		   SET name         = EXCLUDED.name,
		       description  = EXCLUDED.description,
		       permissions  = EXCLUDED.permissions,
		       rules        = EXCLUDED.rules,
		       owner_module = EXCLUDED.owner_module,
		       updated_at   = EXCLUDED.updated_at
		 WHERE roles.name         IS DISTINCT FROM EXCLUDED.name
		    OR roles.description  IS DISTINCT FROM EXCLUDED.description
		    OR roles.permissions  IS DISTINCT FROM EXCLUDED.permissions
		    OR roles.rules        IS DISTINCT FROM EXCLUDED.rules
		    OR roles.owner_module IS DISTINCT FROM EXCLUDED.owner_module
		RETURNING %s`, roleCols)
	// Владелец пишется как ОТСУТСТВИЕ, а не как пустая строка: ключ на каталог
	// однокомпонентный, и `NULL` под него не подпадает by construction, тогда как
	// `''` искал бы в каталоге модуль с пустым именем и отвергался бы ключом.
	var owner *string
	if r.OwnerModule != "" {
		owner = &r.OwnerModule
	}
	row := w.tx.QueryRow(ctx, q,
		string(r.ID), string(r.ClusterID), string(r.Name), string(r.Description),
		permsJSON, rulesJSON, owner, now, labelsJSON,
	)
	out, err := scanRole(row)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Конфликт по первичному ключу случился, а предикат отличия оказался
		// ложным: объявленное состояние уже стоит в строке. Это ШТАТНЫЙ исход
		// повторного применения, а не отказ.
		return domain.Role{}, false, nil
	case err != nil:
		return domain.Role{}, false, mapErr(err, "", string(r.Name))
	}
	return out, true, nil
}

// Update — UPDATE на mutable полях. Custom-role: name (с UNIQUE check),
// description, permissions. System-role caller отвергает на use-case-уровне.
func (w *roleWriter) Update(ctx context.Context, r domain.Role, updateMask []string) (domain.Role, error) {
	args, changed, err := roleUpdateArgs(r, updateMask)
	if err != nil {
		return domain.Role{}, err
	}
	if !changed {
		return w.Get(ctx, r.ID)
	}
	row := w.tx.QueryRow(ctx, roleUpdateQ, args...)
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", r.ID)
		}
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// UpdateCAS — Update guarded by an xmin OCC token. It builds the same
// mutable-field SET list as Update, then appends `AND xmin::text = $expected` to the
// WHERE so two concurrent Role.Updates cannot both commit a fan-out derived from
// their own role projection (ledger↔FGA drift). The row-lock serializes them: the
// loser reads the SAME expected version, finds xmin bumped, RETURNING yields 0 rows
// → pgx.ErrNoRows → ErrFailedPrecondition (the caller rolls back its whole writer-tx
// — UPDATE + reconcile fan-out — together, ban #10). expectedVersion=="" skips the
// predicate (unconditional last-writer Update, back-compat). A 0-row result with a
// non-empty token is OCC loss OR not-found; both surface as FailedPrecondition (the
// use-case loaded the role on the sync path, so not-found here means it raced away).
func (w *roleWriter) UpdateCAS(ctx context.Context, r domain.Role, updateMask []string, expectedVersion string) (domain.Role, error) {
	if expectedVersion == "" {
		return w.Update(ctx, r, updateMask)
	}
	args, _, err := roleUpdateArgs(r, updateMask)
	if err != nil {
		return domain.Role{}, err
	}
	// Пустая маска НЕ выводит из-под сторожа: оператор исполняется с ложными
	// признаками применимости, то есть переписывает строку теми же значениями.
	// Это и есть прежний «re-touch» — версия сверяется, xmin двигается для
	// наблюдателей, а метка правки НЕ трогается (её признак тоже ложен), потому
	// что правки не было.
	args = append(args, expectedVersion)
	row := w.tx.QueryRow(ctx, roleUpdateCASQ, args...)
	out, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Stable contract text — capital "Role" to match
			// the use-case OCC text in role.update.go (register unified).
			return domain.Role{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"Role was modified concurrently, retry")
		}
		return domain.Role{}, mapErr(err, "", string(r.Name))
	}
	return out, nil
}

// ─── Запись роли: набор колонок известен КОМПИЛЯТОРУ ────────────────────────
//
// Оператор СТАТИЧЕСКИЙ, и это несущее свойство, а не стиль (задача продукта
// #2058). Прежде список `SET` собирался из маски форматированием строки: какие
// колонки пишет оператор, решалось во время исполнения и не проверялось ни
// типами, ни компилятором. Ошибка такой сборки не видна ни сборке, ни обзору
// диффа — только прогону, дошедшему до этой ветви маски.
//
// Применимость поля переехала из ТЕКСТА оператора в его ПАРАМЕТР: каждой
// изменяемой колонке отвечает пара «признак применимости + значение», и колонка,
// которую маска не назвала, переписывается сама в себя. Наблюдаемо это
// тождественно прежнему поведению — писалось ровно то же значение, — а разница в
// том, что перечень колонок теперь один и он в коде.
//
// Метка правки — такая же пара, и её признак ЛОЖЕН на пустой правке. Условие
// несущее: `Update` на пустом перечне уходит в `Get`, не выполняя оператора
// вовсе, а `UpdateCAS` оператор исполняет (сторож версии обязан отработать) —
// и метка при этом двигаться не должна, иначе `updated_at` перестал бы означать
// правку.
const roleUpdateSetSQL = `
	       name        = CASE WHEN $2::boolean  THEN $3::text        ELSE name        END,
	       description = CASE WHEN $4::boolean  THEN $5::text        ELSE description END,
	       rules       = CASE WHEN $6::boolean  THEN $7::jsonb       ELSE rules       END,
	       permissions = CASE WHEN $8::boolean  THEN $9::jsonb       ELSE permissions END,
	       labels      = CASE WHEN $10::boolean THEN $11::jsonb      ELSE labels      END,
	       updated_at  = CASE WHEN $12::boolean THEN $13::timestamptz ELSE updated_at END`

const roleUpdateQ = `UPDATE roles SET` + roleUpdateSetSQL +
	` WHERE id = $1 RETURNING ` + roleCols

const roleUpdateCASQ = `UPDATE roles SET` + roleUpdateSetSQL +
	` WHERE id = $1 AND xmin::text = $14 RETURNING ` + roleCols

// roleUpdateUnknownField — единственное место, где маска отвергается; текст
// конвенционный и остаётся частью контракта.
func roleUpdateUnknownField(f string) error {
	return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument update_mask field %q", f)
}

// roleUpdateArgs — аргументы статического оператора записи роли в порядке
// подстановок, начиная с `$1`.
//
// changed=false означает «маска не назвала ни одного изменяемого поля»:
// вызывающий решает сам, исполнять ли оператор (сторож версии — да, обычная
// запись — нет).
//
// `rules` — авторская изменяемая форма; когда она названа, use-case уже
// перекомпилировал `permissions` из новых правил, и обе колонки пишутся в одной
// транзакции писателя, чтобы хранимый скомпилированный набор не разошёлся с
// авторитетом. Отсюда следование: названы правила ⇒ названы и права.
//
// Время правки берётся из тех же часов, что `created_at` у вставки (время
// процесса, не `now()` сервера): две метки одной строки, сравниваемые между
// собой, обязаны приходить из одного источника, иначе расхождение часов делает
// `updated_at < created_at` представимым.
func roleUpdateArgs(r domain.Role, updateMask []string) (args []any, changed bool, err error) {
	mutableFields := map[string]bool{
		"name": true, "description": true, "permissions": true, "rules": true, "labels": true,
	}
	apply := map[string]bool{}
	if len(updateMask) == 0 {
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range updateMask {
			if !mutableFields[f] {
				return nil, false, roleUpdateUnknownField(f)
			}
			apply[f] = true
		}
	}
	// Editing rules implies re-storing the compiled permissions projection.
	if apply["rules"] {
		apply["permissions"] = true
	}

	// Значение готовится ТОЛЬКО для названного поля: отказ разбора принадлежит
	// полю, которое вызывающий действительно прислал, а не всякому обновлению.
	var rulesJSON, permsJSON, labelsJSON []byte
	if apply["rules"] {
		if rulesJSON, err = rulesToJSON(r.Rules); err != nil {
			return nil, false, iamerr.Wrapf(iamerr.ErrInvalidArg,
				"Illegal argument rules: %s", err.Error())
		}
	}
	if apply["permissions"] {
		if permsJSON, err = json.Marshal(stringSlice(r.Permissions)); err != nil {
			return nil, false, iamerr.Wrapf(iamerr.ErrInvalidArg,
				"Illegal argument permissions: %s", err.Error())
		}
	}
	// labels — own-resource tenant-facing метки; mutable наравне с name/rules.
	if apply["labels"] {
		if labelsJSON, err = marshalLabels(r.Labels); err != nil {
			return nil, false, iamerr.Wrapf(iamerr.ErrInvalidArg,
				"Illegal argument labels: %s", err.Error())
		}
	}

	changed = apply["name"] || apply["description"] || apply["rules"] ||
		apply["permissions"] || apply["labels"]

	return []any{
		string(r.ID),
		apply["name"], string(r.Name),
		apply["description"], string(r.Description),
		apply["rules"], rulesJSON,
		apply["permissions"], permsJSON,
		apply["labels"], labelsJSON,
		changed, time.Now().UTC(),
	}, changed, nil
}

// Delete — the in-use invariant is enforced at the DB level by the FK
// access_bindings_role_fk ON DELETE RESTRICT (ban #10): an unconditional
// DELETE of a role still carrying ANY binding row raises SQLSTATE 23503, mapped to
// FAILED_PRECONDITION "role is in use by access bindings" (no software
// check-then-act / TOCTOU, no pgx leak). The FK fires regardless of the binding's
// status; AccessBindingService.Delete is a HARD delete (purges the row), which is
// what clears the precondition (the text is intentionally not qualified "active").
// The is_system and not-found cases are
// business-state discriminations (NOT FK-expressible), so the DELETE is guarded
// `is_system = false` and a 0-row result is probed to distinguish:
//
//	system role          → FAILED_PRECONDITION "System role ... cannot be deleted"
//	role does not exist  → NOT_FOUND
//
// The single-statement DELETE holds the row-lock, so a concurrent grant on the
// same role serializes and either commits before (this DELETE then trips the FK)
// or after (the grant's FK insert sees the deleted role and fails) — second-
// writer never wins.
func (w *roleWriter) Delete(ctx context.Context, id domain.RoleID) error {
	row := w.tx.QueryRow(ctx,
		`DELETE FROM roles WHERE id = $1 AND is_system = false RETURNING 1`, string(id))
	var one int
	err := row.Scan(&one)
	if err == nil {
		return nil // exactly one custom role deleted
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		// FK RESTRICT (23503) on a still-bound role lands here → FailedPrecondition
		// with the canonical text via the "Role.Delete" kindHint (no constraint/pgx leak).
		return mapErr(err, "Role.Delete", string(id))
	}
	// 0 rows deleted: either system role or non-existent. Probe to discriminate.
	var isSystem bool
	perr := w.tx.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, string(id)).Scan(&isSystem)
	if perr != nil {
		if errors.Is(perr, pgx.ErrNoRows) {
			return iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return mapErr(perr, "Role.Delete", string(id))
	}
	if isSystem {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "System role %s cannot be deleted", id)
	}
	// Custom role exists but the guarded DELETE matched 0 rows — should not happen
	// (the only guard is is_system=false). Treat as not-found defensively.
	return iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
}

// ReplaceRuleSelectors syncs role_rule_selectors with the role's UNIFIED
// materializing rules (flat explicit RBAC model): ARM_ANCHOR(all) +
// ARM_NAMES + ARM_LABELS. DELETE-all-then-INSERT keyed by role_id inside the caller
// tx, so a removed/edited rule drops/replaces its selector atomically with the rules
// change (ban #10). A rule whose dotted-types are empty (wildcard `*.*` system form,
// served by the cluster super-admin short-circuit) is NOT persisted — it materializes nothing.
// ReplaceRoleVerbs заменяет проекцию «роль → тип объекта × глагол».
//
// ПОЛНАЯ ЗАМЕНА, а не досыпка: проекция есть СОСТОЯНИЕ роли, и глагол, снятый из
// разрешений, обязан исчезнуть отсюда. Досыпка означала бы, что отзыв права не
// применяется, — причём молча, потому что добавление проходит успешно и ни одна
// проверка «строки записаны» этого не заметит.
//
// Пары приходят от вызывающего уже переведёнными: перевод «точечное разрешение →
// тип модели + глагол» — это код (закрытый каталог типов, приведение имени), и
// повторять его в SQL значило бы завести второе место, знающее соответствие.
//
// # Пустую пару отвергает БАЗА, и своей проверки здесь НЕТ намеренно
//
// Пустое поле пары отводят ограничения `role_verb_type_nonempty` и
// `role_verb_verb_nonempty` (миграция 0085) — то есть инвариант выражен
// конструкцией хранилища, как того и требует запрет #10, а не проверкой в коде.
//
// Здесь стояла своя проверка, и она была не просто дубликатом: её предикат —
// строгое подмножество ограничений (третьего, канонической формы глагола, она не
// знала вовсе), а стояла она ДО вставки и потому ЗАСЛОНЯЛА ответ базы своим.
// Замер обеих полос на одном входе: своя проверка отдавала `*errors.errorString`
// без sentinel'а («role_verb: пустая пара»), база отдаёт `ErrInvalidArg`. Отказ
// проверки входа приезжал вызывающему неклассифицированным — то есть доезжал бы
// до края фиксированным INTERNAL, сообщая о поломке службы там, где вызывающий
// прислал негодный вход и в силах его починить.
//
// Свойство держит проба контракта `TestIAMRV109_EmptyPairIsRefusedAndNothingIsWritten`,
// и утверждает она НАБЛЮДАЕМОЕ — код отказа и состояние проекции, — а не то,
// какой слой ответил. Поэтому проверка, заведённая здесь снова и отвечающая
// иначе, покраснеет.
func (w *roleWriter) ReplaceRoleVerbs(ctx context.Context, roleID domain.RoleID, pairs []domain.RoleVerb) error {
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM kaname.role_verb WHERE role_id = $1`, string(roleID)); err != nil {
		return mapErr(err, "", string(roleID))
	}
	for _, pv := range pairs {
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO kaname.role_verb (role_id, object_type, verb)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (role_id, object_type, verb) DO NOTHING`,
			string(roleID), pv.ObjectType, pv.Verb,
		); err != nil {
			return mapErr(err, "", string(roleID))
		}
	}
	return nil
}

// ReplaceRuleRefs заменяет проекцию ОБЪЯВЛЕННЫХ сегментов правила роли.
//
// ПОЛНАЯ ЗАМЕНА, как и у проекции глаголов: сегмент, снятый из правил, обязан
// исчезнуть отсюда, иначе ключ продолжал бы держать строку каталога, которую
// роль больше не называет.
//
// # Своей проверки каталога здесь НЕТ намеренно
//
// Существование сегмента судит БАЗА — ключи `role_rule_ref_res_fk` и
// `role_rule_ref_verb_fk`. Проверка в коде была бы software check-then-act
// (запрет #10): между «спросить каталог» и «записать правило» помещается снятие
// ресурса, и правило пережило бы свой референт. Тот же порядок, что у
// `ReplaceRoleVerbs` после #1028.
//
// # Подсказка ставится ПООПЕРАТОРНО, и это не стиль
//
// Отказ ключа называет ПОЛЕ (по имени ограничения, ветвь `fkText`) и ТОКЕН.
// Токен из ошибки драйвера взять нельзя: единственный его носитель —
// `pgErr.Detail`, а `fkText` не читает его намеренно (защита от разведки схемы).
// Значит токен обязан прийти от писателя — и прийти ТОТ САМЫЙ: правило несёт N
// сегментов, а сказать надо про нарушивший. Носители подсказки уровня транзакции
// (`ownerFKHint`, `membershipHint`) этого не дают by construction — они по
// одному значению на транзакцию. Вставка идёт ПО СТРОКЕ, поэтому в момент отказа
// писатель держит ровно один сегмент, и подсказка однозначна.
//
// Работает это ТОЛЬКО при немедленной форме ключа (`DEFERRABLE INITIALLY
// IMMEDIATE`, миграция 20260901113757): при отложенной оператор уже завершился успехом,
// и подсказывать некому.
func (w *roleWriter) ReplaceRuleRefs(ctx context.Context, roleID domain.RoleID, refs []domain.RoleRuleRef) error {
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM kaname.role_rule_ref WHERE role_id = $1`, string(roleID)); err != nil {
		return mapErr(err, "", string(roleID))
	}
	for _, ref := range refs {
		var verb any
		if !ref.IsAnchor() {
			verb = ref.Verb
		}
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO kaname.role_rule_ref (role_id, module, resource, verb)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT DO NOTHING`,
			string(roleID), ref.Module, ref.Resource, verb,
		); err != nil {
			// Подсказка — ТОТ САМЫЙ токен, на котором отказал оператор. Какой
			// сегмент назвать, решает ветвь `fkText` по имени ограничения; здесь
			// подаются оба, потому что писатель не знает, который из двух ключей
			// сработал, и гадать об этом ему не положено.
			return mapErr(err, "", ruleRefHint(ref))
		}
	}
	return nil
}

// ruleRefHint — подсказка вида «resource\x1fverb» для одного оператора вставки.
// Разделитель — тот же приём, что у подсказки выдачи (`splitBindingHint`):
// значений два, а носитель у `mapErr` один.
func ruleRefHint(ref domain.RoleRuleRef) string {
	return ref.Resource + ruleRefHintSep + ref.Verb
}

// ruleRefHintSep — разделитель половин подсказки. Токен правила его содержать не
// может: грамматика сегмента (`ruleResRe`/`ruleVerbRe`) допускает только буквы,
// цифры, дефис и подчёркивание.
const ruleRefHintSep = "\x1f"

// splitRuleRefHint — обратная сторона `ruleRefHint`. Подсказка без разделителя
// возвращается как ресурс: так ветвь `fkText` остаётся годной, если её позовут с
// подсказкой другой формы.
func splitRuleRefHint(hint string) (resource, verb string) {
	if i := strings.Index(hint, ruleRefHintSep); i >= 0 {
		return hint[:i], hint[i+len(ruleRefHintSep):]
	}
	return hint, ""
}

// ReplaceRuleSelectors заменяет проекцию селекторов правила роли ПОЛНОСТЬЮ.
//
// # Замки на строки каталога берутся ПЕРВЫМИ (задача продукта #1996)
//
// Страж живости селектора читает строку каталога под `FOR KEY SHARE` (миграция
// `20260903181000`), и без этого предварительного запроса замок на неё
// брался бы ВНУТРИ вставки — то есть ПОСЛЕ замка на строках селекторов, снятых
// удалением выше. Порядок оказывался обратным порядку применителя каталога
// (строка каталога → строки селекторов), и пара давала взаимную блокировку.
//
// Цена инверсии измерена, а не предположена: Postgres обнаруживал пару и
// отвергал СТОРОНУ АРЕНДАТОРА — применитель доходил до конца, а правка правил
// роли получала `40P01`, приезжавший вызывающему как `ABORTED`
// «conflicting concurrent change, retry the request». То есть цену платил не
// тот, кто инверсию создаёт, повтор без правки условия ничего не менял, а
// условие наступления от арендатора не зависело вовсе.
//
// # Это НЕ вторая проверка живости, и путать нельзя
//
// Запрос ничего не отвергает: ноль строк — законный исход, и решение о нём
// принимает страж, как и раньше. Берётся РОВНО ТОТ ЖЕ набор строк, что возьмёт
// страж (`dotted = <элемент> AND live`), поэтому второго словаря живости здесь
// не заводится, а замок, взятый вперёд, к моменту вставки уже держится.
//
// Порядок внутри набора — по `dotted`: `ORDER BY` стоит под захватом строк,
// поэтому набор берётся детерминированно, а не в порядке обхода индекса.
//
// # Граница СНЯТА: перекрёстный порядок по нескольким типам закрыт (#2012)
//
// Здесь стояло «не закрыто», и его довод был НЕВЕРЕН: снимаемые строки приходят
// из `ReadModule` (`ORDER BY resource`) и фильтруются `Withdrawn` с сохранением
// порядка — то есть порядок операторов снятия задавала не разница манифестов.
// Инверсия жила между ДВУМЯ проходами применителя: объявленные он брал на
// upsert'е, снимаемые на retire, и снимаемое имя, сортирующееся раньше
// сохраняемого, доставалось ему последним.
//
// Применитель берёт теперь замки на строки ресурсов модуля ОДНИМ оператором и
// тем же `ORDER BY dotted` (`catalogWriter.LockModuleResources`), до первой
// записи. Порядок у обеих сторон назначает БАЗА, и расхождение перестало быть
// представимым. Утверждает это проба, ставящая обе стороны в гонку на двух
// типах, названных в обратном порядке
// (`catalog_applier_lock_order_integration_test.go`), — прочитать порядок
// нельзя, он есть свойство исполнения.
func (w *roleWriter) ReplaceRuleSelectors(ctx context.Context, roleID domain.RoleID, selectors []domain.RuleSelector) error {
	if types := lockedCatalogTypesOf(selectors); len(types) > 0 {
		if _, err := w.tx.Exec(ctx, `
			SELECT 1 FROM kaname.catalog_resource
			 WHERE dotted = ANY($1) AND live
			 ORDER BY dotted
			   FOR KEY SHARE`, types); err != nil {
			return mapErr(err, "", string(roleID))
		}
	}
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM kaname.role_rule_selectors WHERE role_id = $1`, string(roleID)); err != nil {
		// Route SQLSTATE → sentinel (mapErr) rather than bare fmt.Errorf(%w) so a
		// constraint violation maps to the right gRPC code and no pgx text leaks.
		return mapErr(err, "", string(roleID))
	}
	for _, sel := range selectors {
		// A wildcard-only rule projects to zero dotted-types (cluster super-admin
		// `*.*` short-circuit) — nothing to materialize per-object, skip it.
		if len(sel.ObjectTypes) == 0 {
			continue
		}
		labelsJSON, err := json.Marshal(sel.MatchLabels)
		if err != nil {
			return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument matchLabels: %s", err.Error())
		}
		if string(labelsJSON) == "null" {
			labelsJSON = []byte("{}")
		}
		// pgx encodes a nil []string as SQL NULL, which violates the NOT NULL column
		// (DEFAULT applies only when the column is OMITTED, not when NULL is passed
		// explicitly). Normalize to an empty array so an anchor/labels selector (no
		// names) stores '{}'.
		resourceNames := sel.ResourceNames
		if resourceNames == nil {
			resourceNames = []string{}
		}
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO kaname.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6::jsonb, now(), now())
			 ON CONFLICT (role_id, rule_fp) DO UPDATE
			    SET arm            = EXCLUDED.arm,
			        object_types   = EXCLUDED.object_types,
			        resource_names = EXCLUDED.resource_names,
			        match_labels   = EXCLUDED.match_labels,
			        updated_at     = now()`,
			string(roleID), sel.RuleFP, armText(sel.Arm), sel.ObjectTypes, resourceNames, labelsJSON,
		); err != nil {
			// A CHECK violation (23514 — e.g. match_labels fails kacho_labels_valid)
			// must surface as InvalidArgument, not INTERNAL; mapErr also keeps the pgx
			// constraint text from leaking to the caller.
			return mapErr(err, "", string(roleID))
		}
	}
	return nil
}

// lockedCatalogTypesOf — точечные имена, чьи строки каталога возьмёт страж
// живости: объединение `ObjectTypes` тех селекторов, которые действительно
// пойдут во вставку.
//
// Селектор с пустым набором типов пропускается вставкой (правило-подстановка
// проецируется в ноль типов), поэтому его имена сюда не попадают: замок на
// строку, которую никто не спросит, был бы лишней сериализацией.
//
// Набор отсортирован и лишён повторов: правило вправе назвать один тип дважды,
// а замок на него один.
func lockedCatalogTypesOf(selectors []domain.RuleSelector) []string {
	seen := make(map[string]struct{})
	for _, sel := range selectors {
		if len(sel.ObjectTypes) == 0 {
			continue
		}
		for _, t := range sel.ObjectTypes {
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// armText maps the domain Arm to the role_rule_selectors.arm enum text.
func armText(a domain.Arm) string {
	switch a {
	case domain.ArmNames:
		return "names"
	case domain.ArmLabels:
		return "labels"
	default:
		return "anchor"
	}
}

// ---- helpers ---------------------------------------------------------------

func scanRole(row scanner) (domain.Role, error) {
	return scanRoleWithVersion(row)
}

// scanRolePolicy decodes the permissions + rules JSONB columns into the role.
// A legacy permissions-only role (rules='[]') yields ro.Rules == nil/empty.
func scanRolePolicy(ro *domain.Role, permsJSON, rulesJSON []byte) error {
	var perms []string
	if err := json.Unmarshal(permsJSON, &perms); err != nil {
		return fmt.Errorf("unmarshal permissions: %w", err)
	}
	ro.Permissions = make(domain.Permissions, 0, len(perms))
	for _, p := range perms {
		ro.Permissions = append(ro.Permissions, domain.Permission(p))
	}
	rules, err := rulesFromJSON(rulesJSON)
	if err != nil {
		return err
	}
	ro.Rules = rules
	return nil
}

// scanRoleWithVersion — ЕДИНСТВЕННОЕ объявление порядка назначений под roleCols.
// Без versionOut это обычное чтение проекции (сюда делегирует scanRole); с ним
// запрос ОБЯЗАН нести ведущую колонку `xmin::text`, и токен пишется в
// *versionOut[0] — слот версии встаёт первым в тот же список (GetWithVersion).
//
// Порядок здесь именно ОДИН, а не «воспроизведён»: прежде список был написан
// дважды, и вторая копия отстала на колонку `owner_module` — правка любой роли
// отвечала арендатору INTERNAL, потому что описаний полей приходило 13, а
// приёмников было 12. Компилятор такое расхождение не ловит, роняет его только
// живая Postgres. Заводя колонку в roleCols, правь список ЗДЕСЬ; второго места,
// способного с ним разойтись, больше нет, а остаточную ось «проекция против
// списка» держит TestProjectionScanArityMatchesItsColumns.
// scanRoleWithTrailing — те же колонки `roleCols`, за которыми идут ДОПОЛНИТЕЛЬНЫЕ
// приёмники вызывающего.
//
// Заведена ради одного случая: путь реконсиляции читает роль ВМЕСТЕ с её
// живостью, а `roleCols` живость не несёт намеренно — тот же перечень читают
// пути ответа операции, а ответ операции жизненного состояния не вычисляет.
// Второго разбора строки роли при этом не заводится: хвост приклеивается к
// ЭТОМУ, а копия разошлась бы с ним молча на первой же новой колонке.
func scanRoleWithTrailing(row scanner, trailing ...any) (domain.Role, error) {
	return scanRoleWithVersionAndTrailing(row, nil, trailing)
}

func scanRoleWithVersion(row scanner, versionOut ...*string) (domain.Role, error) {
	return scanRoleWithVersionAndTrailing(row, versionOut, nil)
}

func scanRoleWithVersionAndTrailing(row scanner, versionOut []*string, trailing []any) (domain.Role, error) {
	var (
		ro                       domain.Role
		clusterID, accID, projID sql.NullString
		ownerModule              sql.NullString
		permsJSON, rulesJSON     []byte
		labelsJSON               []byte
	)
	dest := make([]any, 0, 14)
	if len(versionOut) > 0 {
		dest = append(dest, versionOut[0])
	}
	dest = append(dest,
		(*string)(&ro.ID),
		&clusterID,
		&accID,
		&projID,
		(*string)(&ro.Name),
		(*string)(&ro.Description),
		&permsJSON,
		&rulesJSON,
		&ro.IsSystem,
		&ownerModule,
		&ro.CreatedAt,
		&ro.UpdatedAt,
		&labelsJSON,
	)
	dest = append(dest, trailing...)
	if err := row.Scan(dest...); err != nil {
		return domain.Role{}, err
	}
	if clusterID.Valid {
		ro.ClusterID = domain.ClusterID(clusterID.String)
	}
	if accID.Valid {
		ro.AccountID = domain.AccountID(accID.String)
	}
	if projID.Valid {
		ro.ProjectID = domain.ProjectID(projID.String)
	}
	// Пустая колонка означает ПЛАТФОРМЕННУЮ роль, и пустая строка домена
	// означает ровно то же: `PolicyOfRole` читает непустоту, а не наличие. Второй
	// формы отсутствия здесь не заводится.
	if ownerModule.Valid {
		ro.OwnerModule = ownerModule.String
	}
	if err := scanRolePolicy(&ro, permsJSON, rulesJSON); err != nil {
		return domain.Role{}, err
	}
	var err error
	ro.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Role{}, err
	}
	return ro, nil
}

func stringSlice(perms domain.Permissions) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}
