// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// access_binding_repo.go — pgxpool-impl для access_binding.ReaderIface / WriterIface;
// lifecycle state machine on access_bindings.status (PENDING → ACTIVE → REVOKED).
//
// Strict Insert:
//
//   INSERT INTO kaname.access_bindings (...)
//   VALUES ($newID, $st, $sid, $rid, $rt, $rid2, $status, $cond, $exp, $grb, $rva, $rvb, now())
//   RETURNING id, ..., created_at;
//
// На дубле (subject_id, subject_type, role_id, resource_type, resource_id)
// с revoked_at IS NULL — partial UNIQUE access_bindings_active_grant_uniq
// (migration 0003) поднимает 23505 → mapErr → ErrAlreadyExists с verbatim
// «these permissions are already granted to <subject_id> on <res_type>:<res_id>».
// Прежний `ON CONFLICT DO UPDATE SET id = access_bindings.id` (silent
// idempotent-upsert) удален — он маскировал реальный duplicate-grant и
// засорял audit-чейн.
//
// Full column coverage (12 cols):
//   id, subject_type, subject_id, role_id, resource_type, resource_id,
//   status (PENDING|ACTIVE|REVOKED — DEFAULT 'ACTIVE'),
//   expires_at (nullable TTL), granted_by_user_id (audit),
//   revoked_at (nullable), revoked_by_user_id (nullable), created_at.
//
// State machine: PENDING → ACTIVE → REVOKED (terminal).
// TransitionStatus(...) — single-statement CAS UPDATE WHERE status IN (expected);
// 0 rows из RETURNING → ErrFailedPrecondition (no TOCTOU; within-service refs
// must be enforced at the DB level).
//
// Within-service refs — DB-level invariants:
//   - UNIQUE access_bindings_active_grant_uniq (5-tuple WHERE revoked_at IS NULL)
//     → 23505 → ErrAlreadyExists (verbatim text per idHint encoding).
//   - FK access_bindings_role_fk → SQLSTATE 23503 → ErrFailedPrecondition.
//   - CHECK access_bindings_status_ck — SQLSTATE 23514 → ErrInvalidArg.
//   - CHECK access_bindings_revoked_consistency_ck — same.
//   - subject_id/resource_id — soft-ref (нет FK; polymorphic + cross-DB).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
)

type abReader struct {
	tx pgx.Tx
}

// abCols — access_bindings columns (RBAC v2 + scope + deletion_protection + F8
// target). Порядок SELECT и RETURNING совпадает ПОСТРОЕНИЕМ: оба места
// интерполируют эту константу, и разойтись им нечем. `target_digest` is
// write-only (index key, computed on Insert) — NOT scanned, so it is
// deliberately absent here.
//
// Здесь стоял поимённый перечень глаголов, несущих RETURNING. Он разошёлся с
// деревом в ОБЕ стороны: называл `DeleteGuarded`, который эту проекцию не
// возвращает, и молчал о `RevokeGuarded` и `UpdateLabels`, которые возвращают.
// Рукописный перечень рядом с тем, что и так держится построением, гарантии не
// добавляет — он добавляет второе место, стареющее молча (#1951).
//
// `role_id` читается через COALESCE: у ФОРМЫ ОТНОШЕНИЯ (системная выдача) роли
// нет, и колонка допускает NULL. Пустая строка здесь — не подмена значения, а его
// отсутствие в том же виде, в каком отсутствие выражено во всём домене: форму
// выдачи различает пара (role_id, granted_relation), и ровно одна из них непуста.
const abCols = "id, subject_type, subject_id, COALESCE(role_id, '') AS role_id, resource_type, resource_id, " +
	"status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope, " +
	"deletion_protection, labels, target, granted_relation, is_system"

func (r *abReader) Get(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetForNoKeyUpdate is Get with a `FOR NO KEY UPDATE` row-lock on the binding row.
// The γ reconciler calls it as the FIRST statement of its FULL writer-tx
// (LoadBinding) so two concurrent full passes of the SAME binding are serialized on
// the row-lock: the second pass blocks until the first commits its membership diff,
// then re-reads CurrentMembers seeing the already-ACTIVE member (no status change ⇒
// idempotent skip) and emits ZERO duplicate fga_outbox tuples. This is a parent-row-
// lock critical-section pattern. A missing row ⇒ ErrNotFound (the binding was deleted
// — the reconciler then does nothing).
//
// ПОЧЕМУ `FOR NO KEY UPDATE`, А НЕ `FOR UPDATE` — И ЧТО ЭТО НЕ ОСЛАБЛЯЕТ.
//
// Взаимное исключение полных проходов сохраняется дословно: `FOR NO KEY UPDATE`
// конфликтует и с `FOR UPDATE`, и сам с собой, и с обычным UPDATE строки, — то есть
// со всем, что меняет биндинг (истечение срока, отзыв, удаление). Ключ строки
// (id) реконсайлер не меняет НИКОГДА, поэтому более сильный режим здесь ничего не
// охранял.
//
// А охранял он лишнее — и это измерено. `FOR UPDATE` — единственный режим, который
// конфликтует с `FOR KEY SHARE`, а именно `FOR KEY SHARE` берёт на этой же строке
// КАЖДАЯ вставка в дочерние таблицы по внешнему ключу (access_binding_target_members
// / access_binding_emitted_tuples). Из-за этого аддитивный форвард пути СОЗДАНИЯ — тот,
// ради которого свежий ресурс виден создателю сразу, — не мог писать, пока фоновый
// полный проход держит строку, и вынужден был брать SHARE-advisory, чтобы не словить
// перекрёстное ожидание (40P01). То есть окно видимости своего свежего ресурса
// определялось не работой форварда, а сроком чужой транзакции.
//
// Замер (тёплый 12-ядерный стенд, волна vpc+compute+nlb, выборка pg_stat_activity
// раз в 5 с): 99 наблюдений бэкенда в ожидании `pg_advisory_xact_lock_shared` —
// это и есть форвард — со средним 0.88 с и максимумом 4.6 с. На ранере вчетверо
// меньшей мощности те же ожидания растягиваются за клиентский бюджет
// чтения-своих-записей, и создатель получает отказ на СВОЙ ресурс.
//
// Сняв конфликт в его корне, форвард перестаёт брать advisory-блокировку вовсе
// (reconcile/forward.go). Свойство держит проба
// TestReconcileForward_07_DoesNotQueueBehindInFlightFullPass: она держит полный
// проход в полёте ЕГО ЖЕ первыми стейтментами и требует, чтобы форвард прошёл, — с
// парным положительным контролем, что тот же форвард без держателя материализует
// объект (иначе «не ждёт» зеленело бы на проходе, который ничего не делает).
func (r *abReader) GetForNoKeyUpdate(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1 FOR NO KEY UPDATE`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// accountScopePredicate — «привязка лежит в области ЭТОГО аккаунта»: либо
// привязана к самому аккаунту, либо к любому его проекту. Один placeholder,
// названный дважды: аккаунт и его проекты сверяются с одним и тем же значением.
//
// ОДНО написание на двух вызывающих — `List` (поле AccountID, #1737) и
// `ListByAccount`. Прежде их было два, и приёмка требует от них ОДИНАКОВОГО
// охвата; держать это требование на двух написаниях значило бы завести два
// ответа на вопрос «чья это привязка», которые разойдутся молча.
//
// Третье написание в этом файле — `membershipHoldingBindingsPredicate` (#1686) —
// сюда НЕ сводится: копия там объявлена копией НАМЕРЕННО, чтобы правка одной
// стороны заставляла открыть вторую, и у неё свой предмет (отказ исключения).
//
// Within-service refs (ban #10): подзапрос читает FK-проверенную таблицу
// projects — ни кросс-сервисного вызова, ни TOCTOU.
func accountScopePredicate(argPos int) string {
	return fmt.Sprintf(
		`((resource_type = 'account' AND resource_id = $%[1]d)
		   OR (resource_type = 'project'
		       AND resource_id IN (SELECT id FROM projects WHERE account_id = $%[1]d)))`,
		argPos)
}

// List — the unified read (redesign-2026 F11). Builds the WHERE from whatever
// optional predicates the filter carries (subject/role/scope-type/scope-id),
// then keyset-paginates by (created_at, id) ASC. Read VISIBILITY is NOT a
// predicate here — the use-case applies it per-object to the returned page
// (internal/authzfilter); the former FGA visible-id push-down was capped at
// 1000 objects by the external engine and silently hid a tenant's own bindings.
// The page_token decode is the authoritative format backstop (garbage →
// InvalidArgument), independent of the handler pre-check.
//
// IncludeRevoked defaults to FALSE: F10 soft-revoke RETAINS the row with
// status='REVOKED', so without the predicate a revoked grant would be listed next to
// live ones — and because the active-grant partial UNIQUE keys on revoked_at, an
// identical re-grant produces a SECOND row, i.e. one grant shown twice. Parity with
// ListByAccount / ListByRole, whose default already hides them.
func (r *abReader) List(ctx context.Context, f access_binding.ListFilter) ([]domain.AccessBinding, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped: a clamp
	// answers 200 OK with a page shorter than asked for, and nothing in the
	// response tells that apart from a complete answer.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{}
	args := []any{}
	argIdx := 1
	addEq := func(col, val string) {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", col, argIdx))
		args = append(args, val)
		argIdx++
	}
	if f.SubjectID != "" {
		addEq("subject_id", f.SubjectID)
	}
	if f.RoleID != "" {
		addEq("role_id", f.RoleID)
	}
	if f.ScopeType != "" {
		addEq("resource_type", f.ScopeType)
	}
	if f.ScopeID != "" {
		addEq("resource_id", f.ScopeID)
	}
	// Сужение до области ОДНОГО аккаунта (#1737): сам аккаунт плюс каждый его
	// проект. Тот же предикат, что у ListByAccount, — одно написание на оба
	// глагола, поэтому «одинаковый охват» есть свойство кода, а не совпадение.
	//
	// Стоит ОТДЕЛЬНО от сужения кандидатов ниже и от него не зависит: у
	// администратора облака и у держателя cluster-scoped выдачи Candidates равен
	// nil, и предикат, спрятанный внутрь того блока, для них не исполнился бы
	// вовсе — ответ остался бы на вид исправным и шире запрошенного.
	if f.AccountID != "" {
		conditions = append(conditions, accountScopePredicate(argIdx))
		args = append(args, f.AccountID)
		argIdx++
	}
	// Argument-free predicate (like ListByAccount/ListByRole) — appending it does not
	// disturb argIdx.
	if !f.IncludeRevoked {
		conditions = append(conditions, "status <> 'REVOKED'")
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
	// не после него: постфильтр по видимости теряет всякую привязку, перед которой
	// лежит больше `page_size` невидимых предшественников — она до фильтра просто
	// не доезжает.
	//
	// Аккаунт привязки не колонка, а вывод из её области, и выражение ниже —
	// то же самое, которым пользуется ListByAccount (`resource_type='account'`
	// прямо, `resource_type='project'` через проект), обобщённое с одного аккаунта
	// на набор. Держать его в двух написаниях значило бы завести два ответа на
	// вопрос «чья это привязка», которые разойдутся молча.
	//
	// nil — не сужать (администратор облака); непустой указатель с пустыми
	// наборами не называет ни одной строки и потому не пропускает ни одной.
	if f.Candidates != nil {
		conditions = append(conditions, fmt.Sprintf(
			`(id = ANY($%[2]d)
			   OR (resource_type = 'account' AND resource_id = ANY($%[1]d))
			   OR (resource_type = 'project'
			       AND resource_id IN (SELECT id FROM projects WHERE account_id = ANY($%[1]d))))`,
			argIdx, argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM access_bindings %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, serr := scanAB(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, ab)
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

func (r *abReader) ListByScope(ctx context.Context, resourceType domain.ResourceType, resourceID string, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWithConds(ctx, f,
		[]string{"resource_type = $%d", "resource_id = $%d"},
		[]any{string(resourceType), resourceID})
}

func (r *abReader) ListBySubject(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWithConds(ctx, f,
		[]string{"subject_type = $%d", "subject_id = $%d"},
		[]any{string(subjectType), string(subjectID)})
}

// ListByAccount — admin path returning every binding in an Account scope:
//
//   - bindings directly attached to the account (resource_type='account'
//     AND resource_id = $accountID); plus
//   - bindings on every Project whose account_id = $accountID
//     (resource_type='project' AND resource_id IN (SELECT id FROM projects
//     WHERE account_id = $accountID)).
//
// Optional SubjectTypeFilter narrows to a single subject_type.
// IncludeRevoked=false (default) hides status='REVOKED' rows.
//
// Ordering: (created_at DESC, id ASC) — newest grants first; ties broken by
// id ASC to keep keyset cursors deterministic.
//
// Keyset cursor format matches encodePageToken/decodePageToken (opaque
// base64 (created_at, id)) but applies the DESC predicate
// `(created_at, id) < ($prev_ts, $prev_id)`.
//
// Within-service refs (ban #10): the subquery uses
// the FK-validated projects table — no cross-DB call required, no TOCTOU.
func (r *abReader) ListByAccount(ctx context.Context, accountID domain.AccountID, f access_binding.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped: a clamp
	// answers 200 OK with a page shorter than asked for, and nothing in the
	// response tells that apart from a complete answer.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	// $1 = accountID — referenced twice (direct + project scope).
	args := []any{string(accountID)}
	argIdx := 2

	// Тот же предикат, что у `List` с полем AccountID (#1737) — одно написание,
	// поэтому охват обоих глаголов совпадает by construction.
	conditions := []string{accountScopePredicate(1)}

	if !f.IncludeRevoked {
		conditions = append(conditions, `status <> 'REVOKED'`)
	}

	if f.SubjectTypeFilter != "" {
		conditions = append(conditions, fmt.Sprintf("subject_type = $%d", argIdx))
		args = append(args, f.SubjectTypeFilter)
		argIdx++
	}

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		// DESC keyset predicate: (created_at, id) < (last_seen_created_at, last_seen_id)
		// when ordered by created_at DESC + id ASC. We treat id ASC as a tiebreaker:
		// (created_at < ts) OR (created_at = ts AND id > prev_id).
		conditions = append(conditions,
			fmt.Sprintf(`(created_at < $%d OR (created_at = $%d AND id > $%d))`,
				argIdx, argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s
		ORDER BY created_at DESC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
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

// ListSubjectPrivileges — enriched read for the subject-privileges view.
// Returns the subject's DIRECT AccessBindings LEFT JOINed with
// `roles` so the human-readable role_name is resolved server-side in ONE query
// (access_bindings ab ⋈ roles r ON ab.role_id = r.id; same kaname schema,
// FK access_bindings_role_fk — no per-row N+1).
//
// LEFT JOIN (not INNER): a dangling role (deleted after a revoke) must not drop
// the row — the binding is returned with role_name="" (graceful).
//
// Only PENDING/ACTIVE rows are returned (status <> 'REVOKED' — parity with
// ListByAccount.include_revoked=false). v1 is DIRECT-only — subject_id literally
// equals the requested subject.
//
// Ordering & keyset cursor match ListBySubject: (created_at, id) ASC with an
// opaque base64 (created_at, id) page_token; (created_at, id) > (prev) predicate.
// page_size: 0 → DefaultPageSize(50), capped at 1000.
//
// Within-service refs (запрет #10): the JOIN reads the FK-validated `roles`
// table — no cross-DB call, no TOCTOU. Read-only — no CAS/race path.
func (r *abReader) ListSubjectPrivileges(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped: a clamp
	// answers 200 OK with a page shorter than asked for, and nothing in the
	// response tells that apart from a complete answer.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	// Subject-match: DIRECT (the binding names the subject) OR GROUP-derived (the
	// binding names a group the subject belongs to). Both branches are equality
	// predicates on (subject_type, subject_id), so access_bindings_subject_idx
	// serves them as a BitmapOr — the read stays index-driven, no seq-scan.
	//
	// The group side reads kaname.group_members via group_members_member_idx.
	// Groups do NOT nest (group_members_type_check allows only user /
	// service_account), so this is exactly ONE hop and cannot recurse: when the
	// REQUESTED subject is itself a group the sub-select is empty and only the
	// DIRECT branch applies.
	conditions := []string{
		`(   (ab.subject_type = $1 AND ab.subject_id = $2)
		  OR (ab.subject_type = 'group' AND ab.subject_id IN (
		        SELECT gm.group_id FROM group_members gm
		         WHERE gm.member_type = $1 AND gm.member_id = $2)) )`,
		"ab.status <> 'REVOKED'",
	}
	args := []any{string(subjectType), string(subjectID)}
	argIdx := 3

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions,
			fmt.Sprintf("(ab.created_at, ab.id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// COALESCE(r.name, '') so a LEFT JOIN miss (dangling role) scans as "" — the
	// Go scan target is a plain string, never NULL.
	//
	// The last two columns attribute the row: `is_direct` is true when the binding
	// names the subject itself; otherwise it was reached through the group named by
	// `via_group_id`. A binding that is BOTH direct and group-carried resolves to
	// DIRECT (the stronger, self-evident attribution) and yields ONE row — the
	// predicate is a disjunction on the same row, never a join, so cardinality stays
	// one-row-per-binding and the (created_at, id) keyset cursor stays valid.
	q := fmt.Sprintf(`
		SELECT ab.id, ab.role_id, COALESCE(r.name, ''),
		       ab.resource_type, ab.resource_id, ab.scope, ab.status,
		       ab.created_at, ab.granted_by_user_id, ab.expires_at,
		       (ab.subject_type = $1 AND ab.subject_id = $2) AS is_direct,
		       CASE WHEN ab.subject_type = 'group' AND NOT (ab.subject_type = $1 AND ab.subject_id = $2)
		            THEN ab.subject_id ELSE '' END AS via_group_id
		  FROM access_bindings ab
		  LEFT JOIN roles r ON ab.role_id = r.id
		 WHERE %s
		 ORDER BY ab.created_at ASC, ab.id ASC
		 LIMIT $%d`, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.SubjectPrivilege
	for rows.Next() {
		sp, serr := scanSubjectPrivilege(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.BindingID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// scanSubjectPrivilege — maps a ListSubjectPrivileges row into the enriched
// domain projection. role_name is already COALESCE'd to ” (dangling role).
// scope is bounds-checked the same way as scanAB. The trailing
// is_direct/via_group_id columns carry the derivation attribution (DIRECT vs
// GROUP-derived — see the query comment).
func scanSubjectPrivilege(row scanner) (domain.SubjectPrivilege, error) {
	var (
		sp         domain.SubjectPrivilege
		expiresAt  sql.NullTime
		scopeI     int16
		isDirect   bool
		viaGroupID string
	)
	err := row.Scan(
		(*string)(&sp.BindingID),
		(*string)(&sp.RoleID),
		(*string)(&sp.RoleName),
		(*string)(&sp.ResourceType),
		&sp.ResourceID,
		&scopeI,
		(*string)(&sp.Status),
		&sp.CreatedAt,
		(*string)(&sp.GrantedByUserID),
		&expiresAt,
		&isDirect,
		&viaGroupID,
	)
	if err != nil {
		return domain.SubjectPrivilege{}, err
	}
	if !isDirect {
		sp.Derivation = domain.DerivationGroup
		sp.ViaGroupID = domain.GroupID(viaGroupID)
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		sp.ExpiresAt = &t
	}
	if scopeI < 0 || scopeI > 3 {
		sp.Scope = domain.ScopeUnspecified
	} else {
		sp.Scope = domain.Scope(scopeI)
	}
	return sp, nil
}

// listWithConds — общий path-builder для ListByScope/ListBySubject.
//
// ОГРАНИЧЕНИЕ НА ВЫЗЫВАЮЩИХ: `condTmpls` попадает в fmt.Sprintf как СТРОКА
// ФОРМАТА и уезжает в ТЕКСТ запроса. Значит каждый элемент обязан быть
// литералом кода вида `"<колонка> = $%d"` — ровно один глагол `%d` под номер
// плейсхолдера. Данные вызывающего идут ТОЛЬКО через `condArgs` (их связывает
// pgx), в шаблон — НИКОГДА.
//
// Сегодня это выполняется: метод неэкспортирован, вызывающих двое
// (ListByScope/ListBySubject), оба передают литеральные срезы. Но ни сигнатура,
// ни тип этого не держат — `[]string` примет что угодно, поэтому ограничение
// записано здесь. Вызывающий, собравший элемент из значения запроса, получит
// прямую SQL-инъекцию, и ни компилятор, ни сканер не возразят: правила
// инъекции (G201/G202) эту форму не матчат — приёмник pgx, Sprintf инлайном.
//
// Два смежных капкана той же строки: шаблон без `%d` молча вставит в SQL
// `%!(EXTRA int=…)`, а шаблон с `%s` съест номер плейсхолдера как текст.
func (r *abReader) listWithConds(ctx context.Context, f access_binding.PageFilter, condTmpls []string, condArgs []any) ([]domain.AccessBinding, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped: a clamp
	// answers 200 OK with a page shorter than asked for, and nothing in the
	// response tells that apart from a complete answer.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{}
	args := []any{}
	argIdx := 1
	for i, tmpl := range condTmpls {
		conditions = append(conditions, fmt.Sprintf(tmpl, argIdx))
		args = append(args, condArgs[i])
		argIdx++
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
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

type abWriter struct {
	abReader
}

// Insert — strict create. На дубле (subject_type, subject_id, role_id,
// resource_type, resource_id) с revoked_at IS NULL — partial UNIQUE
// access_bindings_active_grant_uniq (миграция 0003) поднимает SQLSTATE 23505,
// который маппится в ErrAlreadyExists с verbatim text:
//
//	"these permissions are already granted to <subject_id> on <resource_type>:<resource_id>"
//
// Прежняя идемпотентность (ON CONFLICT DO UPDATE SET id = access_bindings.id)
// удалена: silent-upsert скрывал реальный duplicate-grant и заставлял ревьюера
// разбираться, почему один и тот же тапл создавался под разными id. Use-case
// больше не вызывает FindExisting для pre-resolution candidate-id; reseats
// strictly create-or-conflict.
//
// Записывает все 12 колонок. Пустой Status проходит как DB-default ACTIVE
// (через COALESCE(NULLIF($7, ”), 'ACTIVE')). Nullable поля (expires_at,
// revoked_at, revoked_by_user_id) передаются через
// nullableString/nullableTimePtr хелперы.
func (w *abWriter) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	now := time.Now().UTC()
	// Scope: explicit value when non-Unspecified, otherwise let the
	// access_bindings_scope_default_trg trigger derive from resource_type
	// (migration 0005). Passing SMALLINT NULL trips the NOT NULL constraint
	// AFTER the trigger only when the trigger leaves NEW.scope NULL — which
	// it never does (the trigger has an ELSE branch).
	// labels — own-resource tenant-facing метки самого binding-ресурса,
	// делают AccessBinding label-selectable (catalog-видимость через viewer ∪ v_list).
	labelsJSON, err := marshalLabels(b.Labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	// F8: persist the object-selection (target) + its set-based digest. The digest
	// is a key column of the active-grant partial UNIQUE (identical target →
	// collision, distinct per-object targets coexist). Empty/whole-anchor → "all".
	targetJSON, err := marshalTarget(b.Target)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument target: %s", err.Error())
	}
	targetDigest := b.Target.Digest()
	q := fmt.Sprintf(`
		INSERT INTO access_bindings (
			id, subject_type, subject_id, role_id, resource_type, resource_id,
			status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope,
			deletion_protection, labels, target, target_digest, granted_relation, is_system
		)
		VALUES (
			$1, $2, $3,
			-- Роли может не быть: у формы отношения колонка NULL, и внешний ключ
			-- пропускает её by construction. Пустая строка вместо NULL уехала бы в
			-- ключ и дала бы отказ ссылочной целостности на несуществующую роль.
			NULLIF($4, ''), $5, $6,
			COALESCE(NULLIF($7, ''), 'ACTIVE'),
			$8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
		RETURNING %s`, abCols)
	var scopeArg any
	if b.Scope == domain.ScopeUnspecified {
		scopeArg = nil
	} else {
		scopeArg = int16(b.Scope)
	}
	row := w.tx.QueryRow(ctx, q,
		string(b.ID), string(b.SubjectType), string(b.SubjectID), string(b.RoleID),
		string(b.ResourceType), b.ResourceID,
		string(b.Status),
		nullableTimePtr(b.ExpiresAt),
		string(b.GrantedByUserID),
		nullableTimePtr(b.RevokedAt),
		nullableUserIDPtr(b.RevokedByUserID),
		now,
		scopeArg,
		b.DeletionProtection,
		labelsJSON,
		targetJSON,
		targetDigest,
		b.GrantedRelation,
		b.System,
	)
	out, err := scanAB(row)
	if err != nil {
		// Подсказка несёт ТРИ слота: "<subject_id>|<resource_type>:<resource_id>|<role_id>".
		// Разбирает её splitBindingHint, и каждый потребитель берёт своё: текст UNIQUE —
		// субъекта и область, ветвь FK по роли — роль. Роль добавлена, потому что без неё
		// FK-ветвь печатала всю подсказку в слот роли и называла вызывающему сущности,
		// о которых он не спрашивал (issue #105).
		idHint := fmt.Sprintf("%s|%s:%s|%s", b.SubjectID, b.ResourceType, b.ResourceID, b.RoleID)
		return domain.AccessBinding{}, mapErr(err, "", idHint)
	}
	return out, nil
}

// targetPersistJSON is the JSONB persistence shape of AccessBinding.target (F8).
type targetPersistJSON struct {
	AllInScope bool                    `json:"allInScope,omitempty"`
	Resources  []targetResourceRefJSON `json:"resources,omitempty"`
}

type targetResourceRefJSON struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// marshalTarget serializes the domain target to its JSONB persistence shape. A
// per-object set is written as {"resources":[…]}; AllInScope OR the empty
// whole-anchor zero value is written as {"allInScope":true}.
func marshalTarget(t domain.AccessTarget) ([]byte, error) {
	tj := targetPersistJSON{}
	if len(t.Resources) > 0 {
		tj.Resources = make([]targetResourceRefJSON, 0, len(t.Resources))
		for _, r := range t.Resources {
			tj.Resources = append(tj.Resources, targetResourceRefJSON{Type: r.Type, ID: r.ID})
		}
	} else {
		tj.AllInScope = true
	}
	return json.Marshal(tj)
}

// unmarshalTarget parses the JSONB persistence shape back to the domain target.
// An empty/NULL column (defensive — every row is backfilled by migration 0055) →
// the whole-anchor AllInScope grant.
func unmarshalTarget(b []byte) (domain.AccessTarget, error) {
	if len(b) == 0 {
		return domain.AccessTarget{AllInScope: true}, nil
	}
	var tj targetPersistJSON
	if err := json.Unmarshal(b, &tj); err != nil {
		return domain.AccessTarget{}, err
	}
	if len(tj.Resources) > 0 {
		out := make([]domain.ResourceRef, 0, len(tj.Resources))
		for _, r := range tj.Resources {
			out = append(out, domain.ResourceRef{Type: r.Type, ID: r.ID})
		}
		return domain.AccessTarget{Resources: out}, nil
	}
	return domain.AccessTarget{AllInScope: true}, nil
}

// Delete — простой DELETE. 0 rows → NotFound. Used by paths that have already
// established the binding is deletable (reconcile/expire) or by tests; the public
// Delete use-case goes through DeleteGuarded (P6 deletion_protection CAS).
func (w *abWriter) Delete(ctx context.Context, id domain.AccessBindingID) error {
	tag, err := w.tx.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "AccessBinding.Delete", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
	}
	return nil
}

// DeleteGuarded — атомарный CAS-delete (по образцу vpc.address.DeleteGuarded). Single-statement
// `DELETE … WHERE id=$1 AND deletion_protection=false` берет row-lock: конкурентный
// writer ждет commit, затем видит строку уже удаленной (его CAS → 0 строк →
// NotFound) ИЛИ строку с deletion_protection=true (его CAS → 0 строк →
// FailedPrecondition). Никакого software TOCTOU (ban #10). 0 строк → повторное
// чтение различает not-found / protected.
func (w *abWriter) DeleteGuarded(ctx context.Context, id domain.AccessBindingID) error {
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_bindings WHERE id = $1 AND deletion_protection = false`, string(id))
	if err != nil {
		return mapErr(err, "AccessBinding.Delete", string(id))
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// 0 rows: not-found vs protected — re-read on this tx.
	cur, gerr := w.Get(ctx, id)
	if gerr != nil {
		return gerr // ErrNotFound (или иная)
	}
	if cur.DeletionProtection {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
	}
	// Row exists, unprotected, yet 0 rows deleted → concurrent delete won the race.
	return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

// RevokeGuarded — atomic CAS soft-revoke (redesign-2026 F10 IAM-1-28). Mirror of
// DeleteGuarded's protection-CAS + TransitionStatus's REVOKED move, but RETAINS the
// row: single-statement `UPDATE … SET status='REVOKED', revoked_at=now(),
// revoked_by_user_id=$2 WHERE id=$1 AND status='ACTIVE' AND deletion_protection=false
// RETURNING …` takes a row-lock, so exactly one revoke wins under concurrency (the
// loser waits the commit, its WHERE status='ACTIVE' no longer matches → 0 rows, ban
// #10 — no software TOCTOU). 0 rows → re-read on this tx disambiguates: absent →
// NotFound; protected → FailedPrecondition; non-ACTIVE (terminal REVOKED / PENDING or
// a concurrent revoke that won) → FailedPrecondition. revoked_at is stamped so the
// partial active-grant UNIQUE (WHERE revoked_at IS NULL) frees the slot for re-grant.
func (w *abWriter) RevokeGuarded(ctx context.Context, id domain.AccessBindingID, revokedBy domain.UserID) (domain.AccessBinding, error) {
	if revokedBy == "" {
		// CHECK access_bindings_revoked_consistency_ck requires revoked_at to move
		// with status='REVOKED'; a REVOKED row without a revoker is not allowed.
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg,
			"revoked_by_user_id is required for REVOKED transition")
	}
	now := time.Now().UTC()
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET status             = 'REVOKED',
		       revoked_at         = $2,
		       revoked_by_user_id = $3
		 WHERE id = $1
		   AND status = 'ACTIVE'
		   AND deletion_protection = false
		RETURNING %s`, abCols), string(id), now, string(revokedBy))
	out, err := scanAB(row)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.RevokeGuarded", string(id))
	}
	// 0 rows updated — re-read on this tx to disambiguate the CAS miss.
	cur, gerr := w.Get(ctx, id)
	if gerr != nil {
		return domain.AccessBinding{}, gerr // ErrNotFound (or a transient fault)
	}
	if cur.DeletionProtection {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before revoke", id)
	}
	// Not-active (already REVOKED / PENDING, or a concurrent revoke won the row-lock).
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
		"access binding %s is not active (status %s); cannot revoke", id, cur.Status)
}

// SetDeletionProtection — atomic CAS UPDATE of the deletion_protection flag.
// Single-statement
// `UPDATE … WHERE id=$1 RETURNING …`; 0 rows → NotFound. Used by the
// Update(update_mask=["deletion_protection"]) path to clear the flag.
func (w *abWriter) SetDeletionProtection(ctx context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET deletion_protection = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), protected)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.SetDeletionProtection", string(id))
	}
	return out, nil
}

// UpdateLabels — atomic single-statement UPDATE of the own-resource labels
// (AB mutable set расширен до {deletion_protection, labels}).
// `UPDATE … SET labels=$2 WHERE id=$1 RETURNING …` берет row-lock: конкурентный
// writer ждет commit и видит обновленный row (last-writer-wins, не TOCTOU, ban #10).
// 0 rows RETURNING → NotFound. Identity/scope/subject поля не затрагиваются.
func (w *abWriter) UpdateLabels(ctx context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	labelsJSON, err := marshalLabels(labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET labels = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), labelsJSON)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.UpdateLabels", string(id))
	}
	return out, nil
}

// TransitionStatus — atomic CAS UPDATE для state machine (PENDING → ACTIVE → REVOKED).
// Single-statement `UPDATE … WHERE id=$1 AND status = ANY($expected) RETURNING …`;
// 0 rows из RETURNING → ErrFailedPrecondition (терминальный state или mismatch).
// SQLSTATE 23514 (CHECK violation для невалидного newState) → ErrInvalidArg.
//
// При transition в REVOKED обязательно передается revokedByUserID (CHECK
// access_bindings_revoked_consistency_ck). Для PENDING→ACTIVE / ACTIVE→ACTIVE
// revokedByUserID игнорируется (NULL в DB).
//
// Race-safety: row-level lock Postgres гарантирует one-winner на одну row;
// параллельный writer ждет commit-а первого и видит уже измененное значение.
func (w *abWriter) TransitionStatus(
	ctx context.Context,
	id domain.AccessBindingID,
	expected []domain.AccessBindingStatus,
	newStatus domain.AccessBindingStatus,
	revokedByUserID *domain.UserID,
) (domain.AccessBinding, error) {
	if err := newStatus.Validate(); err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if len(expected) == 0 {
		return domain.AccessBinding{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "expected statuses must not be empty")
	}
	expStrings := make([]string, len(expected))
	for i, s := range expected {
		expStrings[i] = string(s)
	}
	now := time.Now().UTC()
	var (
		revAtArg any
		revByArg any
	)
	if newStatus == domain.AccessBindingStatusRevoked {
		revAtArg = now
		if revokedByUserID == nil || *revokedByUserID == "" {
			return domain.AccessBinding{},
				iamerr.Wrapf(iamerr.ErrInvalidArg, "revoked_by_user_id is required for REVOKED transition")
		}
		revByArg = string(*revokedByUserID)
	} else {
		// PENDING / ACTIVE — revoked_at / revoked_by must be NULL (CHECK).
		revAtArg = nil
		revByArg = nil
	}
	q := fmt.Sprintf(`
		UPDATE access_bindings
		   SET status              = $2,
		       revoked_at          = $3,
		       revoked_by_user_id  = $4
		 WHERE id = $1
		   AND status = ANY($5)
		RETURNING %s`, abCols)
	row := w.tx.QueryRow(ctx, q,
		string(id), string(newStatus), revAtArg, revByArg, expStrings,
	)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"AccessBinding %s cannot transition to %s (not in expected states %v)",
				id, newStatus, expected)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.TransitionStatus", string(id))
	}
	return out, nil
}

func scanAB(row scanner) (domain.AccessBinding, error) {
	return scanABWithVersion(row)
}

// scanABWithVersion — ЕДИНСТВЕННОЕ объявление порядка назначений под abCols.
// When versionOut is provided (γ GetWithVersion) the query MUST prepend an
// `xmin::text` column and the token is written into *versionOut[0] — the Scan
// dest list is built with the version slot first to match. Without versionOut it
// is the plain abCols scan: сюда делегирует `scanAB`, поэтому список один на
// Get / GetWithVersion / list paths.
//
// Прежняя редакция обещала «parity with the prior scanAB». Отдельного `scanAB`
// со своим списком уже нет — сверять стало не с чем, и утверждение о совпадении
// пережило свой предмет. Расходиться внутри пакета этому списку теперь нечем;
// остаточную ось «abCols против списка» держит проба арности
// TestProjectionScanArityMatchesItsColumns (#1951).
func scanABWithVersion(row scanner, versionOut ...*string) (domain.AccessBinding, error) {
	var (
		ab           domain.AccessBinding
		expiresAt    sql.NullTime
		revokedAt    sql.NullTime
		revokedByUID sql.NullString
		scopeI       int16
		labelsJSON   []byte
		targetJSON   []byte
	)
	dest := make([]any, 0, 20)
	if len(versionOut) > 0 {
		dest = append(dest, versionOut[0])
	}
	dest = append(dest,
		(*string)(&ab.ID),
		(*string)(&ab.SubjectType),
		(*string)(&ab.SubjectID),
		(*string)(&ab.RoleID),
		(*string)(&ab.ResourceType),
		&ab.ResourceID,
		(*string)(&ab.Status),
		&expiresAt,
		(*string)(&ab.GrantedByUserID),
		&revokedAt,
		&revokedByUID,
		&ab.CreatedAt,
		&scopeI,
		&ab.DeletionProtection,
		&labelsJSON,
		&targetJSON,
		&ab.GrantedRelation,
		&ab.System,
	)
	err := row.Scan(dest...)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	ab.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	ab.Target, err = unmarshalTarget(targetJSON)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		ab.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		ab.RevokedAt = &t
	}
	if revokedByUID.Valid {
		u := domain.UserID(revokedByUID.String)
		ab.RevokedByUserID = &u
	}
	// gosec G115 — bounds-check int16 → int8 conversion. Scope values are
	// {0,1,2,3} guarded by access_bindings_scope_ck CHECK; any other value
	// is a corrupt row that we surface as an explicit Unspecified rather
	// than silently truncating.
	if scopeI < 0 || scopeI > 3 {
		ab.Scope = domain.ScopeUnspecified
	} else {
		ab.Scope = domain.Scope(scopeI)
	}
	return ab, nil
}

// EmitSubjectChangeEvent — writes both legacy denormalised
// columns AND the canonical event_type + payload jsonb in a single INSERT.
// Single-row INSERT is atomic by construction; combined with the enclosing
// writer-tx, the outbox row is committed iff the surrounding domain mutation
// commits (within-service refs must be enforced at the DB level).
//
// payload is REQUIRED by the corelib drainer SELECT contract — Decoder[T]
// receives ONLY payload bytes, not other row columns.
func (w *abWriter) EmitSubjectChangeEvent(ctx context.Context, evt access_binding.SubjectChangeEvent) error {
	if evt.SubjectID == "" {
		return fmt.Errorf("emit subject_change_outbox: subject_id required")
	}
	if evt.EventType == "" {
		evt.EventType = deriveEventTypeFromOp(evt.Op)
	}
	if evt.Op == "" {
		evt.Op = deriveOpFromEventType(evt.EventType)
	}

	// Величины предмета (`resource_type`/`resource_id`) в нагрузку не идут — ни
	// колонкой, ни близнецом внутри неё: читателя у них не было ни одного, а
	// платила за них каждая мутация выдачи (kacho#1462).
	payload, err := json.Marshal(struct {
		SubjectID   string `json:"subject_id"`
		SubjectType string `json:"subject_type,omitempty"`
		Op          string `json:"op"`
		EventType   string `json:"event_type"`
	}{
		SubjectID:   evt.SubjectID,
		SubjectType: evt.SubjectType,
		Op:          evt.Op,
		EventType:   evt.EventType,
	})
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: marshal payload: %w", err)
	}

	_, err = w.tx.Exec(ctx, `
		INSERT INTO kaname.subject_change_outbox
			(subject_id, op, event_type, payload)
		VALUES ($1, $2, $3, $4::jsonb)`,
		evt.SubjectID, evt.Op, evt.EventType, payload)
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: %w", err)
	}
	return nil
}

// EmitRelationWrite — atomically appends N grant rows into
// kaname.fga_outbox (event_type='fga.tuple.write') in the current
// writer-tx (atomicity required — see within-service refs). A trigger on that
// INSERT folds each row into a direct fact in the same commit.
//
// The binding INSERT and the enqueue commit-or-rollback atomically — no
// post-commit write that could diverge from the DB on failure.
func (w *abWriter) EmitRelationWrite(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.write", tuples)
}

// EmitRelationDelete — mirror of EmitRelationWrite for revoke. Caller supplies the
// EXACT tuples that were originally written by EmitRelationWrite (symmetric revoke).
func (w *abWriter) EmitRelationDelete(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.delete", tuples)
}

// InsertEmittedTuples persists the EXACT FGA tuples emitted for a binding into
// kaname.access_binding_emitted_tuples in the current writer-tx, co-committed
// with the matching EmitRelationWrite (ban #10). ON CONFLICT DO NOTHING
// keeps a repeated emit (idempotent re-grant / reconcile) a no-op. len==0 no-op.
func (w *abWriter) InsertEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("insert emitted tuple: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		if _, err := w.tx.Exec(ctx,
			// source='binding': written by Create + the Role.Update RoleTupleReconciler.
			// ARM_LABELS per-member rows (source='member') are owned by the γ reconciler
			// (RecordEmittedTuples) and MUST NOT be touched by the binding-level path.
			`INSERT INTO access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
			 VALUES ($1, $2, $3, $4, 'binding')
			 ON CONFLICT (binding_id, fga_user, relation, object) DO NOTHING`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// ReplaceEmittedTuples atomically replaces a binding's persisted emitted-set
// (DELETE all rows of the binding, then INSERT the new set) in the current
// writer-tx — the Role.Update reconcile fan-out uses it so the ledger reflects
// the CURRENT emitted projection after a permission change (ban #10).
// An empty `tuples` clears the binding's ledger rows.
func (w *abWriter) ReplaceEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	// Scope the wholesale swap to the BINDING-LEVEL subset (source='binding'). The
	// Role.Update reconcile (RoleTupleReconciler) owns only those tuples; the
	// ARM_LABELS per-member rows (source='member', written by the γ reconciler) are
	// owned by RoleMembershipFanout and MUST survive a binding-level reconcile —
	// otherwise a rules-changing Role.Update of a custom role mixing a binding-level
	// arm with an ARM_LABELS arm would revoke all label-selected access (the prior
	// `DELETE … WHERE binding_id` wiped them). InsertEmittedTuples re-inserts the new
	// set as source='binding'.
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_emitted_tuples WHERE binding_id = $1 AND source = 'binding'`, string(bindingID),
	); err != nil {
		return mapErr(err, "", string(bindingID))
	}
	return w.InsertEmittedTuples(ctx, bindingID, tuples)
}

// emitFGAOutbox enqueues the binding's tuples through the table's OWN emitter
// rather than rendering a row here.
//
// It used to write its own INSERT, one row per tuple, with its own hand-built
// payload — a second rendering of a shape whose whole point is that every producer
// agrees on it. The two drifted the moment the row stopped being one tuple: this
// path kept splitting a subject's relation set across rows, so a grant made through
// a binding still landed one relation at a time while the same grant made
// through the reconciler arrived whole. One emitter, one shape, one unit of
// atomicity — the drift has nowhere to happen.
func (w *abWriter) emitFGAOutbox(ctx context.Context, eventType string, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	out := make([]clients.RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("emit fga_outbox: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		out = append(out, clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	switch eventType {
	case fga_outbox.EventTypeWrite:
		return fga_outbox.EmitWriteTx(ctx, w.tx, out)
	case fga_outbox.EventTypeDelete:
		return fga_outbox.EmitDeleteTx(ctx, w.tx, out)
	default:
		return fmt.Errorf("emit fga_outbox: unknown event type %q", eventType)
	}
}

// EmitAuditEvent atomically appends one durable compliance row into
// kaname.audit_outbox in the current writer-tx (atomicity required — see
// within-service refs, запрет #10). The binding INSERT/DELETE and the audit
// enqueue commit-or-rollback together: a rolled-back grant leaves no audit row
// claiming it happened, and a committed grant always leaves its trail.
//
// The event_payload jsonb carries the compliance dimensions (actor / subject /
// resource / role_id / binding_id) so the "who granted which role to whom on
// which resource, and when" question is queryable; created_at supplies the
// "when". The row starts status='pending' for the audit shipper (pkg/audit).
func (w *abWriter) EmitAuditEvent(ctx context.Context, ev access_binding.AuditEvent) error {
	if ev.EventType == "" {
		return fmt.Errorf("emit audit_outbox: event_type required")
	}
	// Canonical compliance dimensions, then merge any event-specific
	// ExtraPayload (e.g. selector_replaced's old/new diff). Build as map[string]any
	// so heterogeneous extra fields (nested objects) are representable; keys in
	// ExtraPayload override the canonical ones on collision.
	fields := map[string]any{
		"actor":         ev.Actor,
		"subject_type":  ev.SubjectType,
		"subject_id":    ev.SubjectID,
		"resource_type": ev.ResourceType,
		"resource_id":   ev.ResourceID,
		"role_id":       ev.RoleID,
		"binding_id":    ev.BindingID,
	}
	for k, v := range ev.ExtraPayload {
		fields[k] = v
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("emit audit_outbox: marshal payload: %w", err)
	}
	// tenant_account_id is nullable (per-account scoping when known).
	tenant := nullableString(ev.TenantAccountID)
	if _, err := w.tx.Exec(ctx,
		`INSERT INTO kaname.audit_outbox
			(id, event_type, tenant_account_id, event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now(), now())`,
		newAuditEventID(), string(ev.EventType), tenant, payload,
	); err != nil {
		return fmt.Errorf("emit audit_outbox %s: %w", ev.EventType, err)
	}
	return nil
}

// newAuditEventID returns an audit_outbox id of the form `evt_<22-char
// crockford-base32>`, satisfying the audit_outbox_id_check regex
// (`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`). The 22-char body mirrors
// the proven bootstrap-admin generator; domain.NewKac127ID produces only a
// 17-char body, which is below the CHECK's 20-char floor.
func newAuditEventID() string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	const bodyLen = 22
	var raw [14]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand.Read does not fail on a healthy host; a failure means
		// the system entropy source is broken — panic is the correct response.
		panic("pg: crypto/rand failed: " + err.Error())
	}
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[6:14])

	var sb strings.Builder
	sb.Grow(len("evt_") + bodyLen)
	sb.WriteString("evt_")
	for i := 0; i < bodyLen; i++ {
		bitOff := uint(i*5) % 64 // i is the bounded loop index [0,bodyLen); i*5 cannot overflow uint.
		src := hi
		if i >= 12 {
			src = lo
		}
		val := (src >> (64 - bitOff - 5)) & 0x1f
		sb.WriteByte(crockford[val])
	}
	return sb.String()
}

// deriveEventTypeFromOp — canonical event_type for a legacy op alias.
// binding_delete→binding_revoke, binding_upsert→binding_grant, else passthrough.
func deriveEventTypeFromOp(op string) string {
	switch op {
	case "binding_delete":
		return "binding_revoke"
	case "binding_upsert":
		return "binding_grant"
	default:
		return op
	}
}

// deriveOpFromEventType — legacy op alias for a canonical event_type.
// Inverse of deriveEventTypeFromOp; used when caller provides only event_type
// (Op must satisfy DB CHECK subject_change_op_check, so we must populate it).
func deriveOpFromEventType(eventType string) string {
	switch eventType {
	case "binding_revoke":
		return "binding_delete"
	case "binding_grant":
		return "binding_upsert"
	default:
		return eventType
	}
}

// SelectEmittedTuplesBySource reads only the emitted-set rows of a binding written
// by ONE owner (source='binding' for Create + RoleTupleReconciler, source='member'
// for the γ reconciler). The Role.Update reconcile fan-out reads the 'binding'
// subset so its set-diff never sees — and so cannot revoke — the ARM_LABELS
// per-member tuples (CRITICAL ledger-source fix). The full symmetric revoke
// (delete.go) keeps using SelectEmittedTuples (the whole ledger). Zero rows ⇒ nil.
func (r *abReader) SelectEmittedTuplesBySource(ctx context.Context, bindingID domain.AccessBindingID, source string) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1 AND source = $2
		  ORDER BY relation, object, fga_user`, string(bindingID), source)
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// SelectEmittedTuples reads the persisted exact emitted-set of a binding
// (kaname.access_binding_emitted_tuples). The revoke (delete.go)
// and the Role.Update reconcile fan-out use it as the source of truth for which
// FGA tuples were actually written, so the revoke is byte-symmetric to the grant
// regardless of the role's current permissions. Zero rows ⇒ empty slice (nil).
func (r *abReader) SelectEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1
		  ORDER BY relation, object, fga_user`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// SelectTuplesClaimedByOtherActiveBindings returns the subset of `tuples` that some
// OTHER *ACTIVE* binding also records in the emitted-tuple ledger — the tuples a
// revoke of excludeBinding must NOT strip (the tuple is not refcounted, the ledger
// is keyed per binding; see the ReaderIface doc).
//
// ONE query for the whole candidate set: the triples are shipped as three parallel
// arrays and unnested into a join against the ledger, so the probe costs one
// round-trip regardless of set size (the reconciler's per-tuple EXISTS twin predates
// this). DISTINCT because several other bindings may claim the same tuple. Zero
// rows ⇒ nil (nothing survives ⇒ the whole set is revoked).
func (r *abReader) SelectTuplesClaimedByOtherActiveBindings(ctx context.Context, excludeBinding domain.AccessBindingID, tuples []access_binding.RelationTuple) ([]access_binding.RelationTuple, error) {
	if len(tuples) == 0 {
		return nil, nil
	}
	users := make([]string, len(tuples))
	relations := make([]string, len(tuples))
	objects := make([]string, len(tuples))
	for i, t := range tuples {
		users[i], relations[i], objects[i] = t.User, t.Relation, t.Object
	}
	rows, err := r.tx.Query(ctx,
		`SELECT DISTINCT c.fga_user, c.relation, c.object
		   FROM unnest($2::text[], $3::text[], $4::text[]) AS c(fga_user, relation, object)
		   JOIN access_binding_emitted_tuples et
		     ON et.fga_user = c.fga_user AND et.relation = c.relation AND et.object = c.object
		   JOIN access_bindings ab ON ab.id = et.binding_id
		  WHERE et.binding_id <> $1
		    AND ab.status = 'ACTIVE'`,
		string(excludeBinding), users, relations, objects)
	if err != nil {
		return nil, mapErr(err, "", string(excludeBinding))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(excludeBinding))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(excludeBinding))
	}
	return out, nil
}

// membershipHoldingBindingsPredicate — предикат «эта выдача держит членство
// человека в аккаунте». $1 = user_id, $2 = account_id.
//
// ЭТО КОПИЯ УСЛОВИЯ ТРИГГЕРА `membership_carrying_rights_is_kept` (миграция
// 472002), и копия намеренная: перенести его в общее место нельзя — триггер
// исполняется внутри базы на удалении строки, а это чтение идёт снаружи и после
// отказа. Копия названа копией здесь, чтобы правка одной стороны заставляла
// открыть вторую; расхождение наблюдаемо пробой, которая заводит выдачу каждой
// формы и требует, чтобы отвергнутое триггером было названо отказом.
//
// Три оси, ровно как у триггера: живая · адресует ЭТОГО человека (обе проекции
// субъекта) · в области ЭТОГО аккаунта либо его проекта.
const membershipHoldingBindingsPredicate = `
	  status = 'ACTIVE'
	  AND ( (subject_type = 'user' AND subject_id = $1)
	        OR EXISTS (SELECT 1 FROM access_binding_subjects s
	                    WHERE s.binding_id = access_bindings.id
	                      AND s.subject_type = 'user' AND s.subject_id = $1) )
	  AND ( (resource_type = 'account' AND resource_id = $2)
	        OR (resource_type = 'project'
	            AND resource_id IN (SELECT id FROM projects WHERE account_id = $2)) )`

// ListActiveHoldingMembership — выдачи, держащие членство (задача #1686).
//
// Один запрос отдаёт и ограниченный перечень, и ПОЛНУЮ величину: два запроса
// читали бы два разных снимка, и «названо 5 из 3» стало бы наблюдаемым исходом.
// Порядок — (created_at, id) ASC: отказ, называющий одни и те же выдачи в разном
// порядке от прогона к прогону, нельзя ни сравнить, ни закрепить пробой.
//
// cursor-list-table: access_bindings
//
// Объявление стоит потому, что имя таблицы в запросе СОБИРАЕТСЯ в Go (предикат
// вынесен константой ради сверки с триггером), и обход дерева его не видит.
// Без объявления индекс под этот порядок не проверялся бы никем — а порядок тут
// не украшение: он и есть то, что делает перечень воспроизводимым.
func (r *abReader) ListActiveHoldingMembership(
	ctx context.Context, userID domain.UserID, accountID domain.AccountID, limit int,
) ([]string, int, error) {
	if limit <= 0 {
		return nil, 0, nil
	}
	rows, err := r.tx.Query(ctx, `
		SELECT id, count(*) OVER () AS total
		  FROM access_bindings
		 WHERE `+membershipHoldingBindingsPredicate+`
		 ORDER BY created_at ASC, id ASC
		 LIMIT $3`, string(userID), string(accountID), limit)
	if err != nil {
		return nil, 0, mapErr(err, "", string(userID))
	}
	defer rows.Close()

	var (
		ids   []string
		total int
	)
	for rows.Next() {
		var id string
		var t int
		if err := rows.Scan(&id, &t); err != nil {
			return nil, 0, mapErr(err, "", string(userID))
		}
		ids = append(ids, id)
		total = t
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mapErr(err, "", string(userID))
	}
	return ids, total, nil
}

// ListActiveByRole returns every non-revoked (PENDING/ACTIVE) binding of a role
// (Role.Update reconcile fan-out). The set is bounded by the active
// bindings of the SINGLE mutated role. Ordered (created_at, id) ASC for
// deterministic reconcile.
func (r *abReader) ListActiveByRole(ctx context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error) {
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings
		              WHERE role_id = $1 AND status <> 'REVOKED'
		              ORDER BY created_at ASC, id ASC`, abCols), string(roleID))
	if err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, mapErr(err, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	return out, nil
}

// CountActiveByRole returns the count of non-revoked bindings of a role — the
// Role.Update fan-out bound-check (limit 10000). Cheap COUNT on role_id.
func (r *abReader) CountActiveByRole(ctx context.Context, roleID domain.RoleID) (int, error) {
	var n int
	if err := r.tx.QueryRow(ctx,
		`SELECT count(*) FROM access_bindings WHERE role_id = $1 AND status <> 'REVOKED'`,
		string(roleID)).Scan(&n); err != nil {
		return 0, mapErr(err, "", string(roleID))
	}
	return n, nil
}

// ─── multi-subject set + ListByRole ───

// ListByRole returns the bindings carrying roleID, keyset-paginated by
// (created_at, id) ASC. Mirrors the other List queries' pagination/scan/
// cursor semantics; the IncludeRevoked=false default hides REVOKED rows (a
// static predicate with no bind-arg, so this query is built inline rather than
// via listWithConds, which assumes one bind-arg per condition).
func (r *abReader) ListByRole(ctx context.Context, roleID domain.RoleID, f access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	// page_size outside [0..maxListPageSize] is REJECTED, never clamped: a clamp
	// answers 200 OK with a page shorter than asked for, and nothing in the
	// response tells that apart from a complete answer.
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}

	conditions := []string{"role_id = $1"}
	args := []any{string(roleID)}
	argIdx := 2
	if !f.IncludeRevoked {
		conditions = append(conditions, "status <> 'REVOKED'")
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, serr := scanAB(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListSubjects returns the multi-subject set of ONE binding ordered by
// (ordinal, subject_type, subject_id). Zero rows ⇒ a
// pre-backfill legacy binding; the read-side falls back to the legacy single
// subject.
func (r *abReader) ListSubjects(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.Subject, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = $1
		  ORDER BY ordinal ASC, subject_type ASC, subject_id ASC`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []domain.Subject
	for rows.Next() {
		var s domain.Subject
		if err := rows.Scan((*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// ListSubjectsForBindings batch-loads the subjects of MANY bindings in one query
// (no per-row N+1). Bindings with no rows are absent from the map.
func (r *abReader) ListSubjectsForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	out := make(map[domain.AccessBindingID][]domain.Subject, len(bindingIDs))
	if len(bindingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(bindingIDs))
	for i, id := range bindingIDs {
		ids[i] = string(id)
	}
	rows, err := r.tx.Query(ctx,
		`SELECT binding_id, subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = ANY($1)
		  ORDER BY binding_id ASC, ordinal ASC, subject_type ASC, subject_id ASC`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var bid string
		var s domain.Subject
		if err := rows.Scan(&bid, (*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", "")
		}
		key := domain.AccessBindingID(bid)
		out[key] = append(out[key], s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// ListMaterializedAtForBindings batch-loads each binding's materialization instant
// — MAX(updated_at) over its ACTIVE rows in access_binding_target_members (the
// reconciler's ledger). Bindings with no ACTIVE member are ABSENT from the map
// (the caller leaves MaterializedAt zero → the API projects an unset field).
//
// PENDING_VERIFICATION rows are deliberately excluded by the WHERE: a pending
// member is NOT live access, and reporting it would tell an administrator the
// grant works when it does not. Served by the PK's leading binding_id column, so
// this is one indexed aggregate, not an N+1 fan-out.
func (r *abReader) ListMaterializedAtForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error) {
	out := make(map[domain.AccessBindingID]time.Time, len(bindingIDs))
	if len(bindingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(bindingIDs))
	for i, id := range bindingIDs {
		ids[i] = string(id)
	}
	rows, err := r.tx.Query(ctx,
		`SELECT binding_id, MAX(updated_at)
		   FROM access_binding_target_members
		  WHERE binding_id = ANY($1)
		    AND verification_status = 'ACTIVE'
		  GROUP BY binding_id`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var (
			bid string
			at  time.Time
		)
		if err := rows.Scan(&bid, &at); err != nil {
			return nil, mapErr(err, "", "")
		}
		out[domain.AccessBindingID(bid)] = at
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// InsertSubjects persists the multi-subject set of a binding. One row per
// subject, idempotent (ON CONFLICT DO NOTHING — re-insert is a no-op; the PK
// row-lock serializes concurrent identical inserts to exactly one row, ban #10).
// The ordinal preserves request order so subjects[0] (= the legacy single
// projection) is deterministic.
func (w *abWriter) InsertSubjects(ctx context.Context, bindingID domain.AccessBindingID, subjects []domain.Subject) error {
	if len(subjects) == 0 {
		return nil
	}
	for i, s := range subjects {
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING`,
			string(bindingID), string(s.Type), string(s.ID), i,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// DeleteSubject removes ONE subject's row (per-subject revoke) and reports
// whether a row was actually deleted (idempotent — a missing subject ⇒ false).
func (w *abWriter) DeleteSubject(ctx context.Context, bindingID domain.AccessBindingID, subject domain.Subject) (bool, error) {
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_subjects
		  WHERE binding_id = $1 AND subject_type = $2 AND subject_id = $3`,
		string(bindingID), string(subject.Type), string(subject.ID))
	if err != nil {
		return false, mapErr(err, "AccessBinding.DeleteSubject", string(bindingID))
	}
	return tag.RowsAffected() > 0, nil
}

// nullableString — пустую строку как NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUserIDPtr — *UserID → string/nil для pgx (NULL когда указатель nil
// либо пустой).
func nullableUserIDPtr(u *domain.UserID) any {
	if u == nil || *u == "" {
		return nil
	}
	return string(*u)
}
