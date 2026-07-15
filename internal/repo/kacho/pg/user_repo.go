// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// user_repo.go — pgxpool-impl для user.ReaderIface / WriterIface.
//
// User is scoped per-Account (один Kratos identity → N User-row); поля
// {account_id, invite_status, invited_by} живут в users.
//
// Within-service refs — DB-level invariants:
//   - UNIQUE (account_id, lower(email))                      → 23505 / iamerr.ErrAlreadyExists
//   - UNIQUE (account_id, external_id) WHERE external_id<>'' → 23505 / iamerr.ErrAlreadyExists
//   - DEFERRABLE FK users.account_id → accounts(id)          → 23503 на COMMIT
//   - DEFERRABLE FK accounts.owner_user_id → users(id)       → 23503 на COMMIT
//   - CHECK users_invite_status_consistency (PENDING ⇔ external_id='')
//   - InsertPending: атомарный ON CONFLICT (account_id, lower(email)) DO NOTHING +
//                    SELECT existing — race-safe.
//   - ActivateInvite: атомарный UPDATE … WHERE invite_status='PENDING' RETURNING — 0 rows ⇒ NotFound.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
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

// GetByExternalID — возвращает первую ACTIVE-row с таким external_id среди
// всех Account'ов. Caller обычно знает targetAccount — используй
// GetByAccountEmail или FindActiveByExternalID.
//
// `ORDER BY created_at ASC` — детерминированный выбор. Это тот же row, что
// api-gateway резолвит через InternalIAMService.LookupSubject (subject-identity
// для per-RPC authz). Без ORDER BY Postgres возвращал произвольный
// physical-order row: для identity с N ACTIVE-rows (один человек = N rows,
// по одной на Account) gateway мог резолвить один row, а invite-flow создать
// AccessBinding на другой → FGA `no path`. Канонический row = старейший ACTIVE
// — он же первый bootstrap-row identity, на него invite-flow и вешает
// project-scoped grant.
func (r *userReader) GetByExternalID(ctx context.Context, ext domain.ExternalSubject) (domain.User, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE external_id = $1 AND invite_status = 'ACTIVE' ORDER BY created_at ASC LIMIT 1`, userCols),
		string(ext))
	u, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User with external_id not found")
		}
		return domain.User{}, mapErr(err, "", string(ext))
	}
	return u, nil
}

// GetByEmail — cross-Account lookup, возвращает первую row (любого
// invite_status). Caller должен знать target Account — используй
// GetByAccountEmail.
func (r *userReader) GetByEmail(ctx context.Context, email domain.Email) (domain.User, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE lower(email) = lower($1) LIMIT 1`, userCols),
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
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM users WHERE account_id = $1 AND lower(email) = lower($2)`, userCols),
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

// FindPendingByEmail — все PENDING-row'ы по email через все Account'ы.
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
// Account'ы. ORDER BY created_at ASC — actives[0] совпадает с тем, что
// возвращает GetByExternalID (тот же ORDER) и, следовательно, api-gateway
// InternalIAMService.LookupSubject. Используется invite-flow'ом для привязки
// project-scoped AccessBinding к канонической identity-row.
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

// ListAccountsForUser — все Account'ы, где у user'а есть ACTIVE-row или где
// user является owner'ом (default-deny scope для UserService.List).
//
// Включает аккаунты, созданные через AccountService.Create с owner_user_id =
// userID (в таком случае в `users` нет ACTIVE-строки с account_id = новый
// аккаунт, но аккаунт реально принадлежит пользователю), и аккаунты, в которых
// у principal есть ACTIVE AccessBinding с resource_type='account', даже если
// его users-row там еще PENDING (приглашение).
//
// Полный набор аккаунтов, которые видит принципал =
//
//	(1) аккаунт bootstrap-row (users.account_id WHERE users.id = $1 ACTIVE)
//	UNION
//	(2) аккаунты, где principal является owner (accounts.owner_user_id = $1)
//	UNION
//	(3) аккаунты, на которые у principal есть ACTIVE AccessBinding
//	    (resource_type='account', subject_type='user', subject_id=$1)
//
// UNION автоматически устраняет дубли.
func (r *userReader) ListAccountsForUser(ctx context.Context, userID domain.UserID) ([]domain.AccountID, error) {
	rows, err := r.tx.Query(ctx, `
		SELECT account_id FROM users WHERE id = $1 AND invite_status = 'ACTIVE'
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

func (r *userReader) List(ctx context.Context, f user.ListFilter) ([]domain.User, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // #184: reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1

	// AccountID filter (single).
	if f.AccountID != "" {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", argIdx))
		args = append(args, string(f.AccountID))
		argIdx++
	}
	// AccountIDs filter (multi). Применяется только если AccountID не задан.
	if f.AccountID == "" && len(f.AccountIDs) > 0 {
		placeholders := make([]string, 0, len(f.AccountIDs))
		for _, acc := range f.AccountIDs {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argIdx))
			args = append(args, string(acc))
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("account_id IN (%s)", strings.Join(placeholders, ",")))
	}

	if f.Filter != "" {
		if email, ok := parseFieldFilter(f.Filter, "email"); ok {
			conditions = append(conditions, fmt.Sprintf("lower(email) = lower($%d)", argIdx))
			args = append(args, email)
			argIdx++
		} else if ext, ok := parseFieldFilter(f.Filter, "external_id"); ok {
			conditions = append(conditions, fmt.Sprintf("external_id = $%d", argIdx))
			args = append(args, ext)
			argIdx++
		} else if st, ok := parseFieldFilter(f.Filter, "invite_status"); ok {
			conditions = append(conditions, fmt.Sprintf("invite_status = $%d", argIdx))
			args = append(args, st)
			argIdx++
		}
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
}

// Upsert — legacy path retained for backward-compat with integration tests
// that call Upsert directly (TestUser_2_0_15a/15b).
//
// The unique-индекс на external_id — per-Account (partial WHERE external_id<>”).
// Upsert делает INSERT с {AccountID + invite_status='ACTIVE'}; при дубле
// (account_id, external_id) → UPDATE email/display_name.
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

	// AccountID требуется: подцепляем UPSERT по external_id уникальному в
	// Account'е (без account_id это невозможно). Тесты должны сами создать
	// Account перед Upsert. Используется partial UNIQUE
	// (account_id, external_id) WHERE external_id<>''.
	q := fmt.Sprintf(`
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, invited_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (account_id, external_id) WHERE external_id <> '' DO UPDATE
		   SET email = EXCLUDED.email,
		       display_name = EXCLUDED.display_name
		RETURNING %s, (xmax = 0) AS created`, userCols)
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

// InsertPending — атомарный idempotent INSERT PENDING-row.
//
// SQL:
//
//	INSERT INTO users (..., invite_status='PENDING', external_id='') VALUES (...)
//	ON CONFLICT (account_id, lower(email)) DO NOTHING
//	RETURNING ... ;
//
// Если CONFLICT — DO NOTHING не возвращает row. Делаем backstop SELECT по
// (account_id, lower(email)). Возвращаем (existing, inserted=false).
// Race-safe: оба пути атомарны на DB-уровне.
func (w *userWriter) InsertPending(ctx context.Context, u domain.User) (domain.User, bool, error) {
	now := time.Now().UTC()
	invitedBy := nullableInvitedBy(u.InvitedBy)

	// INSERT … ON CONFLICT … DO NOTHING RETURNING + UNION SELECT existing.
	// CTE-форма обеспечивает атомарность и единый result set вне зависимости от
	// того, был ли INSERT или конфликт.
	q := fmt.Sprintf(`
		WITH ins AS (
			INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, invited_by, created_at)
			VALUES ($1, $2, '', $3, $4, 'PENDING', $5, $6)
			ON CONFLICT (account_id, lower(email)) DO NOTHING
			RETURNING %s
		)
		SELECT %s, true AS inserted FROM ins
		UNION ALL
		SELECT %s, false AS inserted FROM users
		WHERE account_id = $2 AND lower(email) = lower($3)
		  AND NOT EXISTS (SELECT 1 FROM ins)
		LIMIT 1`, userCols, userCols, userCols)

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

// ReEnable — атомарный CAS BLOCKED → ACTIVE для recovery (OnRecoveryCompleted).
//
// SQL (single-statement UPDATE … FROM (SELECT … FOR UPDATE)):
//
//	UPDATE users u
//	   SET invite_status = 'ACTIVE'
//	  FROM (SELECT id, invite_status FROM users WHERE id = $1 FOR UPDATE) old
//	 WHERE u.id = old.id AND old.invite_status IN ('ACTIVE','BLOCKED')
//	RETURNING u.<cols>, (old.invite_status = 'BLOCKED') AS was_blocked
//
// The `FROM (… FOR UPDATE)` subquery snapshots the PRE-image row (and row-locks
// it) before the UPDATE applies, so `old.invite_status` is the OLD value while
// `RETURNING u.*` is the new row — was_blocked is computed correctly in one
// statement. Idempotent: an already-ACTIVE row passes (no-op, not an error). 0
// rows RETURNING → ErrNotFound (row absent or PENDING — recovery works only on
// ACTIVE/BLOCKED). The row-lock serializes concurrent writers (запрет #10, not
// TOCTOU).
func (w *userWriter) ReEnable(ctx context.Context, userID domain.UserID) (domain.User, bool, error) {
	q := fmt.Sprintf(`
		UPDATE users u
		   SET invite_status = 'ACTIVE'
		  FROM (SELECT id, invite_status FROM users WHERE id = $1 FOR UPDATE) old
		 WHERE u.id = old.id AND old.invite_status IN ('ACTIVE', 'BLOCKED')
		RETURNING %s, (old.invite_status = 'BLOCKED') AS was_blocked`, userColsQualified("u"))
	row := w.tx.QueryRow(ctx, q, string(userID))
	var (
		out        domain.User
		wasBlocked bool
	)
	if err := scanUserWithBool(row, &out, &wasBlocked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, false, iamerr.Wrapf(iamerr.ErrNotFound,
				"User %s not found", userID)
		}
		return domain.User{}, false, mapErr(err, "", string(userID))
	}
	return out, wasBlocked, nil
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

// ---- helpers ---------------------------------------------------------------

func scanUser(row scanner) (domain.User, error) {
	var (
		u            domain.User
		accountID    sql.NullString
		externalID   sql.NullString
		displayName  sql.NullString
		inviteStatus sql.NullString
		invitedBy    sql.NullString
		labelsJSON   []byte
	)
	err := row.Scan(
		(*string)(&u.ID),
		&accountID,
		&externalID,
		(*string)(&u.Email),
		&displayName,
		&inviteStatus,
		&invitedBy,
		&u.CreatedAt,
		&labelsJSON,
	)
	if err != nil {
		return domain.User{}, err
	}
	if accountID.Valid {
		u.AccountID = domain.AccountID(accountID.String)
	}
	if externalID.Valid {
		u.ExternalID = domain.ExternalSubject(externalID.String)
	}
	if displayName.Valid {
		u.DisplayName = domain.DisplayName(displayName.String)
	}
	if inviteStatus.Valid {
		u.InviteStatus = domain.InviteStatus(inviteStatus.String)
	}
	if invitedBy.Valid {
		u.InvitedBy = domain.UserID(invitedBy.String)
	}
	u.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.User{}, err
	}
	return u, nil
}

func scanUserWithCreated(row scanner, out *domain.User, created *bool) error {
	var (
		accountID    sql.NullString
		externalID   sql.NullString
		displayName  sql.NullString
		inviteStatus sql.NullString
		invitedBy    sql.NullString
		labelsJSON   []byte
	)
	if err := row.Scan(
		(*string)(&out.ID),
		&accountID,
		&externalID,
		(*string)(&out.Email),
		&displayName,
		&inviteStatus,
		&invitedBy,
		&out.CreatedAt,
		&labelsJSON,
		created,
	); err != nil {
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

func scanUserWithInserted(row scanner, out *domain.User, inserted *bool) error {
	return scanUserWithCreated(row, out, inserted)
}

// scanUserWithBool — scanUser + одна trailing bool-колонка (used by ReEnable's
// was_blocked). Shares the same column order as userCols.
func scanUserWithBool(row scanner, out *domain.User, b *bool) error {
	return scanUserWithCreated(row, out, b)
}

// userColsQualified — userCols с table-alias-префиксом (для CTE-JOIN SELECT'ов,
// где userCols фигурируют как `upd.*`-эквивалент колонок без ambiguity).
func userColsQualified(alias string) string {
	parts := strings.Split(userCols, ", ")
	for i, p := range parts {
		parts[i] = alias + "." + p
	}
	return strings.Join(parts, ", ")
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

// parseFieldFilter — generalized parseNameFilter для arbitrary field-name.
// Принимает `<field>="value"` либо `<field> = "value"`.
func parseFieldFilter(s, field string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, field) {
		return "", false
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, field))
	if !strings.HasPrefix(s, "=") {
		return "", false
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "="))
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	return s[1 : len(s)-1], true
}
