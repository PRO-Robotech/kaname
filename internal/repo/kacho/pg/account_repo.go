// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// account_repo.go — pgxpool-impl for account.ReaderIface / WriterIface.
//
// Reader / Writer run over an arbitrary pgx.Tx (read-only / RW); outbox emit
// is a separate step driven by the use-case (see tx.go).
//
// Within-service refs — DB-level invariants:
//   - UNIQUE (name) — accounts_name_unique → 23505 → ErrAlreadyExists.
//   - FK accounts_owner_fk on users(id) RESTRICT — 23503 → ErrFailedPrecondition.
//   - Delete-non-empty (projects/SAs/groups/custom-roles) — atomic
//     DELETE-WHERE-NOT-EXISTS (see Delete below): 0 rows RETURNING + probe to
//     distinguish NotFound vs FailedPrecondition.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// accountReader — Get/List/ExistsByName поверх pgx.Tx (read-only или RW).
type accountReader struct {
	tx pgx.Tx
}

const accountCols = "id, name, description, labels, owner_user_id, created_at"

// Get — well-formed-but-absent → NotFound с "Account <id> not found".
func (r *accountReader) Get(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	q := fmt.Sprintf(`SELECT %s FROM accounts WHERE id = $1`, accountCols)
	row := r.tx.QueryRow(ctx, q, string(id))
	a, err := scanAccount(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Account{}, iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
		}
		return domain.Account{}, mapErr(err, "", string(id))
	}
	return a, nil
}

// List — cursor-based pagination + опционально filter по name (минимальный фильтр).
// Простой List без полного filter-парсера (он живет в corelib и нужен для
// API-уровня; здесь — внутренняя CQRS-iface).
func (r *accountReader) List(ctx context.Context, f account.ListFilter) ([]domain.Account, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}

	conditions := []string{}
	args := []any{}
	argIdx := 1
	if f.Filter != "" {
		// Минимальный синтаксис `name="value"`.
		if name, ok := parseNameFilter(f.Filter); ok {
			conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
			args = append(args, name)
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
	q := fmt.Sprintf(`SELECT %s FROM accounts %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		accountCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, a)
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

// ExistsByName — отдельный метод iface; use-case'ы его не используют
// (запрет #10: UNIQUE-конструкция на DB-уровне — единственный backstop).
func (r *accountReader) ExistsByName(ctx context.Context, name domain.AccountName) (bool, error) {
	var exists bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM accounts WHERE name = $1)`, string(name)).
		Scan(&exists)
	if err != nil {
		return false, mapErr(err, "", string(name))
	}
	return exists, nil
}

// CountAccountsByOwner — COUNT(*) accounts WHERE owner_user_id = $1. Backs the
// RC-5 "owns-zero-accounts" bootstrap gate (use-case #10-safe read: it gates a
// bootstrap that re-checks the DB UNIQUE/FK invariants on write, not a
// software-only mutation guard). Unknown user → 0 (no error).
func (r *accountReader) CountAccountsByOwner(ctx context.Context, ownerUserID domain.UserID) (int, error) {
	var n int
	err := r.tx.QueryRow(ctx,
		`SELECT count(*) FROM accounts WHERE owner_user_id = $1`, string(ownerUserID)).
		Scan(&n)
	if err != nil {
		return 0, mapErr(err, "", string(ownerUserID))
	}
	return n, nil
}

// accountWriter — DML над accounts через writer-TX. Embeds accountReader
// (G.2 — writer видит свои writes в рамках той же TX).
type accountWriter struct {
	accountReader
	// ownerFKHintSink — optional back-pointer into the enclosing writeTx (set by
	// writeTx.AccountsW). accounts_owner_fk is DEFERRABLE INITIALLY DEFERRED, so an
	// owner that does not exist is NOT caught by this INSERT statement — the 23503
	// surfaces at COMMIT. On a successful (deferred) INSERT we record the owner id
	// here so writeTx.Commit can render the canonical "User <id> not found" text if
	// the deferred FK fires at commit-time (otherwise the raw pgx error would hit
	// the sentinel-only INTERNAL fallback in shared.MapRepoErr).
	ownerFKHintSink *string
}

// Insert — INSERT INTO accounts ... RETURNING (id, created_at).
// CreatedAt здесь явно проставляется в UTC для детерминированности тестов
// (parity с kacho-vpc/internal/repo/kacho/pg/network.go::Insert).
func (w *accountWriter) Insert(ctx context.Context, a domain.Account) (domain.Account, error) {
	labelsJSON, err := marshalLabels(a.Labels)
	if err != nil {
		return domain.Account{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO accounts (id, name, description, labels, owner_user_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, accountCols)

	row := w.tx.QueryRow(ctx, q,
		string(a.ID), string(a.Name), string(a.Description), labelsJSON,
		string(a.OwnerUserID), now,
	)
	out, err := scanAccount(row)
	if err != nil {
		// На UNIQUE / FK / CHECK идем через mapErr с verbatim-text hint'ами.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return domain.Account{}, mapErr(err, "", string(a.Name)) // accounts_name_unique → "Account with name <name> already exists"
			case "23503":
				return domain.Account{}, mapErr(err, "", string(a.OwnerUserID)) // accounts_owner_fk → "User <id> not found"
			case "23514":
				return domain.Account{}, mapErr(err, "", "")
			}
		}
		return domain.Account{}, mapErr(err, "", string(a.ID))
	}
	// Deferred accounts_owner_fk: the INSERT succeeded but the owner-existence
	// check runs at COMMIT. Record the owner id so writeTx.Commit can produce the
	// canonical "User <id> not found" text on a commit-time 23503.
	if w.ownerFKHintSink != nil {
		*w.ownerFKHintSink = string(a.OwnerUserID)
	}
	return out, nil
}

// Update — UPDATE на mutable полях (name, description, labels). owner_user_id
// hard-immutable — отвергнут на sync-уровне use-case'а (ErrInvalidArg), сюда
// не доходит.
//
// Mask может содержать "name" / "description" / "labels"; пустой mask
// (full-PATCH) применяется как «обновить все три». Caller (use-case) уже
// отфильтровал immutable.
func (w *accountWriter) Update(ctx context.Context, a domain.Account, updateMask []string) (domain.Account, error) {
	labelsJSON, err := marshalLabels(a.Labels)
	if err != nil {
		return domain.Account{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}

	set, args, err := buildAccountUpdateSet(a, labelsJSON, updateMask)
	if err != nil {
		return domain.Account{}, err
	}
	if set == "" {
		// Mask без mutable-полей → no-op; вернуть текущую row.
		return w.Get(ctx, a.ID)
	}
	args = append(args, string(a.ID))
	q := fmt.Sprintf(`UPDATE accounts SET %s WHERE id = $%d RETURNING %s`,
		set, len(args), accountCols)

	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanAccount(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Account{}, iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", a.ID)
		}
		return domain.Account{}, mapErr(err, "", string(a.Name))
	}
	return out, nil
}

// Delete — атомарный DELETE-WHERE-NOT-EXISTS (запрет #10 — within-service refs
// обязаны держаться на DB-уровне).
//
// Сначала пытаемся DELETE с гвардом NOT EXISTS на projects/service_accounts/
// groups/roles. Если 0 rows — это либо «не существует», либо «есть дети» —
// проверяем через `SELECT EXISTS(... id=$1)` и возвращаем соответствующий sentinel:
//   - row есть   → есть хотя бы один child → ErrFailedPrecondition
//   - row нет    → ErrNotFound
//
// Это race-safe: DELETE атомарен (row-level lock на конкретной row + sub-SELECT
// EXISTS в одной WHERE-clause), параллельная попытка Insert-child будет либо
// до DELETE (тогда не пройдет FK ON DELETE RESTRICT и DELETE упадет сам), либо
// после (тогда дочерний INSERT не пройдет FK на удаленный account_id, 23503).
//
// **Замечание**: можно было бы положиться **только** на FK RESTRICT (Postgres
// поднимет 23503 при попытке DELETE с детьми), но тогда точный текст ошибки
// зависит от того, какой child-FK сработал первым — недетерминирован. Атомарный
// gate с custom-text дает стабильное сообщение, FK остается backstop'ом для
// race-конкурента.
func (w *accountWriter) Delete(ctx context.Context, id domain.AccountID) error {
	const q = `
		WITH del AS (
			DELETE FROM accounts a
			WHERE a.id = $1
			  AND NOT EXISTS (SELECT 1 FROM projects         WHERE account_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM service_accounts WHERE account_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM groups           WHERE account_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM roles            WHERE account_id = $1)
			RETURNING 1
		)
		SELECT
		  (SELECT count(*) FROM del)::int AS deleted,
		  EXISTS(SELECT 1 FROM accounts        WHERE id = $1)        AS account_exists,
		  EXISTS(SELECT 1 FROM projects        WHERE account_id = $1) AS has_projects,
		  EXISTS(SELECT 1 FROM service_accounts WHERE account_id = $1) AS has_sas,
		  EXISTS(SELECT 1 FROM groups          WHERE account_id = $1)  AS has_groups,
		  EXISTS(SELECT 1 FROM roles           WHERE account_id = $1)  AS has_roles
	`
	var (
		deleted                                                 int
		accountExists, hasProjects, hasSAs, hasGroups, hasRoles bool
	)
	err := w.tx.QueryRow(ctx, q, string(id)).
		Scan(&deleted, &accountExists, &hasProjects, &hasSAs, &hasGroups, &hasRoles)
	if err != nil {
		return mapErr(err, "Account.Delete", string(id))
	}
	if deleted == 1 {
		return nil
	}
	// Не удалили: либо нет, либо есть дети. Probe-результаты выше.
	if !accountExists {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
	}
	switch {
	case hasProjects:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Account %s contains projects and cannot be deleted", id)
	case hasSAs:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Account %s contains service accounts and cannot be deleted", id)
	case hasGroups:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Account %s contains groups and cannot be deleted", id)
	case hasRoles:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Account %s contains custom roles and cannot be deleted", id)
	}
	// Race: row исчез между DELETE-step и probe-SELECT (другой коммит). NotFound.
	return iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", id)
}

// ---- helpers ---------------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func scanAccount(row scanner) (domain.Account, error) {
	var (
		a          domain.Account
		labelsJSON []byte
	)
	err := row.Scan(
		(*string)(&a.ID),
		(*string)(&a.Name),
		(*string)(&a.Description),
		&labelsJSON,
		(*string)(&a.OwnerUserID),
		&a.CreatedAt,
	)
	if err != nil {
		return domain.Account{}, err
	}
	a.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Account{}, err
	}
	return a, nil
}

func marshalLabels(l domain.Labels) ([]byte, error) {
	if len(l) == 0 {
		return []byte(`{}`), nil
	}
	// stable map для предсказуемого вывода (JSON-объект сам по себе unordered,
	// но driver-level marshalling может варьироваться — encode'им через
	// map[string]string).
	m := make(map[string]string, len(l))
	for k, v := range l {
		m[string(k)] = string(v)
	}
	return json.Marshal(m)
}

func unmarshalLabels(b []byte) (domain.Labels, error) {
	if len(b) == 0 {
		return domain.Labels{}, nil
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshal labels: %w", err)
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out, nil
}

func buildAccountUpdateSet(a domain.Account, labelsJSON []byte, mask []string) (string, []any, error) {
	mutableFields := map[string]bool{"name": true, "description": true, "labels": true}
	apply := map[string]bool{}
	if len(mask) == 0 {
		// full-PATCH: применяем все mutable, immutable из тела silent-ignore
		// (отфильтрован caller'ом по semantic'у "full-PATCH = body wins on mutable only").
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range mask {
			if !mutableFields[f] {
				// caller гарантирует, что immutable/unknown отвергнуты на sync-уровне;
				// сюда не должно прилететь.
				return "", nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument update_mask field %q", f)
			}
			apply[f] = true
		}
	}

	parts := []string{}
	args := []any{}
	idx := 1
	if apply["name"] {
		parts = append(parts, fmt.Sprintf("name = $%d", idx))
		args = append(args, string(a.Name))
		idx++
	}
	if apply["description"] {
		parts = append(parts, fmt.Sprintf("description = $%d", idx))
		args = append(args, string(a.Description))
		idx++
	}
	if apply["labels"] {
		parts = append(parts, fmt.Sprintf("labels = $%d", idx))
		args = append(args, labelsJSON)
	}
	return strings.Join(parts, ", "), args, nil
}

// ---- filter / page-token helpers ------------------------------------------

func parseNameFilter(s string) (string, bool) {
	// Минимальный парсер: `name="<value>"` либо `name = "<value>"`.
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "name") {
		return "", false
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "name"))
	if !strings.HasPrefix(s, "=") {
		return "", false
	}
	s = strings.TrimSpace(strings.TrimPrefix(s, "="))
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", false
	}
	return s[1 : len(s)-1], true
}

func encodePageToken(ts time.Time, id string) string {
	// Простой формат: `<RFC3339Nano>|<id>` через base64-URL.
	raw := ts.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64URLEncode([]byte(raw))
}

func decodePageToken(token string) (time.Time, string, error) {
	raw, err := base64URLDecode(token)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid page_token format")
	}
	ts, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	return ts, parts[1], nil
}
