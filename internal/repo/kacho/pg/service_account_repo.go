// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// service_account_repo.go — pgxpool-impl для service_account.ReaderIface / WriterIface.
//
// Ban #10 (within-service refs — DB-уровень):
//   - FK service_accounts_account_fk (23503).
//   - UNIQUE service_accounts_account_name_unique (23505).
//   - Delete: atomic CAS WHERE NOT EXISTS на access_bindings + group_members
//     (subject_type='service_account'/'service_account'). probe для NotFound vs
//     FailedPrecondition + канонический Kachō error-text.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
)

type saReader struct {
	tx pgx.Tx
}

// saCols — every column a caller of this aggregate is entitled to see.
//
// `enabled` is part of it because it decides whether the account may
// authenticate, and a projection that leaves it out hands every caller the same
// zero value: false for an enabled account and false for a disabled one, with
// nothing able to tell them apart. That is not a missing convenience, it is a
// state nobody downstream can read — including the operator who set it.
const saCols = "id, account_id, name, description, labels, created_at, enabled"

func (r *saReader) Get(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM service_accounts WHERE id = $1`, saCols), string(id))
	out, err := scanSA(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
		}
		return domain.ServiceAccount{}, mapErr(err, "", string(id))
	}
	return out, nil
}

func (r *saReader) List(ctx context.Context, f service_account.ListFilter) ([]domain.ServiceAccount, string, error) {
	pageSize, err := effectivePageSize(f.PageSize) // #184: reject >max, no silent clamp
	if err != nil {
		return nil, "", err
	}
	conditions := []string{}
	args := []any{}
	argIdx := 1
	if f.AccountID != "" {
		conditions = append(conditions, fmt.Sprintf("account_id = $%d", argIdx))
		args = append(args, string(f.AccountID))
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

	// Сужение набора КАНДИДАТОВ (задача #645). Оно стоит здесь, в отборе строк, а
	// не после него: постфильтр по видимости теряет всякую служебную учётку, перед
	// которой лежит больше `page_size` невидимых предшественников — она до фильтра
	// просто не доезжает.
	//
	// nil — не сужать (администратор облака); непустой указатель с пустыми
	// наборами не называет ни одной строки и потому не пропускает ни одной.
	if f.Candidates != nil {
		conditions = append(conditions,
			fmt.Sprintf("(account_id = ANY($%d) OR id = ANY($%d))", argIdx, argIdx+1))
		args = append(args, nonNilStrings(f.Candidates.AccountIDs), nonNilStrings(f.Candidates.ObjectIDs))
		argIdx += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	q := fmt.Sprintf(`SELECT %s FROM service_accounts %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		saCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.ServiceAccount
	for rows.Next() {
		sa, err := scanSA(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, sa)
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

type saWriter struct {
	saReader
}

func (w *saWriter) Insert(ctx context.Context, sa domain.ServiceAccount) (domain.ServiceAccount, error) {
	now := time.Now().UTC()
	labelsJSON, err := marshalLabels(sa.Labels)
	if err != nil {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	q := fmt.Sprintf(`
		INSERT INTO service_accounts (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, saCols)
	row := w.tx.QueryRow(ctx, q,
		string(sa.ID), string(sa.AccountID), string(sa.Name), string(sa.Description), labelsJSON, now,
	)
	out, err := scanSA(row)
	if err != nil {
		return domain.ServiceAccount{}, mapErr(err, "", string(sa.Name))
	}
	return out, nil
}

func (w *saWriter) Update(ctx context.Context, sa domain.ServiceAccount, updateMask []string) (domain.ServiceAccount, error) {
	mutableFields := map[string]bool{"name": true, "description": true, "labels": true}
	apply := map[string]bool{}
	if len(updateMask) == 0 {
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range updateMask {
			if !mutableFields[f] {
				return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument update_mask field %q", f)
			}
			apply[f] = true
		}
	}
	parts := []string{}
	args := []any{}
	idx := 1
	if apply["name"] {
		parts = append(parts, fmt.Sprintf("name = $%d", idx))
		args = append(args, string(sa.Name))
		idx++
	}
	if apply["description"] {
		parts = append(parts, fmt.Sprintf("description = $%d", idx))
		args = append(args, string(sa.Description))
		idx++
	}
	if apply["labels"] {
		labelsJSON, err := marshalLabels(sa.Labels)
		if err != nil {
			return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
		}
		parts = append(parts, fmt.Sprintf("labels = $%d", idx))
		args = append(args, labelsJSON)
	}
	if len(parts) == 0 {
		return w.Get(ctx, sa.ID)
	}
	args = append(args, string(sa.ID))
	q := fmt.Sprintf(`UPDATE service_accounts SET %s WHERE id = $%d RETURNING %s`,
		strings.Join(parts, ", "), len(args), saCols)
	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanSA(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", sa.ID)
		}
		return domain.ServiceAccount{}, mapErr(err, "", string(sa.Name))
	}
	return out, nil
}

// SetEnabled writes `enabled` — the state that decides whether this service
// account may authenticate.
//
// One statement, and the argument is the state rather than a transition: the
// row ends up holding what was asked for whether or not it already did. There
// is nothing to serialise here — two callers asking for the same state agree,
// and a compare-and-set would buy no invariant while turning the retry of a
// disable into a failure, which is the direction that must never be hard to
// reach.
//
// What this does NOT settle, and must not be read as settling: the ORDER of two
// opposite requests. That is not decided at this statement — the use-case hands
// the write to a background worker, so request order does not determine commit
// order at all (see set_enabled.go). Nothing available at this layer could fix
// that, and a row lock is not what would.
//
// The whole row comes back so the caller can name the account in an audit
// record without a second read.
func (w *saWriter) SetEnabled(ctx context.Context, id domain.ServiceAccountID, enabled bool) (domain.ServiceAccount, error) {
	q := fmt.Sprintf(`UPDATE service_accounts SET enabled = $2 WHERE id = $1 RETURNING %s`, saCols)
	row := w.tx.QueryRow(ctx, q, string(id), enabled)
	out, err := scanSA(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
		}
		return domain.ServiceAccount{}, mapErr(err, "ServiceAccount.SetEnabled", string(id))
	}
	return out, nil
}

// Delete — атомарный DELETE с гвардом NOT EXISTS на access_bindings +
// access_binding_subjects + group_members.
//
// The access_bindings guard covers the legacy subjects[0] projection; the
// access_binding_subjects guard covers subjects[1..N] — an independent grantee of a
// multi-subject binding (migration 0028) the subjects[0]-only guard missed (SEC r8,
// hard-rule #10). The concurrent delete-vs-add-subject window is closed at the DB
// level by the BEFORE DELETE trigger (migration 0050); this software guard is the
// fast common-case reject + canonical error text.
func (w *saWriter) Delete(ctx context.Context, id domain.ServiceAccountID) error {
	const q = `
		WITH del AS (
			DELETE FROM service_accounts s
			WHERE s.id = $1
			  AND NOT EXISTS (SELECT 1 FROM access_bindings         WHERE subject_type = 'service_account' AND subject_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM access_binding_subjects WHERE subject_type = 'service_account' AND subject_id = $1)
			  AND NOT EXISTS (SELECT 1 FROM group_members           WHERE member_type  = 'service_account' AND member_id  = $1)
			RETURNING 1
		)
		SELECT
		  (SELECT count(*) FROM del)::int                                                                                     AS deleted,
		  EXISTS(SELECT 1 FROM service_accounts WHERE id = $1)                                                                AS sa_exists,
		  (EXISTS(SELECT 1 FROM access_bindings         WHERE subject_type='service_account' AND subject_id = $1)
		   OR EXISTS(SELECT 1 FROM access_binding_subjects WHERE subject_type='service_account' AND subject_id = $1))         AS has_bindings,
		  EXISTS(SELECT 1 FROM group_members WHERE member_type='service_account' AND member_id = $1)                          AS has_group_mems
	`
	var (
		deleted                             int
		saExists, hasBindings, hasGroupMems bool
	)
	err := w.tx.QueryRow(ctx, q, string(id)).Scan(&deleted, &saExists, &hasBindings, &hasGroupMems)
	if err != nil {
		return mapErr(err, "ServiceAccount.Delete", string(id))
	}
	if deleted == 1 {
		return nil
	}
	if !saExists {
		return iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
	}
	switch {
	case hasBindings:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"ServiceAccount %s has active access bindings and cannot be deleted", id)
	case hasGroupMems:
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"ServiceAccount %s is a member of one or more groups and cannot be deleted", id)
	}
	return iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
}

func scanSA(row scanner) (domain.ServiceAccount, error) {
	var (
		sa         domain.ServiceAccount
		labelsJSON []byte
	)
	err := row.Scan(
		(*string)(&sa.ID),
		(*string)(&sa.AccountID),
		(*string)(&sa.Name),
		(*string)(&sa.Description),
		&labelsJSON,
		&sa.CreatedAt,
		&sa.Enabled,
	)
	if err != nil {
		return domain.ServiceAccount{}, err
	}
	sa.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.ServiceAccount{}, err
	}
	return sa, nil
}
