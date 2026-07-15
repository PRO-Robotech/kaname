// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// project_repo.go — pgxpool-impl для project.ReaderIface / WriterIface.
//
// Ban #10 (within-service refs — DB-уровень):
//   - FK projects_account_fk на accounts(id) ON DELETE RESTRICT (23503).
//   - UNIQUE projects_account_name_unique (account_id, name) (23505).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

// projectReader — Get/List/CountByAccount поверх pgx.Tx.
type projectReader struct {
	tx pgx.Tx
}

const projectCols = "id, account_id, name, description, labels, created_at"

// Get — Kachō contract: well-formed-но-несуществующий → NotFound "Project <id> not found".
func (r *projectReader) Get(ctx context.Context, id domain.ProjectID) (domain.Project, error) {
	q := fmt.Sprintf(`SELECT %s FROM projects WHERE id = $1`, projectCols)
	row := r.tx.QueryRow(ctx, q, string(id))
	p, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Project{}, iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
		}
		return domain.Project{}, mapErr(err, "", string(id))
	}
	return p, nil
}

// List — cursor pagination + опц. filter (name="…") + опц. AccountID scope.
func (r *projectReader) List(ctx context.Context, f project.ListFilter) ([]domain.Project, string, error) {
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
	q := fmt.Sprintf(`SELECT %s FROM projects %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		projectCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, p)
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

// CountByAccount — для AccountService.Delete sync precheck (iface compatibility).
// Production path не использует (DELETE-WHERE-NOT-EXISTS в account_repo race-safe).
func (r *projectReader) CountByAccount(ctx context.Context, accountID domain.AccountID) (int64, error) {
	var n int64
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM projects WHERE account_id = $1`, string(accountID)).Scan(&n)
	if err != nil {
		return 0, mapErr(err, "", string(accountID))
	}
	return n, nil
}

// projectWriter — DML над projects через writer-TX.
type projectWriter struct {
	projectReader
}

// Insert — INSERT INTO projects ... RETURNING ...
// FK projects_account_fk (23503) — account_id не существует → FailedPrecondition.
// UNIQUE projects_account_name_unique (23505) — дубль name per account → AlreadyExists.
func (w *projectWriter) Insert(ctx context.Context, p domain.Project) (domain.Project, error) {
	labelsJSON, err := marshalLabels(p.Labels)
	if err != nil {
		return domain.Project{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	now := time.Now().UTC()
	q := fmt.Sprintf(`
		INSERT INTO projects (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, projectCols)
	row := w.tx.QueryRow(ctx, q,
		string(p.ID), string(p.AccountID), string(p.Name), string(p.Description), labelsJSON, now,
	)
	out, err := scanProject(row)
	if err != nil {
		return domain.Project{}, mapErr(err, "", string(p.Name))
	}
	return out, nil
}

// Update — UPDATE mutable полей (name, description, labels). account_id —
// hard-immutable; если попало в mask → caller отверг до repo.
func (w *projectWriter) Update(ctx context.Context, p domain.Project, updateMask []string) (domain.Project, error) {
	labelsJSON, err := marshalLabels(p.Labels)
	if err != nil {
		return domain.Project{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	set, args, err := buildProjectUpdateSet(p, labelsJSON, updateMask)
	if err != nil {
		return domain.Project{}, err
	}
	if set == "" {
		return w.Get(ctx, p.ID)
	}
	args = append(args, string(p.ID))
	q := fmt.Sprintf(`UPDATE projects SET %s WHERE id = $%d RETURNING %s`,
		set, len(args), projectCols)
	row := w.tx.QueryRow(ctx, q, args...)
	out, err := scanProject(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Project{}, iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", p.ID)
		}
		return domain.Project{}, mapErr(err, "", string(p.Name))
	}
	return out, nil
}

// Delete — без cross-service refcheck. Простой DELETE.
func (w *projectWriter) Delete(ctx context.Context, id domain.ProjectID) error {
	tag, err := w.tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Project %s not found", id)
	}
	return nil
}

// ---- helpers ---------------------------------------------------------------

func scanProject(row scanner) (domain.Project, error) {
	var (
		p          domain.Project
		labelsJSON []byte
	)
	err := row.Scan(
		(*string)(&p.ID),
		(*string)(&p.AccountID),
		(*string)(&p.Name),
		(*string)(&p.Description),
		&labelsJSON,
		&p.CreatedAt,
	)
	if err != nil {
		return domain.Project{}, err
	}
	p.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.Project{}, err
	}
	return p, nil
}

func buildProjectUpdateSet(p domain.Project, labelsJSON []byte, mask []string) (string, []any, error) {
	mutableFields := map[string]bool{"name": true, "description": true, "labels": true}
	apply := map[string]bool{}
	if len(mask) == 0 {
		for k := range mutableFields {
			apply[k] = true
		}
	} else {
		for _, f := range mask {
			if !mutableFields[f] {
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
		args = append(args, string(p.Name))
		idx++
	}
	if apply["description"] {
		parts = append(parts, fmt.Sprintf("description = $%d", idx))
		args = append(args, string(p.Description))
		idx++
	}
	if apply["labels"] {
		parts = append(parts, fmt.Sprintf("labels = $%d", idx))
		args = append(args, labelsJSON)
	}
	return strings.Join(parts, ", "), args, nil
}
