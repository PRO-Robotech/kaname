// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_repo.go — pgxpool adapter implementing service.SubjectChangeReader.
// Drains kacho_iam.subject_change_outbox for the InternalIAMService.PollSubjectChanges
// use-case. Read-only; no mutation.
package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// SubjectChangeRepo — pgxpool adapter for service.SubjectChangeReader.
type SubjectChangeRepo struct{ pool *pgxpool.Pool }

// NewSubjectChangeRepo constructs a SubjectChangeRepo backed by pool.
func NewSubjectChangeRepo(pool *pgxpool.Pool) *SubjectChangeRepo {
	return &SubjectChangeRepo{pool: pool}
}

// Compile-time guard: SubjectChangeRepo must implement service.SubjectChangeReader.
var _ service.SubjectChangeReader = (*SubjectChangeRepo)(nil)

// PollSubjectChanges returns rows with id > sinceID ordered ascending,
// at most limit rows, plus headID = current MAX(id) (0 when empty).
func (r *SubjectChangeRepo) PollSubjectChanges(ctx context.Context, sinceID int64, limit int32) ([]service.SubjectChange, int64, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, subject_id, op
		   FROM kacho_iam.subject_change_outbox
		  WHERE id > $1
		  ORDER BY id ASC
		  LIMIT $2`,
		sinceID, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("poll subject_change_outbox: %w", err)
	}
	defer rows.Close()

	var changes []service.SubjectChange
	for rows.Next() {
		var c service.SubjectChange
		if err := rows.Scan(&c.ID, &c.SubjectID, &c.Op); err != nil {
			return nil, 0, fmt.Errorf("scan subject_change: %w", err)
		}
		changes = append(changes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate subject_change: %w", err)
	}

	var headID int64
	if err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(id), 0) FROM kacho_iam.subject_change_outbox`).
		Scan(&headID); err != nil {
		return nil, 0, fmt.Errorf("head_id subject_change_outbox: %w", err)
	}

	return changes, headID, nil
}
