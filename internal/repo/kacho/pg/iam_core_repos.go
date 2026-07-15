// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// iam_core_repos.go — repository layer for the Cluster singleton plus the
// shared ClusterAdminGrant row scanner (scanCAG, consumed by the live
// cluster_admin_grant_writer.go) and the nullableTime* helpers.
//
// Structure: per-entity Repo struct over *pgxpool.Pool, exposing methods that
// follow CQRS Reader/Writer naming. Reader methods (Get/List) and Writer
// methods (Insert/Update/Delete) live in the same struct.
//
// Reuses existing sentinel error mapping via `mapErr` (maperr.go) and
// `iamerr.ErrNotFound`/`ErrAlreadyExists`/`ErrFailedPrecondition` family.
//
// SQLSTATE → sentinel:
//
//	23503 (FK)        → ErrFailedPrecondition
//	23505 (UNIQUE)    → ErrAlreadyExists / ErrFailedPrecondition (по контексту)
//	23514 (CHECK)     → ErrInvalidArg
//	23502 (NOT NULL)  → ErrInvalidArg
//	23P01 (EXCLUDE)   → ErrFailedPrecondition
//
// Все запросы — handwritten pgx, NO ORM.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// ───────────────────────────────────────────────────────────────────────────
// Cluster repo (singleton; read-only из service-слоя)
// ───────────────────────────────────────────────────────────────────────────

// ClusterRepo — CRUD-репозиторий синглтон-`Cluster`.
type ClusterRepo struct {
	pool *pgxpool.Pool
}

func NewClusterRepo(pool *pgxpool.Pool) *ClusterRepo { return &ClusterRepo{pool: pool} }

func (r *ClusterRepo) Get(ctx context.Context, id domain.ClusterID) (domain.Cluster, error) {
	const q = `SELECT id, name, description, created_at FROM clusters WHERE id = $1`
	row := r.pool.QueryRow(ctx, q, string(id))
	out, err := scanCluster(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Cluster{}, iamerr.Wrapf(iamerr.ErrNotFound, "Cluster %s not found", id)
	}
	if err != nil {
		return domain.Cluster{}, mapErr(err, "", string(id))
	}
	return out, nil
}

func (r *ClusterRepo) GetSingleton(ctx context.Context) (domain.Cluster, error) {
	return r.Get(ctx, domain.ClusterID(domain.ClusterSingletonID))
}

func scanCluster(row pgx.Row) (domain.Cluster, error) {
	var c domain.Cluster
	if err := row.Scan((*string)(&c.ID), (*string)(&c.Name), (*string)(&c.Description), &c.CreatedAt); err != nil {
		return domain.Cluster{}, err
	}
	return c, nil
}

// ───────────────────────────────────────────────────────────────────────────
// ClusterAdminGrant — shared row scanner (the live writer/reader path lives in
// cluster_admin_grant_writer.go; scanCAG is shared from here).
// ───────────────────────────────────────────────────────────────────────────

func scanCAG(row pgx.Row) (domain.ClusterAdminGrant, error) {
	var (
		g  domain.ClusterAdminGrant
		gu sql.NullTime
	)
	if err := row.Scan(
		(*string)(&g.ID), (*string)(&g.ClusterID),
		(*string)(&g.SubjectType), (*string)(&g.SubjectID),
		&g.GrantedBy, &g.GrantedAt, &gu,
	); err != nil {
		return domain.ClusterAdminGrant{}, err
	}
	if gu.Valid {
		t := gu.Time
		g.GrantedUntil = &t
	}
	return g, nil
}

// ───────────────────────────────────────────────────────────────────────────
// helpers
// ───────────────────────────────────────────────────────────────────────────

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func nullableTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return *t
}
