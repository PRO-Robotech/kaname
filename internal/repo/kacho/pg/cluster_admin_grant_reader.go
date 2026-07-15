// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cluster_admin_grant_reader.go — read-side adapter for cluster
// admin RPCs (ListAdmins, diagnostic SELECTs).
//
// Distinct from the existing `ClusterAdminGrantRepo.Get` (iam_core_repos.go,
// id-based read used by bootstrap_admin / BG flows). This Reader supports
// the InternalClusterService.ListAdmins RPC — active
// grants only, with users-row JOIN for denormalised email / display_name /
// granted_by_email.
package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ClusterAdminGrantReader — read-only port adapter. ListActive returns
// only `granted_until IS NULL` rows ordered by `granted_at ASC` (stable
// across re-renders).
type ClusterAdminGrantReader struct {
	pool *pgxpool.Pool
}

// NewClusterAdminGrantReader — composition root constructor.
func NewClusterAdminGrantReader(pool *pgxpool.Pool) *ClusterAdminGrantReader {
	return &ClusterAdminGrantReader{pool: pool}
}

// ListActive — single SQL with two LEFT JOINs to `kacho_iam.users`:
//   - u_subj — for subject_email / subject_display_name
//   - u_by   — for granted_by_email (NULL when granted_by == "bootstrap")
//
// LEFT JOIN tolerates dangling users-row gracefully (returns empty strings
// for missing user, no SQL error).
//
// Note: bootstrap-flow inserts grant with granted_by='bootstrap' (literal
// string), which never matches users.id ⇒ u_by JOIN returns NULL ⇒
// CASE ... ELSE u_by.email END is COALESCE'd to ”.
func (r *ClusterAdminGrantReader) ListActive(ctx context.Context) ([]domain.ClusterAdminEntry, error) {
	const q = `
		SELECT g.id,
		       g.subject_type,
		       g.subject_id,
		       COALESCE(u_subj.email, ''),
		       COALESCE(u_subj.display_name, ''),
		       g.granted_by,
		       CASE WHEN g.granted_by = 'bootstrap' THEN ''
		            ELSE COALESCE(u_by.email, '')
		       END AS granted_by_email,
		       g.granted_at
		  FROM kacho_iam.cluster_admin_grants g
		  LEFT JOIN kacho_iam.users u_subj ON u_subj.id = g.subject_id
		  LEFT JOIN kacho_iam.users u_by   ON u_by.id   = g.granted_by
		 WHERE g.granted_until IS NULL
		 ORDER BY g.granted_at ASC`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("cluster_admin_grants list: %w", err)
	}
	defer rows.Close()

	out := []domain.ClusterAdminEntry{}
	for rows.Next() {
		var (
			e             domain.ClusterAdminEntry
			grantedByMail sql.NullString
		)
		// grantedByMail is technically already coerced via COALESCE to '',
		// but using sql.NullString here keeps the column scan-safe against
		// future schema tweaks.
		if err := rows.Scan(
			&e.ClusterAdminGrantID,
			&e.SubjectType,
			&e.SubjectID,
			&e.SubjectEmail,
			&e.SubjectDisplayName,
			&e.GrantedByUserID,
			&grantedByMail,
			&e.GrantedAt,
		); err != nil {
			return nil, fmt.Errorf("cluster_admin_grants list scan: %w", err)
		}
		if grantedByMail.Valid {
			e.GrantedByEmail = grantedByMail.String
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cluster_admin_grants list iterate: %w", err)
	}
	return out, nil
}

// GetBySubject — convenience read for the (active OR latest history) row
// of a specific subject. Used by use-cases (e.g. emergency_admin
// gate-pass scenario) and by diagnostic checks.
//
// Returns iamerr.ErrNotFound (via Wrapf) when no row exists for the subject
// at all.
func (r *ClusterAdminGrantReader) GetBySubject(
	ctx context.Context, txh service.Tx, subject domain.SubjectID,
) (domain.ClusterAdminGrant, error) {
	tx := txAsPgx(txh)
	return getCAGBySubjectTx(ctx, tx, subject)
}
