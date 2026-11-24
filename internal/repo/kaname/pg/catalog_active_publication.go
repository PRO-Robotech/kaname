// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

var errActivePublicationUnavailable = errors.Join(authzsnapshot.ErrUnconfirmed, kaname.ErrSemanticIdentityUnavailable)

var _ authzsnapshot.Source = (*CatalogRepo)(nil)

// Сначала выбирается голова всего журнала. Условие допустимости снаружи
// исключает поиск более старой редакции, когда голова ещё не активирована.
const activePublicationHead = `
	FROM (
		SELECT revision, model_text, digest, catalog_id
		FROM kaname.publication_model_revision
		ORDER BY revision DESC LIMIT 1
	) head
	CROSS JOIN kaname.authority_protocol_read_bundle() bundle
	WHERE NOT pg_is_in_recovery()
	  AND head.digest = 'sha256:' || bundle.model_id
	  AND head.catalog_id = bundle.catalog_id
	  AND bundle.projector_version = $1
	  AND kaname.authority_full_contract_validate_v3(bundle.model_id, bundle.catalog_id, bundle.projector_version)
`

// ConfirmActivePublication одним чтением проверяет, что тот же снимок ещё
// подтверждён активным FULL-контрактом первичной базы.
func (r *CatalogRepo) ConfirmActivePublication(ctx context.Context, snapshot *authzsnapshot.Snapshot) (time.Time, error) {
	if snapshot == nil {
		return time.Time{}, errActivePublicationUnavailable
	}
	at := time.Now()
	var unchanged bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1`+activePublicationHead+`
	  AND head.revision = $2 AND head.digest = $3 AND bundle.catalog_id = $4
	)`, granteffect.ProjectorVersion, snapshot.Revision, snapshot.Digest, snapshot.CatalogID).Scan(&unchanged)
	if err != nil {
		return time.Time{}, fmt.Errorf("подтвердить активную редакцию модели: %w", err)
	}
	if !unchanged {
		return time.Time{}, errActivePublicationUnavailable
	}
	return at, ctx.Err()
}

// LoadActivePublication читает модель, каталог и системные роли в одном
// снимке PostgreSQL, сверяет отпечатки и собирает неизменяемые планы.
func (r *CatalogRepo) LoadActivePublication(ctx context.Context) (_ authzsnapshot.Snapshot, err error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	defer func() { err = errors.Join(err, rollbackInstallation(ctx, tx)) }()

	confirmedAt := time.Now()
	var revision int64
	var digest, catalogID string
	var modelText, ownerCatalog []byte
	err = tx.QueryRow(ctx, `
		SELECT head.revision, head.digest, head.model_text, bundle.catalog_id, bundle.catalog_json
	`+activePublicationHead, granteffect.ProjectorVersion).Scan(&revision, &digest, &modelText, &catalogID, &ownerCatalog)
	if errors.Is(err, pgx.ErrNoRows) {
		return authzsnapshot.Snapshot{}, errActivePublicationUnavailable
	}
	if err != nil {
		return authzsnapshot.Snapshot{}, fmt.Errorf("читать активную редакцию модели: %w", err)
	}
	if digest != fmt.Sprintf("sha256:%x", sha256.Sum256(modelText)) {
		return authzsnapshot.Snapshot{}, fmt.Errorf("отпечаток модели редакции %d: %w", revision, authzsnapshot.ErrInvalidPublication)
	}

	halves, err := authorityCatalogSnapshot(ctx, tx)
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	canonical, err := catalog.CanonicalJSON(halves)
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	if !bytes.Equal(canonical, ownerCatalog) || fmt.Sprintf("%x", sha256.Sum256(canonical)) != catalogID {
		return authzsnapshot.Snapshot{}, errActivePublicationUnavailable
	}

	roles, err := readActivePublicationRoles(ctx, tx)
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	if err = rollbackInstallation(ctx, tx); err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	plans, err := authzmodel.New(string(modelText))
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	if err = ctx.Err(); err != nil {
		return authzsnapshot.Snapshot{}, err
	}
	return authzsnapshot.Snapshot{
		Revision: revision, Digest: digest, CatalogID: catalogID, ConfirmedAt: confirmedAt,
		Plans: plans, Facts: facts, Roles: roles,
	}, nil
}

func readActivePublicationRoles(ctx context.Context, tx pgx.Tx) ([]domain.Role, error) {
	rows, err := tx.Query(ctx, `SELECT `+roleCols+` FROM kaname.roles WHERE is_system AND live ORDER BY id COLLATE "C"`)
	if err != nil {
		return nil, fmt.Errorf("читать системные роли публикации: %w", err)
	}
	defer rows.Close()
	var roles []domain.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("читать системную роль публикации: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("читать список системных ролей публикации: %w", err)
	}
	return roles, nil
}
