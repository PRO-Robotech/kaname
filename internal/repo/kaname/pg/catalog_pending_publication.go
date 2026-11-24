// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

// LoadPublicationAuthorityBundle восстанавливает вход для явной активации
// владельцем. Снимок может относиться к переходной фазе, поэтому проверку
// готовности писателя получают отдельно после Stage/Activate.
func (r *Repository) LoadPublicationAuthorityBundle(ctx context.Context) (_ PublicationAuthorityBundle, err error) {
	if r == nil || r.master == nil {
		return PublicationAuthorityBundle{}, granteffect.ErrInvalidBundle
	}
	tx, err := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	defer func() { err = errors.Join(err, rollbackInstallation(ctx, tx)) }()

	var revision int64
	var admissible bool
	err = tx.QueryRow(ctx, `
		WITH head AS (
			SELECT revision, octet_length(model_text) AS model_size
			FROM kaname.publication_model_revision ORDER BY revision DESC LIMIT 1
		), parts AS (
			SELECT DISTINCT ON (module) module, octet_length(document) AS part_size
			FROM kaname.module_part_revision ORDER BY module, revision DESC
		)
		SELECT revision,
		       NOT pg_is_in_recovery() AND model_size BETWEEN 1 AND $1
		       AND COALESCE((SELECT revision FROM kaname.publication_model_revision
		                     WHERE revision < head.revision ORDER BY revision DESC LIMIT 1), 0) = head.revision - 1
		       AND COALESCE((SELECT sum(part_size) FROM parts), 0) <= $1
		       AND NOT EXISTS (SELECT 1 FROM parts p WHERE NOT EXISTS
		           (SELECT 1 FROM kaname.catalog_module m WHERE m.module = p.module))
		FROM head
	`, granteffect.MaxInputBytes).Scan(&revision, &admissible)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !admissible {
		return PublicationAuthorityBundle{}, authzsnapshot.ErrUnconfirmed
	}
	if err != nil {
		return PublicationAuthorityBundle{}, fmt.Errorf("прочитать границы публикации: %w", err)
	}
	var text []byte
	var digest, catalogID string
	if err := tx.QueryRow(ctx, `SELECT model_text, digest, catalog_id FROM kaname.publication_model_revision WHERE revision = $1`,
		revision).Scan(&text, &digest, &catalogID); err != nil {
		return PublicationAuthorityBundle{}, err
	}
	if digest != fmt.Sprintf("sha256:%x", sha256.Sum256(text)) {
		return PublicationAuthorityBundle{}, authzsnapshot.ErrInvalidPublication
	}

	parts, err := readLatestPublishedParts(ctx, tx)
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	halves, err := authorityCatalogSnapshot(ctx, tx)
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	// Журнал и фактический каталог читаются из одного снимка. Новые строки
	// после публикации не становятся кандидатом только из-за успешной сборки.
	canonical, err := catalog.CanonicalJSON(halves)
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(canonical)) != catalogID {
		return PublicationAuthorityBundle{}, authzsnapshot.ErrUnconfirmed
	}
	if err = rollbackInstallation(ctx, tx); err != nil {
		return PublicationAuthorityBundle{}, err
	}
	if len(parts) == 0 && (revision != 1 || string(text) != authzmodel.DSL) {
		return PublicationAuthorityBundle{}, fmt.Errorf("редакция %d без истории частей: %w", revision, granteffect.ErrInvalidBundle)
	}
	model, terms, err := modulecatalog.ReconstructPublishedModel(parts)
	if err != nil {
		return PublicationAuthorityBundle{}, errors.Join(granteffect.ErrInvalidBundle, err)
	}
	if model != string(text) {
		return PublicationAuthorityBundle{}, fmt.Errorf("части не воспроизводят модель редакции %d: %w", revision, granteffect.ErrInvalidBundle)
	}
	bundle, err := granteffect.NewBundle(ctx, model, halves, granteffect.ProjectorVersion, terms...)
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	return PublicationAuthorityBundle{Revision: revision, Digest: digest, CatalogID: catalogID, Bundle: bundle}, nil
}

func readLatestPublishedParts(ctx context.Context, tx pgx.Tx) ([]modulecatalog.LatestPart, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT ON (p.module) p.module, p.revision, p.digest, p.document, NOT m.live
		FROM kaname.module_part_revision p
		JOIN kaname.catalog_module m ON m.module = p.module
		ORDER BY p.module, p.revision DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var parts []modulecatalog.LatestPart
	for rows.Next() {
		var part modulecatalog.LatestPart
		if err := rows.Scan(&part.Module, &part.Edition.Revision, &part.Edition.Digest, &part.Document, &part.Withdrawn); err != nil {
			return nil, err
		}
		parts = append(parts, part)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return parts, nil
}
