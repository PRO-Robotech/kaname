// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type catalogPublicationWriter struct{ catalogWriter }

// RunInCatalogPublicationTx открывает штатный писательский вход FULL и
// повторяет допуск оператора после захвата глобальной ограды и замка каталога.
func (r *CatalogWriteRepo) RunInCatalogPublicationTx(ctx context.Context, fn func(context.Context, modulecatalog.CatalogPublicationWriter) error) error {
	principal, verified := operations.PrincipalFromContextOK(ctx)
	subject, named := authzguard.SubjectFromPrincipal(principal)
	if !verified || !named || principal.Type != "user" || principal.IsAnonymous() {
		return modulecatalog.ErrPublicationOperatorDenied
	}
	snapshot, pinned := authzsnapshot.FromContext(ctx)
	if r == nil || r.pool == nil || r.fullContract == nil || fn == nil ||
		!pinned || snapshot == nil || snapshot.Plans == nil || snapshot.Facts == nil || snapshot.Revision <= 0 {
		return authzsnapshot.ErrUnconfirmed
	}
	modelID, prefixed := strings.CutPrefix(snapshot.Digest, "sha256:")
	profile := r.fullContract.profile
	if !prefixed || !profile.Matches(r.pool, modelID, snapshot.CatalogID, granteffect.ProjectorVersion) ||
		!profile.MatchesPublication(snapshot.Revision, snapshot.Digest) {
		return authzsnapshot.ErrUnconfirmed
	}

	return runFullInstallationTx(r.fullContract.Context(ctx), r.pool, kaname.AuthorityCatalog, func(ctx context.Context, tx pgx.Tx) error {
		writer := catalogPublicationWriter{catalogWriter{tx: tx}}
		if err := writer.LockCatalog(ctx); err != nil {
			return fmt.Errorf("замок каталога перед публикацией: %w", err)
		}
		checker := authzcascade.WrapAdmitted(
			relverdict.NewTransactionAsker(tx, snapshot.Plans),
			personmarks.NewTransaction(tx))
		allowed, err := authzguard.SubjectIsClusterAdminPlainE(ctx, checker, subject)
		if err != nil {
			return err
		}
		if !allowed {
			return modulecatalog.ErrPublicationOperatorDenied
		}
		// Материализованный system_admin может пережить срок исходной выдачи.
		// Проверяем каноническую запись по часам БД после ожидания обоих замков.
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM kaname.cluster_admin_grants
 WHERE cluster_id=$1 AND subject_type='user' AND subject_id=$2
 AND (granted_until IS NULL OR granted_until > clock_timestamp())
)`, domain.ClusterSingletonID, principal.ID).Scan(&live); err != nil {
			return fmt.Errorf("сверка действующей выдачи оператора каталога: %w", err)
		}
		if !live {
			return modulecatalog.ErrPublicationOperatorDenied
		}
		return fn(ctx, writer)
	})
}

func (w catalogPublicationWriter) LatestPublishedModel(ctx context.Context) (modulecatalog.PublishedModel, error) {
	var model modulecatalog.PublishedModel
	var text []byte
	err := w.tx.QueryRow(ctx, `
		SELECT revision, digest, catalog_id, model_text FROM kaname.publication_model_revision
		ORDER BY revision DESC LIMIT 1
	`).Scan(&model.Revision, &model.Digest, &model.CatalogID, &text)
	if errors.Is(err, pgx.ErrNoRows) {
		return modulecatalog.PublishedModel{}, authzsnapshot.ErrUnconfirmed
	}
	if err != nil {
		return modulecatalog.PublishedModel{}, fmt.Errorf("прочитать головную модель каталога: %w", err)
	}
	model.Text = string(text)
	return model, nil
}

func (w catalogPublicationWriter) LatestPublishedParts(ctx context.Context) ([]modulecatalog.LatestPart, error) {
	return readLatestPublishedParts(ctx, w.tx)
}

func (w catalogPublicationWriter) AppendPublishedPart(ctx context.Context, part modulecatalog.PublishedPart) error {
	_, err := w.tx.Exec(ctx, `
		INSERT INTO kaname.module_part_revision (module, revision, digest, document)
		VALUES ($1, $2, $3, $4)
	`, part.Module, part.Edition.Revision, part.Edition.Digest, part.Document)
	if err != nil {
		return fmt.Errorf("записать редакцию модуля %q: %w", part.Module, err)
	}
	return nil
}

func (w catalogPublicationWriter) AppendPublishedModel(ctx context.Context, model modulecatalog.PublishedModel) (modulecatalog.PublishedModel, error) {
	err := w.tx.QueryRow(ctx, `
		INSERT INTO kaname.publication_model_revision (revision, model_text, digest, catalog_id)
		SELECT COALESCE(MAX(revision), 0) + 1, $1, $2, $3
		FROM kaname.publication_model_revision
		RETURNING revision
	`, []byte(model.Text), model.Digest, model.CatalogID).Scan(&model.Revision)
	if err != nil {
		return modulecatalog.PublishedModel{}, fmt.Errorf("записать редакцию модели каталога: %w", err)
	}
	return model, nil
}

var _ modulecatalog.CatalogPublicationWriter = catalogPublicationWriter{}
var _ modulecatalog.CatalogPublicationTxRunner = (*CatalogWriteRepo)(nil)
