// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// BootstrapCatalogPublication переводит уже установленную поставку в журнал.
// Создания модулей, ресурсов, глаголов или ролей здесь нет. Единственный drain
// защищает сверку, обе истории, активацию и watermark одной транзакцией.
func (r *Repository) BootstrapCatalogPublication(ctx context.Context, bundle *granteffect.Bundle, parts []modulecatalog.PublishedPart) (PublicationAuthorityBundle, error) {
	if err := bundle.Validate(); err != nil {
		return PublicationAuthorityBundle{}, err
	}
	owned := make([]modulecatalog.PublishedPart, len(parts))
	bytesLeft := granteffect.MaxInputBytes
	for i, part := range parts {
		if len(part.Document) == 0 || len(part.Document) > bytesLeft || part.Module == "" || part.Edition.Revision <= 0 {
			return PublicationAuthorityBundle{}, granteffect.ErrInvalidBundle
		}
		bytesLeft -= len(part.Document)
		owned[i] = part
		owned[i].Document = bytes.Clone(part.Document)
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].Module < owned[j].Module })
	for i := 1; i < len(owned); i++ {
		if owned[i-1].Module == owned[i].Module {
			return PublicationAuthorityBundle{}, granteffect.ErrInvalidBundle
		}
	}
	id := bundle.Identity()
	publication := PublicationAuthorityBundle{Bundle: bundle, Revision: 1, Digest: "sha256:" + id.ModelID, CatalogID: id.CatalogID}
	err := r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := authorityCatalogMatches(ctx, tx, bundle); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `LOCK TABLE kaname.publication_model_revision,kaname.module_part_revision IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		var phase, modelID, catalogID, projector string
		if err := tx.QueryRow(ctx, `SELECT phase,coalesce(model_id,''),coalesce(catalog_id,''),coalesce(projector_version,'')
 FROM kaname.authority_semantic_identity WHERE singleton FOR UPDATE`).Scan(&phase, &modelID, &catalogID, &projector); err != nil {
			return err
		}
		if phase != "uninitialized" && (phase != "active" || modelID != id.ModelID || catalogID != id.CatalogID || projector != id.ProjectorVersion) {
			return kaname.ErrSemanticIdentityUnavailable
		}
		latest, err := bootstrapInstalledParts(ctx, tx, owned)
		if err != nil {
			return err
		}
		model, _, err := modulecatalog.ReconstructPublishedModel(latest)
		if err != nil {
			return errors.Join(granteffect.ErrInvalidBundle, err)
		}
		if model != bundle.ModelSource() {
			return granteffect.ErrInvalidBundle
		}
		var modelCount, partCount int64
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.publication_model_revision),
 (SELECT count(*) FROM kaname.module_part_revision)`).Scan(&modelCount, &partCount); err != nil {
			return err
		}
		if modelCount != 0 {
			if modelCount != 1 || phase != "active" || partCount != int64(len(owned)) {
				return kaname.ErrSemanticIdentityUnavailable
			}
			if err := publication.matchHead(ctx, tx); err != nil {
				return err
			}
			stored, err := readLatestPublishedParts(ctx, tx)
			if err != nil {
				return err
			}
			if !sameBootstrapParts(owned, stored) {
				return kaname.ErrSemanticIdentityUnavailable
			}
			var active bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_publication_activation
 WHERE singleton AND revision=1) AND kaname.authority_full_contract_validate_v3($1,$2,$3)`,
				id.ModelID, id.CatalogID, id.ProjectorVersion).Scan(&active); err != nil {
				return err
			}
			if !active {
				return kaname.ErrSemanticIdentityUnavailable
			}
			return nil
		}
		if partCount != 0 {
			return kaname.ErrSemanticIdentityUnavailable
		}
		writer := catalogPublicationWriter{catalogWriter{tx: tx}}
		for _, part := range owned {
			if err := writer.AppendPublishedPart(ctx, part); err != nil {
				return err
			}
		}
		if _, err := writer.AppendPublishedModel(ctx, modulecatalog.PublishedModel{
			Text: bundle.ModelSource(), Digest: publication.Digest, CatalogID: publication.CatalogID,
		}); err != nil {
			return err
		}
		// Иначе отложенный trigger закрыл бы уже активированный baseline при commit.
		// При прежнем active handoff именно он переводит ту же identity в transition.
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS kaname.publication_revision_closes_authority IMMEDIATE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_stage_full_v3($1,$2,$3,$4,$5)`,
			bundle.ModelSource(), bundle.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion); err != nil {
			return err
		}
		return activatePublicationAndRecord(ctx, tx, publication)
	})
	if err != nil {
		return PublicationAuthorityBundle{}, err
	}
	return publication, nil
}

func bootstrapInstalledParts(ctx context.Context, tx pgx.Tx, parts []modulecatalog.PublishedPart) ([]modulecatalog.LatestPart, error) {
	latest := make([]modulecatalog.LatestPart, 0, len(parts))
	for _, part := range parts {
		declared, err := part.DeclaredEdition()
		if err != nil {
			return nil, errors.Join(granteffect.ErrInvalidBundle, err)
		}
		var revision *int64
		var digest *string
		var live bool
		if err := tx.QueryRow(ctx, `SELECT applied_revision,applied_digest,live
 FROM kaname.catalog_module WHERE module=$1`, part.Module).Scan(&revision, &digest, &live); err != nil {
			return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
		}
		if !live || declared == nil && (revision != nil || digest != nil) ||
			declared != nil && (revision == nil || digest == nil || *revision != declared.Revision || *digest != declared.Digest) {
			return nil, kaname.ErrSemanticIdentityUnavailable
		}
		latest = append(latest, modulecatalog.LatestPart{PublishedPart: part})
	}
	return latest, nil
}

func sameBootstrapParts(want []modulecatalog.PublishedPart, got []modulecatalog.LatestPart) bool {
	if len(want) != len(got) {
		return false
	}
	byModule := make(map[string]modulecatalog.PublishedPart, len(want))
	for _, part := range want {
		byModule[part.Module] = part
	}
	for _, stored := range got {
		part, ok := byModule[stored.Module]
		if !ok || part.Edition != stored.Edition || !bytes.Equal(part.Document, stored.Document) {
			return false
		}
		delete(byModule, stored.Module)
	}
	return len(byModule) == 0
}
