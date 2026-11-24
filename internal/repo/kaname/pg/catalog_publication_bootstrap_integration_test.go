// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/stretchr/testify/require"
)

func TestCatalogPublicationBootstrapArchivesInstalledPartWithoutChangingItsEdition(t *testing.T) {
	const body = `apiVersion: iam/v1
module: probemod
%sresources:
  - name: baselineBox
    objectType: probemod_baseline_box
    parents: [project]
    producer: derived
    verbs: [get]
`
	for _, versioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy_unversioned", true: "declared_revision"}[versioned], func(t *testing.T) {
			rig, owner := writerProtocolRigBeforePreparation(t)
			revision := ""
			if versioned {
				revision = "revision: 5\n"
			}
			document := []byte(fmt.Sprintf(body, revision))
			m, err := manifest.Load(document)
			require.NoError(t, err)
			_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(rig.admin)).Apply(rig.ctx, m)
			require.NoError(t, err)
			bundle := catalogAtomicBundle(t, rig, m)
			part, err := modulecatalog.NewBaselinePublishedPart(m.Module, document)
			require.NoError(t, err)
			if versioned {
				unversioned, err := modulecatalog.NewBaselinePublishedPart(m.Module, []byte(fmt.Sprintf(body, "")))
				require.NoError(t, err)
				_, err = owner.BootstrapCatalogPublication(rig.ctx, bundle, []modulecatalog.PublishedPart{unversioned})
				require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable, "тот же эффект модели не стирает установленную редакцию")
			}
			published, err := owner.BootstrapCatalogPublication(rig.ctx, bundle, []modulecatalog.PublishedPart{part})
			require.NoError(t, err)
			require.Equal(t, bundle.Identity(), published.Bundle.Identity())
			loaded, err := owner.LoadPublicationAuthorityBundle(rig.ctx)
			require.NoError(t, err)
			require.Equal(t, bundle.Identity(), loaded.Bundle.Identity())
			var stored []byte
			var installedRevision *int64
			var installedDigest *string
			require.NoError(t, rig.admin.QueryRow(rig.ctx, `SELECT p.document,m.applied_revision,m.applied_digest
 FROM kaname.module_part_revision p JOIN kaname.catalog_module m USING(module)
 WHERE p.module=$1`, m.Module).Scan(&stored, &installedRevision, &installedDigest))
			require.Equal(t, document, stored)
			if versioned {
				require.NotNil(t, installedRevision)
				require.Equal(t, int64(5), *installedRevision)
				require.NotNil(t, installedDigest)
				require.Equal(t, part.Edition.Digest, *installedDigest)
			} else {
				require.Nil(t, installedRevision)
				require.Nil(t, installedDigest)
				require.Equal(t, int64(1), part.Edition.Revision)
			}
		})
	}
}

func TestCatalogPublicationBootstrapOwnsFirstJournalAndCommitsActiveBaseline(t *testing.T) {
	for _, alreadyActive := range []bool{false, true} {
		t.Run(map[bool]string{false: "uninitialized", true: "legacy_full_active"}[alreadyActive], func(t *testing.T) {
			rig, owner := writerProtocolRigBeforePreparation(t)
			var legacy *kanamepg.FullWriterContract
			if alreadyActive {
				_, legacy = fullContractActivate(t, rig)
			}
			id := rig.bundle.Identity()
			const firstModel = `INSERT INTO kaname.publication_model_revision
 (revision,model_text,digest,catalog_id) VALUES (1,$1,$2,$3)`
			// Даже отсутствие handoff не позволяет runtime занять первую запись.
			_, err := rig.runtime.Exec(rig.ctx, firstModel, []byte(rig.bundle.ModelSource()), "sha256:"+id.ModelID, id.CatalogID)
			require.Error(t, err)
			_, err = rig.runtime.Exec(rig.ctx, `INSERT INTO kaname.module_part_revision
 (module,revision,digest,document) VALUES ('iam',1,$1,$2)`, "sha256:"+id.ModelID, []byte("not a baseline"))
			require.Error(t, err)
			if alreadyActive {
				tx, err := authorityprotocol.OpenParticipant(legacy.Context(rig.ctx), rig.runtime, kaname.AuthorityCatalog)
				require.NoError(t, err)
				lifecycleRollback(t, tx)
				_, err = tx.Exec(rig.ctx, firstModel, []byte(rig.bundle.ModelSource()), "sha256:"+id.ModelID, id.CatalogID)
				require.Error(t, err, "FULL participant не подменяет owner baseline")
				require.NoError(t, tx.Rollback(rig.ctx))
			}
			_, err = owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
			require.NoError(t, err)
			require.Equal(t, "active", catalogIdentityPhase(t, rig), "отложенное закрытие не переживает commit baseline")
			require.Equal(t, int64(1), publicationActivationRevision(t, rig))
			baseline, err := owner.LoadPublicationAuthorityBundle(rig.ctx)
			require.NoError(t, err)
			require.Equal(t, id, baseline.Bundle.Identity())
			repeated, err := owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
			require.NoError(t, err)
			require.Equal(t, baseline.Revision, repeated.Revision)
			require.Equal(t, baseline.CatalogID, repeated.CatalogID)
			contract, err := kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, baseline)
			require.NoError(t, err)
			legacyWriter, err := kanamepg.NewCatalogWriteRepo(rig.runtime).WithFullWriterContract(contract)
			require.NoError(t, err)
			err = legacyWriter.RunInWriteTx(rig.ctx, func(context.Context, modulecatalog.CatalogWriter) error {
				t.Fatal("прежний применитель получил писатель каталога без записи публикации")
				return nil
			})
			require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
			second := appendActivationPublication(t, rig, contract, 2)
			advanced, err := owner.AdvanceNextCatalogPublication(rig.ctx, second)
			require.NoError(t, err, "следующая публикация сохраняет штатный FULL participant путь")
			require.True(t, advanced)
			_, err = owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
			require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable, "bootstrap не заменяет более позднюю историю")
		})
	}
}

func TestCatalogPublicationBootstrapRefusesUnrelatedIdentityAndManualClose(t *testing.T) {
	rig, owner := writerProtocolRigBeforePreparation(t)
	fullContractActivate(t, rig)
	different := catalogAtomicBundle(t, rig, catalogAtomicManifest(t))
	require.NotEqual(t, rig.bundle.Identity().ModelID, different.Identity().ModelID)
	_, err := owner.BootstrapCatalogPublication(rig.ctx, different, nil)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.Equal(t, "active", catalogIdentityPhase(t, rig))
	require.Zero(t, publicationActivationRevision(t, rig))
	_, err = owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
	require.NoError(t, err)
	require.NoError(t, owner.CloseAuthorityBundle(rig.ctx))
	_, err = owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
	require.Equal(t, int64(1), publicationActivationRevision(t, rig))
}
