// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestMetadataAuthorityBootstrapUsesOwnerAndRetainsExactHandoff(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	initial, err := owner.MetadataAuthorityUninitialized(r.ctx)
	require.NoError(t, err)
	require.True(t, initial)

	var ownerName string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT current_user`).Scan(&ownerName))
	created, err := owner.BootstrapMetadataAuthority(r.ctx, r.bundle, ownerName)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, created)
	created, err = r.repo.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.Error(t, err)
	require.False(t, created)
	initial, err = owner.MetadataAuthorityUninitialized(r.ctx)
	require.NoError(t, err)
	require.True(t, initial, "отказ не создаёт handoff")

	catalog := kanamepg.NewMetadataBootstrapCatalogRepo(r.admin)
	require.NoError(t, catalog.RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		return w.LockCatalog(ctx)
	}))

	created, err = owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.NoError(t, err)
	require.True(t, created)
	lifecycleState(t, r, "prepared", "compatibility")
	writers, required, err := r.repo.LoadLegacyLabelAuthority(r.ctx, r.bundle.ModelSource())
	require.NoError(t, err)
	require.True(t, required)
	require.NotNil(t, writers)
	initial, err = owner.MetadataAuthorityUninitialized(r.ctx)
	require.NoError(t, err)
	require.False(t, initial)

	called := false
	err = catalog.RunInWriteTx(r.ctx, func(context.Context, modulecatalog.CatalogWriter) error {
		called = true
		return nil
	})
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, called, "после stage начальный применитель не открывает запись каталога")

	var firstHandoff, replayedHandoff string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT xmin::text FROM kaname.authority_bundle_handoff WHERE singleton`).Scan(&firstHandoff))
	created, err = owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.NoError(t, err)
	require.False(t, created)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT xmin::text FROM kaname.authority_bundle_handoff WHERE singleton`).Scan(&replayedHandoff))
	require.Equal(t, firstHandoff, replayedHandoff)

	require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
	created, err = owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.NoError(t, err)
	require.False(t, created)
	lifecycleState(t, r, "active", "strict")

	require.NoError(t, owner.CloseAuthorityBundle(r.ctx))
	created, err = owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, created)
	lifecycleState(t, r, "transition", "strict")
}

func TestMetadataAuthorityBootstrapRefusesPreparedFullContract(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	require.NoError(t, owner.StageFullAuthorityBundle(r.ctx, r.bundle))
	created, err := owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, created)
	var required, staged int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT required_contract,staged_contract FROM kaname.authority_writer_contract WHERE singleton`).Scan(&required, &staged))
	require.Equal(t, 1, required)
	require.Equal(t, 2, staged)
}

func TestMetadataAuthorityBootstrapGrantsFreshLoginAndAdmitsRuntime(t *testing.T) {
	r, owner := writerProtocolRigWithRuntimeGrants(t, false)
	assertACL := func(granted bool) {
		t.Helper()
		var readable, writable, executable, authorityMutation bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
		 has_table_privilege($1::name,'kaname.accounts','SELECT'),
		 has_table_privilege($1::name,'kaname.accounts','UPDATE'),
		 has_function_privilege($1::name,'kaname.authority_metadata_preflight_staged_v1(text,text,boolean,text,jsonb)','EXECUTE'),
		 EXISTS(SELECT 1 FROM unnest(ARRAY['authority_writer_protocol','authority_writer_contract',
		 'authority_semantic_identity','authority_bundle_handoff','authority_policy_epoch','authority_binding_epoch']) n
		 WHERE has_table_privilege($1::name,to_regclass('kaname.'||n),'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER'))`, r.role).
			Scan(&readable, &writable, &executable, &authorityMutation))
		require.Equal(t, granted, readable)
		require.Equal(t, granted, writable)
		require.Equal(t, granted, executable)
		require.False(t, authorityMutation, "runtime не получает права изменения authority storage")
	}
	assertACL(false)
	created, err := owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
	require.NoError(t, err)
	require.True(t, created)
	assertACL(true)
	require.NoError(t, r.repo.ValidateAuthorityRuntime(r.ctx))
	for _, phase := range []string{"prepared", "active"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "active" {
				require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
				lifecycleState(t, r, "active", "strict")
			} else {
				lifecycleState(t, r, "prepared", "compatibility")
			}
			writers, required, err := r.repo.LoadLegacyLabelAuthority(r.ctx, r.bundle.ModelSource())
			require.NoError(t, err)
			require.True(t, required)
			require.NotNil(t, writers)
			// Подключение — настоящий новый LOGIN. Проверяем не только фабрику:
			// подписанный participant фиксирует строку через обычный runtime pool.
			writer, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
			require.NoError(t, err)
			lifecycleWriterCleanup(t, writer)
			id := domain.GroupID(padOrTrim20("grp-meta-" + phase))
			_, err = writer.GroupsW().Insert(r.ctx, domain.Group{ID: id, AccountID: domain.AccountID(r.a), Name: domain.GroupName("metadata-" + phase)})
			require.NoError(t, err)
			require.NoError(t, writer.Commit(r.ctx))
			var exists bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.groups WHERE id=$1 AND account_id=$2)`, string(id), r.a).Scan(&exists))
			require.True(t, exists)
			created, err = r.repo.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role)
			require.Error(t, err, "выданные runtime ACL не дают owner bootstrap")
			require.False(t, created)
			assertACL(true)
		})
	}
	lifecycleState(t, r, "active", "strict")
}

func TestMetadataAuthorityBootstrapAppliesMissingManifestBeforeHandoff(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	assertInitial := func() {
		t.Helper()
		var initial bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT a.phase='uninitialized'
		 AND p.enforcement='compatibility' AND a.protocol_version=0
		 AND a.model_id IS NULL AND a.catalog_id IS NULL AND a.projector_version IS NULL
		 AND NOT EXISTS(SELECT 1 FROM kaname.authority_bundle_handoff)
		 FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p
		 WHERE a.singleton AND p.singleton`).Scan(&initial))
		require.True(t, initial, "catalog apply и отказ bootstrap не создают semantic identity")
	}
	declared := revLockDoc(t, 1, "metadatabootstrap")
	delivery := []*manifest.Manifest{declared}
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_module WHERE module=$1`, declared.Module).Scan(&count))
	require.Zero(t, count, "модуль должен отсутствовать до настоящего ApplyAll")
	beforeAudit := auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent)
	applier := modulecatalog.NewApplier(kanamepg.NewMetadataBootstrapCatalogRepo(r.admin))
	census, err := applier.ApplyAll(r.ctx, delivery)
	require.NoError(t, err)
	require.Equal(t, 1, census.Applied)
	require.Equal(t, 1, census.ChangedModules)
	require.Empty(t, census.NotApplied)
	require.Equal(t, beforeAudit+1, auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_resource
	 WHERE module=$1 AND resource='metadatabootstrap' AND live`, declared.Module).Scan(&count))
	require.Equal(t, 1, count)
	assertInitial()

	source, report, err := modelcompose.Compose(authzmodel.DSL, delivery)
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	r.bundle, err = granteffect.NewBundle(r.ctx, source, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	edition := modulecatalog.DeclaredEdition(declared)
	require.NotNil(t, edition)
	pin := kaname.AuthorityModuleEdition{Module: declared.Module, Revision: edition.Revision, Digest: edition.Digest}
	wrong := pin
	wrong.Revision++
	created, err := owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role, wrong)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, created)
	assertInitial()
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_bundle_handoff`).Scan(&count))
	require.Zero(t, count, "неверная редакция не публикует handoff")
	created, err = owner.BootstrapMetadataAuthority(r.ctx, r.bundle, r.role, pin)
	require.NoError(t, err)
	require.True(t, created)
	lifecycleState(t, r, "prepared", "compatibility")
	writers, required, err := r.repo.LoadLegacyLabelAuthority(r.ctx, source, report.KeyTerms...)
	require.NoError(t, err)
	require.True(t, required)
	require.NotNil(t, writers)

	installed := stateFingerprint(t, r.ctx, r.admin)
	_, err = applier.ApplyAll(r.ctx, delivery)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable, "после handoff даже идемпотентный catalog apply не допускается")
	require.Equal(t, installed, stateFingerprint(t, r.ctx, r.admin))
	require.Equal(t, beforeAudit+1, auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent))
	lifecycleState(t, r, "prepared", "compatibility")
}
