// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/stretchr/testify/require"
)

func TestCatalogActivePublicationRequiresActiveHeadEvenWhenModelIsUnchanged(t *testing.T) {
	rig, owner := writerProtocolRigBeforePreparation(t)
	ctx := rig.ctx
	catalog := kanamepg.NewCatalogRepo(rig.runtime)
	_, err := catalog.LoadActivePublication(ctx)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)

	model := []byte(rig.bundle.ModelSource())
	digest := "sha256:" + rig.bundle.Identity().ModelID
	const appendRevision = `INSERT INTO kaname.publication_model_revision(revision, model_text, digest, catalog_id) VALUES ($1, $2, $3, $4)`
	_, legacy := fullContractActivate(t, rig)
	appendWithContract := func(contract *kanamepg.FullWriterContract, revision int64, commit bool) {
		t.Helper()
		tx, err := authorityprotocol.OpenParticipant(contract.Context(ctx), rig.runtime, kaname.AuthorityCatalog)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(ctx, appendRevision, revision, model, digest, rig.bundle.Identity().CatalogID)
		require.NoError(t, err)
		if commit {
			require.NoError(t, tx.Commit(ctx))
			return
		}
		require.NoError(t, tx.Rollback(ctx))
	}
	first, err := owner.BootstrapCatalogPublication(ctx, rig.bundle, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), first.Revision)
	require.Equal(t, digest, first.Digest)
	require.Equal(t, rig.bundle.Identity().CatalogID, first.CatalogID)
	require.Equal(t, rig.bundle.Identity(), first.Bundle.Identity())
	require.ErrorIs(t, owner.StageFullAuthorityBundle(ctx, rig.bundle), kaname.ErrSemanticIdentityUnavailable)
	require.ErrorIs(t, owner.ActivateFullAuthorityBundle(ctx, rig.bundle), kaname.ErrSemanticIdentityUnavailable)
	active, err := catalog.LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), active.Revision)
	require.Equal(t, digest, active.Digest)
	require.Equal(t, rig.bundle.Identity().CatalogID, active.CatalogID)
	_, err = catalog.ConfirmActivePublication(ctx, &active)
	require.NoError(t, err)

	legacyTx, err := authorityprotocol.OpenParticipant(legacy.Context(ctx), rig.runtime, kaname.AuthorityCatalog)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "писатель без редакции закрывается после первой публикации")
	require.Nil(t, legacyTx)

	contract, err := kanamepg.NewPublishedFullWriterContract(ctx, rig.repo, first)
	require.NoError(t, err)
	oldRepository, err := rig.repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	denied, err := rig.runtime.Begin(ctx)
	require.NoError(t, err)
	lifecycleRollback(t, denied)
	_, err = denied.Exec(ctx, appendRevision, int64(2), model, digest, rig.bundle.Identity().CatalogID)
	require.Error(t, err, "новую редакцию записывает только допущенный писатель каталога")
	require.NoError(t, denied.Rollback(ctx))

	appendWithContract(contract, 2, false)
	_, err = catalog.ConfirmActivePublication(ctx, &active)
	require.NoError(t, err, "откат оставляет первую редакцию активной")

	appendWithContract(contract, 2, true)
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
	_, err = catalog.ConfirmActivePublication(ctx, &active)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	_, err = catalog.LoadActivePublication(ctx)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed, "совпадение модели не заменяет активацию второй редакции")
	require.ErrorIs(t, owner.StageFullPublicationAuthorityBundle(ctx, first), kaname.ErrSemanticIdentityUnavailable)
	require.ErrorIs(t, owner.ActivateFullPublicationAuthorityBundle(ctx, first), kaname.ErrSemanticIdentityUnavailable)

	second := kanamepg.PublicationAuthorityBundle{Bundle: rig.bundle, Revision: 2, Digest: digest, CatalogID: rig.bundle.Identity().CatalogID}
	require.NoError(t, owner.StageFullPublicationAuthorityBundle(ctx, second))
	require.NoError(t, owner.ActivateFullPublicationAuthorityBundle(ctx, second))
	stale, err := authorityprotocol.OpenParticipant(contract.Context(ctx), rig.runtime, kaname.AuthorityCatalog)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "тот же digest не возвращает допуск старому профилю")
	require.Nil(t, stale)
	staleWriter, err := oldRepository.ParticipantAuthorityWriter(ctx, rig.intent(rig.a))
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, staleWriter)

	currentContract, err := kanamepg.NewPublishedFullWriterContract(ctx, rig.repo, second)
	require.NoError(t, err)
	currentWriter, err := authorityprotocol.OpenParticipant(currentContract.Context(ctx), rig.runtime, kaname.AuthorityCatalog)
	require.NoError(t, err)
	lifecycleRollback(t, currentWriter)
	require.NoError(t, currentWriter.Rollback(ctx))
	current, err := catalog.LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), current.Revision)
	_, err = catalog.ConfirmActivePublication(ctx, &active)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	_, err = catalog.ConfirmActivePublication(ctx, &current)
	require.NoError(t, err)
}

func TestPublicationCatalogBindingRefusesPostJournalDrift(t *testing.T) {
	rig, owner := writerProtocolRigBeforePreparation(t)
	ctx := rig.ctx
	fullContractActivate(t, rig)
	published, err := owner.BootstrapCatalogPublication(ctx, rig.bundle, nil)
	require.NoError(t, err)
	contract, err := kanamepg.NewPublishedFullWriterContract(ctx, rig.repo, published)
	require.NoError(t, err)
	reader := kanamepg.NewCatalogRepo(rig.runtime)
	active, err := reader.LoadActivePublication(ctx)
	require.NoError(t, err)

	// Штатный legacy writer отказывает до передачи транзакции применителю.
	writer, err := kanamepg.NewCatalogWriteRepo(rig.runtime).WithFullWriterContract(contract)
	require.NoError(t, err)
	err = writer.RunInWriteTx(ctx, func(context.Context, modulecatalog.CatalogWriter) error {
		t.Fatal("legacy writer получил транзакцию после первой публикации")
		return nil
	})
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	_, err = reader.ConfirmActivePublication(ctx, &active)
	require.NoError(t, err)

	// Синтетическое расхождение проверяет защиту чтения независимо от
	// штатных применителей. Сохраняем настоящий барьер и триггеры PostgreSQL.
	tx, err := authorityprotocol.OpenParticipant(contract.Context(ctx), rig.runtime, kaname.AuthorityCatalog)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.catalog_module (module) VALUES ('publicationdrift')`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
	_, err = reader.ConfirmActivePublication(ctx, &active)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	_, err = reader.LoadActivePublication(ctx)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	_, err = owner.LoadPublicationAuthorityBundle(ctx)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed, "журнал не допускает новый фактический каталог")

	// Повторная сборка сама по себе не даёт владельцу новый допуск: проверка
	// внутри drain должна сверить журнал, даже если bundle совпал с actual.
	drifted := semanticBundleDB(t, ctx, rig.admin)
	require.NotEqual(t, published.CatalogID, drifted.Identity().CatalogID)
	rebound := published
	rebound.Bundle = drifted
	rebound.CatalogID = drifted.Identity().CatalogID
	require.ErrorIs(t, owner.StageFullPublicationAuthorityBundle(ctx, published), kaname.ErrSemanticIdentityUnavailable)
	require.ErrorIs(t, owner.StageFullPublicationAuthorityBundle(ctx, rebound), kaname.ErrSemanticIdentityUnavailable)
	require.ErrorIs(t, owner.ActivateFullPublicationAuthorityBundle(ctx, rebound), kaname.ErrSemanticIdentityUnavailable)
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
}

func TestCatalogPublicationExtendsActiveCatalogAndRejectsStalePlan(t *testing.T) {
	fixture := newClusterParticipantFixture(t, false)
	rig, owner := fixture.r, lifecycleOwner(fixture.r)
	ctx := rig.ctx
	fullContractActivate(t, rig)
	active, err := owner.BootstrapCatalogPublication(ctx, rig.bundle, nil)
	require.NoError(t, err)
	reader := kanamepg.NewCatalogRepo(rig.runtime)
	const maxBytes = 8192
	document := func(module, resource string, revision int, verbs string) []byte {
		return []byte(fmt.Sprintf(`apiVersion: iam/v1
module: %s
revision: %d
resources:
  - name: %s
    objectType: %s_contract
    parents: [project]
    producer: authored
    verbs: [%s]
`, module, revision, resource, module, verbs))
	}
	pin := func() (context.Context, *kanamepg.CatalogWriteRepo) {
		t.Helper()
		snapshot, err := reader.LoadActivePublication(ctx)
		require.NoError(t, err)
		pinned, err := authzsnapshot.WithContext(fixture.ctx(), &snapshot)
		require.NoError(t, err)
		contract, err := kanamepg.NewPublishedFullWriterContract(pinned, rig.repo, active)
		require.NoError(t, err)
		writer, err := kanamepg.NewCatalogWriteRepo(rig.runtime).WithFullWriterContract(contract)
		require.NoError(t, err)
		return pinned, writer
	}
	activate := func(revision int64) {
		t.Helper()
		_, err := reader.LoadActivePublication(ctx)
		require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
		active, err = owner.LoadPublicationAuthorityBundle(ctx)
		require.NoError(t, err)
		require.Equal(t, revision, active.Revision)
		advanced, err := owner.AdvanceNextCatalogPublication(ctx, active)
		require.NoError(t, err)
		require.True(t, advanced)
	}
	const initialVerbs = "{name: read, class: get}, {name: sign, class: update}"
	draft := document("erp", "contract", 1, initialVerbs)
	other := document("crm", "contract", 1, "get")
	pinned, writer := pin()
	first, err := modulecatalog.PlanCatalogPublication(pinned, writer, "erp", draft, maxBytes)
	require.NoError(t, err)
	stale, err := modulecatalog.PlanCatalogPublication(pinned, writer, "crm", other, maxBytes)
	require.NoError(t, err)
	result, err := modulecatalog.ApplyCatalogPublication(pinned, writer, "erp", draft, maxBytes, first.StateToken)
	require.NoError(t, err)
	require.Equal(t, first.Model, result)
	activate(2)

	pinned, writer = pin()
	_, err = modulecatalog.ApplyCatalogPublication(pinned, writer, "crm", other, maxBytes, stale.StateToken)
	require.ErrorIs(t, err, modulecatalog.ErrStateMoved)
	conflict := document("erp", "otherContract", 2, initialVerbs)
	_, err = modulecatalog.PlanCatalogPublication(pinned, writer, "erp", conflict, maxBytes)
	require.ErrorIs(t, err, modulecatalog.ErrBeyondAnchor)
	snapshot, err := reader.LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(2), snapshot.Revision)
	objectType, known := snapshot.Facts.FGAObjectType("erp.contract")
	require.True(t, known)
	require.Equal(t, "erp_contract", objectType)
	require.ElementsMatch(t, []string{"read", "sign"}, snapshot.Facts.VerbsOfType(objectType))
	require.False(t, snapshot.Facts.IsKnownModule("crm"))

	extended := document("erp", "contract", 2, initialVerbs+", {name: approve, class: update}")
	second, err := modulecatalog.PlanCatalogPublication(pinned, writer, "erp", extended, maxBytes)
	require.NoError(t, err)
	appliedAudits := auditRowsOfType(t, ctx, rig.admin, modulecatalog.AppliedEventType)
	abort := errors.New("отказ после записи аудита публикации")
	aborted := publicationRollbackRunner{CatalogPublicationTxRunner: writer, failure: abort}
	_, err = modulecatalog.ApplyCatalogPublication(pinned, aborted, "erp", extended, maxBytes, second.StateToken)
	require.ErrorIs(t, err, abort)
	stillActive, err := reader.LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, active.Revision, stillActive.Revision)
	require.Equal(t, first.Model.Digest, stillActive.Digest)
	var newVerb bool
	var persistedModels, persistedParts int
	require.NoError(t, rig.admin.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM kaname.catalog_verb WHERE module='erp' AND resource='contract' AND verb='approve'),
		       (SELECT count(*) FROM kaname.publication_model_revision),
		       (SELECT count(*) FROM kaname.module_part_revision WHERE module='erp')
	`).Scan(&newVerb, &persistedModels, &persistedParts))
	require.False(t, newVerb)
	require.Equal(t, 2, persistedModels)
	require.Equal(t, 1, persistedParts)
	require.Equal(t, appliedAudits, auditRowsOfType(t, ctx, rig.admin, modulecatalog.AppliedEventType))

	// Тот же план применяется после отката без повторного Plan.
	result, err = modulecatalog.ApplyCatalogPublication(pinned, writer, "erp", extended, maxBytes, second.StateToken)
	require.NoError(t, err)
	require.Equal(t, second.Model, result)
	require.Equal(t, appliedAudits+1, auditRowsOfType(t, ctx, rig.admin, modulecatalog.AppliedEventType))
	activate(3)

	pinned, writer = pin()
	result, err = modulecatalog.ApplyCatalogPublication(pinned, writer, "erp", extended, maxBytes, second.StateToken)
	require.NoError(t, err)
	require.Equal(t, second.Model, result)
	snapshot, err = reader.LoadActivePublication(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(3), snapshot.Revision)
	objectType, known = snapshot.Facts.FGAObjectType("erp.contract")
	require.True(t, known)
	require.Equal(t, "erp_contract", objectType)
	require.ElementsMatch(t, []string{"read", "sign", "approve"}, snapshot.Facts.VerbsOfType(objectType))
	var parts int
	require.NoError(t, rig.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.module_part_revision WHERE module='erp'`).Scan(&parts))
	require.Equal(t, 2, parts)
}

type publicationRollbackRunner struct {
	modulecatalog.CatalogPublicationTxRunner
	failure error
}

func (r publicationRollbackRunner) RunInCatalogPublicationTx(ctx context.Context, apply func(context.Context, modulecatalog.CatalogPublicationWriter) error) error {
	return r.CatalogPublicationTxRunner.RunInCatalogPublicationTx(ctx, func(ctx context.Context, writer modulecatalog.CatalogPublicationWriter) error {
		return apply(ctx, publicationRollbackWriter{CatalogPublicationWriter: writer, failure: r.failure})
	})
}

type publicationRollbackWriter struct {
	modulecatalog.CatalogPublicationWriter
	failure error
}

func (w publicationRollbackWriter) EmitApplied(ctx context.Context, event modulecatalog.AppliedEvent) error {
	if err := w.CatalogPublicationWriter.EmitApplied(ctx, event); err != nil {
		return err
	}
	return w.failure
}
