// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/stretchr/testify/require"
)

// Фикстура сохраняет модель, меняя только редакцию: равные отпечатки не должны
// заменять порядок публикаций и разрешать повторное открытие после Close.
func appendActivationPublication(t *testing.T, rig protocolRig, contract *kanamepg.FullWriterContract, revision int64) kanamepg.PublicationAuthorityBundle {
	t.Helper()
	id := rig.bundle.Identity()
	published := kanamepg.PublicationAuthorityBundle{
		Bundle: rig.bundle, Revision: revision, Digest: "sha256:" + id.ModelID, CatalogID: id.CatalogID,
	}
	tx, err := authorityprotocol.OpenParticipant(contract.Context(rig.ctx), rig.runtime, kaname.AuthorityCatalog)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(rig.ctx, `INSERT INTO kaname.publication_model_revision
 (revision,model_text,digest,catalog_id) VALUES ($1,$2,$3,$4)`,
		revision, []byte(rig.bundle.ModelSource()), published.Digest, published.CatalogID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(rig.ctx))
	return published
}

func publicationActivationRevision(t *testing.T, rig protocolRig) int64 {
	t.Helper()
	var revision int64
	require.NoError(t, rig.admin.QueryRow(rig.ctx, `SELECT COALESCE(
 (SELECT revision FROM kaname.authority_publication_activation WHERE singleton),0)`).Scan(&revision))
	return revision
}

func TestPublicationActivationWatermarkSerializesOwnersAndPreservesManualClose(t *testing.T) {
	rig, owner := writerProtocolRigBeforePreparation(t)
	fullContractActivate(t, rig)
	first := kanamepg.PublicationAuthorityBundle{Bundle: rig.bundle, Revision: 1,
		Digest: "sha256:" + rig.bundle.Identity().ModelID, CatalogID: rig.bundle.Identity().CatalogID}
	advanced, err := owner.AdvanceNextCatalogPublication(rig.ctx, first)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable, "первая активация требует явного решения владельца")
	require.False(t, advanced)
	require.Zero(t, publicationActivationRevision(t, rig))
	first, err = owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), publicationActivationRevision(t, rig))
	var runtimeCanMutate bool
	require.NoError(t, rig.runtime.QueryRow(rig.ctx, `SELECT has_table_privilege(current_user,
 'kaname.authority_publication_activation','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')`).Scan(&runtimeCanMutate))
	require.False(t, runtimeCanMutate)
	advanced, err = rig.repo.AdvanceNextCatalogPublication(rig.ctx, first)
	require.Error(t, err, "runtime не получает owner lifecycle")
	require.False(t, advanced)

	contract, err := kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, first)
	require.NoError(t, err)
	second := appendActivationPublication(t, rig, contract, 2)
	// Оба владельца получают один кандидат до начала работы. Единственный
	// общий drain определяет порядок; таймер и sleep барьером не служат.
	type result struct {
		advanced bool
		err      error
	}
	start := make(chan struct{})
	done := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			advanced, err := owner.AdvanceNextCatalogPublication(rig.ctx, second)
			done <- result{advanced, err}
		}()
	}
	close(start)
	count := 0
	for range 2 {
		got := <-done
		require.NoError(t, got.err)
		if got.advanced {
			count++
		}
	}
	require.Equal(t, 1, count)
	require.Equal(t, "active", catalogIdentityPhase(t, rig))
	require.Equal(t, int64(2), publicationActivationRevision(t, rig))
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, first)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable, "устаревший кандидат не меняет текущую голову")
	require.False(t, advanced)

	contract, err = kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, second)
	require.NoError(t, err)
	third := appendActivationPublication(t, rig, contract, 3)
	require.NoError(t, owner.StageFullPublicationAuthorityBundle(rig.ctx, third))
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, third)
	require.NoError(t, err, "продолжение точного prepared кандидата")
	require.True(t, advanced)
	require.Equal(t, int64(3), publicationActivationRevision(t, rig))
	contract, err = kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, third)
	require.NoError(t, err)
	fourth := appendActivationPublication(t, rig, contract, 4)
	require.NoError(t, owner.CloseAuthorityBundle(rig.ctx))
	require.NoError(t, owner.CloseAuthorityBundle(rig.ctx), "повторное закрытие сохраняет запрет")
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, fourth)
	require.NoError(t, err)
	require.False(t, advanced, "фоновый процесс не активирует ожидающую редакцию после ручного закрытия")
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
	require.Equal(t, int64(3), publicationActivationRevision(t, rig))

	require.NoError(t, owner.StageFullPublicationAuthorityBundle(rig.ctx, fourth))
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, fourth)
	require.NoError(t, err)
	require.False(t, advanced, "подготовка редакции не снимает запрет")
	require.NoError(t, owner.ActivateFullPublicationAuthorityBundle(rig.ctx, fourth))
	require.Equal(t, "active", catalogIdentityPhase(t, rig))
	require.Equal(t, int64(4), publicationActivationRevision(t, rig))

	contract, err = kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, fourth)
	require.NoError(t, err)
	fifth := appendActivationPublication(t, rig, contract, 5)
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, fifth)
	require.NoError(t, err)
	require.True(t, advanced, "явная активация восстанавливает автоматическое продолжение")
	require.Equal(t, int64(5), publicationActivationRevision(t, rig))

	require.NoError(t, owner.CloseAuthorityBundle(rig.ctx))
	advanced, err = owner.AdvanceNextCatalogPublication(rig.ctx, fifth)
	require.NoError(t, err)
	require.False(t, advanced)
	require.Equal(t, "transition", catalogIdentityPhase(t, rig), "повтор не отменяет ручное закрытие")
	require.Equal(t, int64(5), publicationActivationRevision(t, rig))
}

func TestPublicationActivationWatermarkRefusesSkippedRevision(t *testing.T) {
	rig, owner := writerProtocolRigBeforePreparation(t)
	fullContractActivate(t, rig)
	first, err := owner.BootstrapCatalogPublication(rig.ctx, rig.bundle, nil)
	require.NoError(t, err)
	contract, err := kanamepg.NewPublishedFullWriterContract(rig.ctx, rig.repo, first)
	require.NoError(t, err)
	// Нарушаем только последовательность журнала через допущенную SQL-фикстуру;
	// настоящий append назначает следующий номер под замком каталога.
	third := appendActivationPublication(t, rig, contract, 3)
	advanced, err := owner.AdvanceNextCatalogPublication(rig.ctx, third)
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.False(t, advanced)
	require.Equal(t, "transition", catalogIdentityPhase(t, rig))
	require.Equal(t, int64(1), publicationActivationRevision(t, rig))
}
