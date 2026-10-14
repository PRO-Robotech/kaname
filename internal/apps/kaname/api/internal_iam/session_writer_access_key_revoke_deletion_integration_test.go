// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_writer_access_key_revoke_deletion_integration_test.go — сцена
// внахлёст для писателя строк сессии «снятие ключа доступа» (Ф13 Р8, задача
// PRO-Robotech/kaname#669) против удаления личности (kaname#382; перечень
// писателей и форма сцены — `session_row_writers_identity_deletion_integration_test.go`).
//
// Транзакция снятия берёт строку личности ПЕРВЫМ оператором
// (`AccessKeyRepo.RevokeWriter`), раньше строк ключей и строк сессии; сцена
// держит снятие после пометки записей сессии и приводит удаление личности в
// это окно. Снятие исполняется настоящим вариантом использования, операция —
// до терминального исхода.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

func TestIntegration_SessionWriterAccessKeyRevokeAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	ctx := context.Background()
	pool := l.s.pool
	keys := kanamepg.NewAccessKeyRepo(pool)
	ops := operations.NewRepo(pool, "kaname")
	revoke, err := access_keys.NewRevokeUseCase(access_keys.Deps{
		Store: keys, Freshness: kanamepg.NewHumanSessionFreshness(pool), Methods: kanamepg.NewLoginMethodRepo(pool),
		Binding: webauthnverify.Binding{RPID: akSceneRPID, Origins: []string{akSceneOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		FreshnessWindow: 15 * time.Minute, Now: time.Now,
	}, ops)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 8)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`)
	require.NoError(t, err, "посев: потолок вида ключа")

	keyOf := map[domain.UserID]domain.AccessKeyID{}
	seed := func(t *testing.T) writerPerson {
		t.Helper()
		p := l.seedPerson(t)
		auth := webauthntest.New(t, webauthntest.AlgES256)
		w, err := keys.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		minted, err := domain.NewCeremonyHandle()
		require.NoError(t, err)
		handle, err := w.EnsureCeremonyHandle(ctx, p.id, minted)
		require.NoError(t, err)
		k, err := w.InsertKey(ctx, domain.AccessKey{
			ID: domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)), UserID: p.id,
			CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t), Algorithm: auth.Algorithm(),
			UserHandle: handle.Bytes(), Name: "scene-key", CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err, "посев: строка ключа писателем продукта")
		require.NoError(t, w.Commit(ctx))
		keyOf[p.id] = k.ID
		return p
	}

	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "UPDATE OF ended_at",
		seed: seed,
		write: func(ctx context.Context, p writerPerson) error {
			op, err := revoke.Execute(ctx, access_keys.RevokeInput{UserID: p.id, Actor: p.id, AccessKeyID: string(keyOf[p.id])})
			if err != nil {
				return err
			}
			waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := operations.Wait(waitCtx); err != nil {
				return err
			}
			got, err := ops.Get(ctx, op.ID)
			if err != nil {
				return err
			}
			if !got.Done {
				return stderrors.New("операция снятия не терминальна")
			}
			if got.Error != nil {
				return stderrors.New("операция снятия завершилась отказом: " + got.Error.GetMessage())
			}
			return nil
		},
	})
}
