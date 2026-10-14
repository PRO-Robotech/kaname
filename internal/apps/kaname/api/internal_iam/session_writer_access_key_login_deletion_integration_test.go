// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_writer_access_key_login_deletion_integration_test.go — сцена
// внахлёст для писателя строк сессии «вход ключом доступа» (Ф13, задача
// PRO-Robotech/kaname#613) против удаления личности (kaname#382; перечень
// писателей и форма сцены — `session_row_writers_identity_deletion_integration_test.go`).
//
// Выдача входа ключом берёт строку личности ПЕРВЫМ оператором своей
// транзакции (`LockPersonForLogin`), как вход паролем; сцена держит выдачу
// после вставки записи сессии и приводит удаление личности в это окно.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const (
	akSceneRPID   = "console.example.invalid"
	akSceneOrigin = "https://console.example.invalid"
)

func TestIntegration_SessionWriterAccessKeyLoginAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	ctx := context.Background()
	keys := kanamepg.NewAccessKeyRepo(l.s.pool)
	deps := humansession.AccessKeyLoginDeps{
		CutoffClock: momentclock.Func(time.Now),
		Store:       l.s.sessions, Keys: kanamepg.NewAccessKeyLoginRepo(l.s.pool, keys), Methods: kanamepg.NewLoginMethodRepo(l.s.pool),
		Binding: webauthnverify.Binding{RPID: akSceneRPID, Origins: []string{akSceneOrigin},
			Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}},
		ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
		Limits: humansession.Limits{AddressAttempts: 50, AddressWindow: 10 * time.Minute, SourceAttempts: 500, SourceWindow: 10 * time.Minute},
		TTL:    24 * time.Hour, Observer: humansession.NopObserver{}, Now: time.Now,
	}
	begin, err := humansession.NewBeginAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	login, err := humansession.NewAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	_, err = l.s.pool.Exec(ctx, `INSERT INTO kaname.own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', 8)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`)
	require.NoError(t, err, "посев: потолок вида ключа")

	type keyed struct {
		auth   *webauthntest.Authenticator
		handle []byte
	}
	byPerson := map[domain.UserID]keyed{}
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
		_, err = w.InsertKey(ctx, domain.AccessKey{
			ID: domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)), UserID: p.id,
			CredentialID: auth.CredentialID(), PublicKey: auth.COSEPublicKey(t), Algorithm: auth.Algorithm(),
			UserHandle: handle.Bytes(), Name: "scene-key", CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err, "посев: строка ключа писателем продукта")
		require.NoError(t, w.Commit(ctx))
		byPerson[p.id] = keyed{auth: auth, handle: handle.Bytes()}
		return p
	}

	runWriterScene(t, l, writerScene{
		table: "human_sessions", event: "INSERT",
		seed: seed,
		write: func(ctx context.Context, p writerPerson) error {
			k := byPerson[p.id]
			form, err := humansession.NewFormContext()
			if err != nil {
				return err
			}
			ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: writerSceneSource})
			if err != nil {
				return err
			}
			as := k.auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: akSceneOrigin, RPID: akSceneRPID})
			_, err = login.Execute(ctx, humansession.AccessKeyLoginInput{
				FormContext: form, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
				AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: k.handle,
				Source: writerSceneSource,
			})
			return err
		},
	})
}
