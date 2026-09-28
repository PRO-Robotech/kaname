// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_row_writer_verification_scene_integration_test.go — сцена внахлёст
// писателя строк сессии «подтверждение адреса» (kaname#456, Р10: новый
// носитель и снятие прочих сессий) с удалением личности. Порядок у писателя
// тот же, что у прочих писателей нескольких сессий: строка личности замком
// писателя нескольких сессий — первым оператором транзакции
// (`RegistrationStore.VerificationWriter`), затем строки кода и сессий.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// sceneVerificationStore — хранилище глагола подтверждения тем же составом,
// что в композиционном корне; активации приглашения у личности сцены нет.
type sceneVerificationStore struct {
	sessions *kanamepg.HumanSessionRepo
	inner    *kanamepg.RegistrationStore
}

func (s sceneVerificationStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.sessions.Resolve(ctx, digest, now)
}

func (s sceneVerificationStore) VerificationWriter(ctx context.Context, userID domain.UserID) (humansession.VerificationWriter, error) {
	w, err := s.inner.VerificationWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return sceneVerificationWriter{RegistrationWriter: w}, nil
}

type sceneVerificationWriter struct{ *kanamepg.RegistrationWriter }

func (sceneVerificationWriter) ActivateInviteOnVerification(context.Context, domain.User) (humansession.InviteActivation, error) {
	return humansession.InviteActivation{}, errors.New("личность сцены — не приглашение")
}

func TestIntegration_SessionWriterAddressVerificationAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	deps := humansession.VerificationDeps{
		Store: sceneVerificationStore{sessions: l.s.sessions, inner: kanamepg.NewRegistrationStore(l.s.pool)},
		Pace:  humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour},
	}
	request, err := humansession.NewRequestVerificationUseCase(deps)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmVerificationUseCase(deps)
	require.NoError(t, err)
	codes := map[domain.UserID]string{}
	runWriterScene(t, l, writerScene{
		table: "email_verification_codes", event: "UPDATE",
		seed: func(t *testing.T) writerPerson {
			ctx := context.Background()
			p := l.seedPerson(t)
			_, err := l.s.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = NULL WHERE id = $1`, string(p.id))
			require.NoError(t, err, "посев: адрес не подтверждён")
			_, err = request.Execute(ctx, p.bearer)
			require.NoError(t, err, "посев: письмо подтверждения")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
				 WHERE event_type = 'mail.verification.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
				string(p.id)).Scan(&code), "посев: код из строки очереди")
			codes[p.id] = code
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			_, err := confirm.Execute(ctx, humansession.ConfirmVerificationInput{Bearer: p.bearer, Code: codes[p.id]})
			return err
		},
	})
}
