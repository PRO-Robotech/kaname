// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_row_writer_email_change_scene_integration_test.go — сцена внахлёст
// писателя строк сессии «исход смены адреса» (kaname#635, Р8: новый носитель и
// снятие прочих сессий) с удалением личности. Порядок у писателя тот же, что у
// прочих писателей нескольких сессий: строка личности замком писателя
// нескольких сессий — первым оператором транзакции
// (`RegistrationStore.EmailChangeWriter`), затем строки отложенной смены,
// адрес и строки сессий.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// sceneEmailChangeStore — хранилище глаголов смены тем же составом, что в
// композиционном корне.
type sceneEmailChangeStore struct {
	sessions *kanamepg.HumanSessionRepo
	inner    *kanamepg.RegistrationStore
}

func (s sceneEmailChangeStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.sessions.Resolve(ctx, digest, now)
}

func (s sceneEmailChangeStore) EmailChangeWriter(ctx context.Context, userID domain.UserID) (humansession.EmailChangeWriter, error) {
	w, err := s.inner.EmailChangeWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return w, nil
}

func TestIntegration_SessionWriterEmailChangeAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	deps := humansession.EmailChangeDeps{
		Store:     sceneEmailChangeStore{sessions: l.s.sessions, inner: kanamepg.NewRegistrationStore(l.s.pool)},
		Pace:      humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour},
		Freshness: 15 * time.Minute,
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
	}
	request, err := humansession.NewRequestEmailChangeUseCase(deps)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmEmailChangeUseCase(deps)
	require.NoError(t, err)
	codes := map[domain.UserID]string{}
	runWriterScene(t, l, writerScene{
		table: "email_change_codes", event: "UPDATE",
		seed: func(t *testing.T) writerPerson {
			ctx := context.Background()
			p := l.seedPerson(t)
			newEmail := "scene-ec-" + strings.ToLower(ids.NewID("tst")[3:13]) + "@example.invalid"
			_, err := request.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: newEmail})
			require.NoError(t, err, "посев: запрос смены адреса")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
				 WHERE event_type = 'mail.email-change.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
				string(p.id)).Scan(&code), "посев: код из строки очереди")
			codes[p.id] = code
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			_, err := confirm.Execute(ctx, humansession.ConfirmEmailChangeInput{Bearer: p.bearer, Code: codes[p.id]})
			return err
		},
	})
}
