// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Неподтверждённый recovery после замены существующего пароля исполняет
// MarkEmailVerified: UPDATE users требует compat admission. Существующий
// verified recovery этого пути не проходит. Та же настоящая сцена удерживает
// user_login_methods после UPDATE; все три раунда и нулевые oracle общие.
func TestIntegration_SessionWriterUnverifiedRecoveryAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newSessionWriterLane(t)
	codes := map[domain.UserID]string{}
	runWriterScene(t, l, writerScene{
		table: "user_login_methods", event: "UPDATE",
		seed: func(t *testing.T) writerPerson {
			ctx := context.Background()
			p := l.seedPerson(t)
			_, err := l.s.pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, string(p.id))
			require.NoError(t, err, "посев: адрес существующей личности с паролем не подтверждён")
			require.NoError(t, l.request.Execute(ctx, humansession.RequestRecoveryInput{
				Email: p.email, Source: writerSceneSource,
			}), "посев: запрос кода неподтверждённому адресу")
			var code string
			require.NoError(t, l.s.pool.QueryRow(ctx,
				`SELECT payload->>'code' FROM kaname.invite_mail_outbox
				 WHERE resource_id=$1 AND event_type='mail.recovery.send'`, string(p.id)).Scan(&code))
			require.NotEmpty(t, code)
			codes[p.id] = code
			return p
		},
		write: func(ctx context.Context, p writerPerson) error {
			_, err := l.complete.Execute(ctx, humansession.CompleteRecoveryInput{
				Email: p.email, Code: codes[p.id], NewPassword: writerSceneNewPassword, Source: writerSceneSource,
			})
			return err
		},
	})
}
