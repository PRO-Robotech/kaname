// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_audit_integration_test.go — User audit slice.
// Активация приглашения в исходе подтверждения адреса → iam.user.updated;
// Delete → iam.user.deleted.
//
// Событие заведения (`iam.user.created`) производит регистрация; глагол
// заведения личности по внешнему удостоверению, чья ветвь вставки тоже его
// писала, снят (kaname#929, AWI-09), и его проба ушла вместе с ним.
// Delete runs through the public UserService.Delete (self-delete).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestUserAudit_5_2_14_InviteActivationEmitsUpdated — активация приглашения на
// полосе входа (`ActivateInviteOnVerificationTx`, тот же оператор, что у
// `ActivateInviteForLane`) пишет `iam.user.updated` той же транзакцией;
// актор — сам человек строки.
func TestUserAudit_5_2_14_InviteActivationEmitsUpdated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed a PENDING invite row with the verification mark of our lane:
	// активация идёт только в исходе подтверждения адреса (kaname#456, Р11).
	owner, accID := seedUserAccount(t, ctx, env.pool, "usr14upd")
	_ = owner
	pendingID := domain.UserID("usr0000000000005214pp")
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at)
		VALUES ($1, $2, '', $3, $4, 'PENDING', now())`,
		string(pendingID), string(accID), "u-5214-activate@example.com", "Pending Invitee")
	require.NoError(t, err)
	// Пароль приглашённого — регистрацией раньше активации (kaname#456,
	// Р11 п. 1): активация не производит ACTIVE без способа входа (kaname#608).
	_, err = env.pool.Exec(ctx, `INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
		VALUES ($1, 'password', 'fixture-password-row-without-a-known-password')`, string(pendingID))
	require.NoError(t, err)

	rd, err := env.repo.Reader(ctx)
	require.NoError(t, err)
	pending, err := rd.Users().Get(ctx, pendingID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)

	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = user.ActivateInviteOnVerificationTx(ctx, w, pending, string(pending.ID))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.updated", string(pendingID))
	require.Equal(t, string(pendingID), r.payload["resource_id"])
	require.Equal(t, string(pendingID), r.payload["actor"], "актор активации — сам человек строки")
	require.Regexp(t, evtIDFormat, r.id)
}

func TestUserAudit_5_2_14_DeleteEmitsDeleted(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	// A standalone user (owns no account) can self-delete.
	owner, accID := seedUserAccount(t, ctx, env.pool, "usr14del")
	_ = owner
	target := seedExtraUser(t, ctx, env.pool, accID, "del14")

	uc := user.NewDeleteUserUseCase(env.repo, env.opsRepo)
	// self-delete: principal == target.
	_, err := uc.Execute(withPrincipal(target), target)
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.deleted", string(target))
	require.Equal(t, string(target), r.payload["resource_id"])
	require.Equal(t, string(target), r.payload["actor"])
}
