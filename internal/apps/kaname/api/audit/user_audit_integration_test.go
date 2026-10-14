// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_audit_integration_test.go — User audit slice.
// UpsertFromIdentity insert-branch → отказ базы (kaname#608), следа нет;
// activate-invite update-branch → iam.user.updated; Delete → iam.user.deleted.
//
// UpsertFromIdentity is the InternalUserService bootstrap/provision path
// (admin-tooling). When no caller principal is present (provision without a
// JWT) the actor is the system/bootstrap identity — recorded, never fabricated.
// Delete runs through the public UserService.Delete (self-delete).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestUserAudit_5_2_14_UpsertInsertIsRefusedAndLeavesNoTrace — ветвь заведения
// новой личности внутренним глаголом заведения по внешнему удостоверению
// производит `ACTIVE` без способа входа, и с инвариантом kaname#608
// (`users_active_has_a_way_in_fk`, приёмка `active-identity-has-a-way-in.md`
// AWI-01, C2) база отвергает её фиксацию: операция завершается отказом, строки
// личности нет, события заведения нет — событие ложится той же транзакцией и
// откатывается вместе с ней. Прежде проба утверждала здесь событие заведения;
// производитель этого события на живом пути — регистрация.
func TestUserAudit_5_2_14_UpsertInsertIsRefusedAndLeavesNoTrace(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	bootstrapCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kaname-bootstrap"})

	uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
	op, err := uc.Execute(bootstrapCtx, user.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject("ext-sub-5214-insert"),
		Email:       domain.Email("u-5214-insert@example.com"),
		DisplayName: domain.DisplayName("Upsert Insert"),
	})
	require.NoError(t, err, "приём операции синхронный; отказ — исход операции")
	awaitWorkers(t)

	done, err := env.opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, done.Done, "операция завершена")
	require.NotNil(t, done.Error, "AWI-01: заведение ACTIVE без способа входа обязано получить отказ базы")

	var n int
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE external_id = $1`, "ext-sub-5214-insert").Scan(&n))
	require.Zero(t, n, "строки личности после отказа нет")
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = 'iam.user.created'
		   AND event_payload->>'actor' = 'system'`).Scan(&n))
	require.Zero(t, n, "события заведения после отказа нет: оно откатилось той же транзакцией")
}

func TestUserAudit_5_2_14_UpsertActivateEmitsUpdated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed a PENDING invite row by email (no external_id yet). Приглашение путь
	// хука активирует только при отметке подтверждения нашей полосы
	// (kaname#456, Р11 п. 5): строка её несёт — предмет пробы событие, а не
	// отметка.
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

	bootstrapCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kaname-bootstrap"})

	uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
	_, err = uc.Execute(bootstrapCtx, user.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject("ext-sub-5214-activate"),
		Email:       domain.Email("u-5214-activate@example.com"),
		DisplayName: domain.DisplayName("Now Active"),
	})
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.updated", string(pendingID))
	require.Equal(t, string(pendingID), r.payload["resource_id"])
	require.Equal(t, "system", r.payload["actor"])
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
