// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_audit_integration_test.go — User audit slice.
// UpsertFromIdentity insert-branch → iam.user.created;
// activate-invite update-branch → iam.user.updated; Delete → iam.user.deleted.
//
// UpsertFromIdentity is the InternalUserService bootstrap/provision path (Kratos
// hook + admin-tooling). When no caller principal is present (Kratos provision)
// the actor is the system/bootstrap identity — recorded, never fabricated.
// Delete runs through the public UserService.Delete (self-delete).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestUserAudit_5_2_14_UpsertInsertEmitsCreated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// No caller principal → Kratos-provision bootstrap path. actor = system/bootstrap.
	bootstrapCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap", DisplayName: "kaname-bootstrap"})

	uc := user.NewUpsertFromIdentityUseCase(env.repo, env.opsRepo)
	_, err := uc.Execute(bootstrapCtx, user.UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject("ext-sub-5214-insert"),
		Email:       domain.Email("u-5214-insert@example.com"),
		DisplayName: domain.DisplayName("Upsert Insert"),
	})
	require.NoError(t, err)
	awaitWorkers(t)

	usrID := singleID(t, ctx, env, `SELECT id FROM kaname.users WHERE external_id = $1 AND email = $2`,
		"ext-sub-5214-insert", "u-5214-insert@example.com")

	r := requireOneAuditRow(ctx, t, env.pool, "iam.user.created", usrID)
	require.Equal(t, "user", r.payload["resource_type"])
	require.Equal(t, usrID, r.payload["resource_id"])
	// Kratos-provision has no user principal → IsAnonymous(bootstrap)=true →
	// PrincipalUserID="" → the use-case records the non-fabricated system
	// identity "system" (never an invented user id). 5.2-14.
	require.Equal(t, "system", r.payload["actor"],
		"Kratos-provision actor is the system identity, never fabricated")
	require.Regexp(t, evtIDFormat, r.id)

	// Здесь стояло требование, чтобы нагрузка НЕСЛА почту и отображаемое имя.
	// Требование пришпиливало утечку: приёмник журнала кладёт все поля как есть,
	// шага сокрытия нет ни одного, и оба поля уезжали в поток службы
	// (`kacho#2483`). Проба не ослаблена, а ПЕРЕВЁРНУТА — утверждает теперь
	// отсутствие, — и утверждает его НА ЧИТАЕМОМ СЛЕДЕ, а не о коде.
	//
	// Положительный контроль выше обязателен: без него отрицание зеленело бы на
	// пустой нагрузке и на неэмитированном событии.
	for _, k := range []string{"email", "display_name", "displayName", "external_id"} {
		require.NotContains(t, r.payload, k,
			"личные данные в поток аудита не уезжают: %s", k)
	}
	// И их там нет НЕ потому, что значения пусты: субъект в следе назван, просто
	// назван идентификатором. Корреляция сохранена, срок хранения потока больше
	// не есть срок хранения личных данных.
	require.NotEmpty(t, r.payload["resource_id"], "субъект назван — идентификатором, а не почтой")
}

func TestUserAudit_5_2_14_UpsertActivateEmitsUpdated(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// Seed a PENDING invite row by email (no external_id yet).
	owner, accID := seedUserAccount(t, ctx, env.pool, "usr14upd")
	_ = owner
	pendingID := domain.UserID("usr0000000000005214pp")
	_, err := env.pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, $4, 'PENDING')`,
		string(pendingID), string(accID), "u-5214-activate@example.com", "Pending Invitee")
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
