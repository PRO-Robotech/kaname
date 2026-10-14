// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invite_grant_scope_delete_leaves_no_facts_integration_test.go — выдача роли на
// проект, положенная ПРИГЛАШЕНИЕМ, после удаления проекта не оставляет фактов в
// модели прав (kaname#670, класс kaname#665).
//
// # Предмет
//
// Глагол приглашения с `projectId + roleId` кладёт выдачу на проект и эмитит
// указатель её объекта на предка `project:<P>#project@iam_access_binding:<AB>`.
// Снятие проекта дренирует выдачи области СИММЕТРИЧНО ПО ВЕДОМОСТИ
// (`shared.RevokeBindingsInScope` → `SelectEmittedTuples`): что записано
// выпущенным, то и снимается. Ведомость эта выдача не писала — строка уходила, а
// указатель оставался фактом модели прав на проект, которого больше нет.
//
// # Как строится «Когда»
//
// Настоящий use-case приглашения (`user.NewInviteUserUseCase`) с настоящим
// реконсайлером — так выдача материализует и своё членство, как в продукте, —
// настоящий глагол удаления проекта и шаг воркера событий снятия (окружение и
// шаг — те же, что у пробы kaname#665).
//
// # Пара
//
// До удаления факты выдачи есть (иначе «0 после» ничего не доказывает), а проект
// соседней личности своих фактов не теряет.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// inviteAllowAll — дверь права приглашать: пропускает (права решает модель на
// крае, предмет пробы — следы выдачи).
type inviteAllowAll struct{}

func (inviteAllowAll) Check(context.Context, string, string, string) (bool, error) { return true, nil }

// TestProjectDelete_InviteGrantLeavesNoFacts — после удаления проекта фактов,
// называющих его, 0 и на пути приглашения; объект выдачи приглашения фактов не
// несёт (kaname#670, предикат задачи).
func TestProjectDelete_InviteGrantLeavesNoFacts(t *testing.T) {
	e := newScopeDeleteEnv(t)
	ctx := context.Background()

	uid, accID := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_670_inviter", "inviter-670@example.com")
	prj := defaultProjectOf(t, ctx, e.pool, accID)
	_, bystAcc := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_670_byst", "byst-670@example.com")
	bystPrj := defaultProjectOf(t, ctx, e.pool, bystAcc)

	rec, _ := newReconciler(e.pool)
	uc := user.NewInviteUserUseCase(e.repo, e.ops, inviteAllowAll{}).
		WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 100, Window: time.Hour}, nil).
		WithObjectReconciler(rec)
	op, err := uc.Execute(principalCtx(uid), user.InviteUserInput{
		AccountID: accID,
		Email:     domain.Email("invitee-670@example.com"),
		ProjectID: prj,
		RoleID:    domain.RoleID(domain.ClusterAdminRoleID),
	})
	require.NoError(t, err, "приглашение принято")
	require.Empty(t, awaitScopeDeleteOp(t, e.ops, op), "приглашение с выдачей на проект отказало")

	var inviteAB string
	require.NoError(t, e.pool.QueryRow(ctx, `
		SELECT b.id FROM kaname.access_bindings b
		  JOIN kaname.users u ON u.id = b.subject_id
		 WHERE b.resource_type = 'project' AND b.resource_id = $1
		   AND lower(u.email) = 'invitee-670@example.com'`, string(prj)).Scan(&inviteAB),
		"ПРЕДПОСЫЛКА: приглашение положило выдачу на проект")
	require.NotEmpty(t, factsNaming(t, ctx, e.pool, "iam_access_binding", inviteAB),
		"ПРЕДПОСЫЛКА: у объекта выдачи приглашения до удаления есть факты")
	bystBefore := factsNaming(t, ctx, e.pool, "project", string(bystPrj))
	require.NotEmpty(t, bystBefore, "ПРЕДПОСЫЛКА: у проекта соседа есть факты")

	e.deleteProject(t, uid, prj)

	left := factsNaming(t, ctx, e.pool, "project", string(prj))
	require.Empty(t, left,
		"после удаления проекта остались факты, называющие его (%d):\n  %s",
		len(left), strings.Join(left, "\n  "))
	abLeft := factsNaming(t, ctx, e.pool, "iam_access_binding", inviteAB)
	require.Empty(t, abLeft,
		"выдача приглашения снята вместе с проектом, а факты её объекта остались (%d):\n  %s",
		len(abLeft), strings.Join(abLeft, "\n  "))
	require.Equal(t, bystBefore, factsNaming(t, ctx, e.pool, "project", string(bystPrj)),
		"удаление чужого проекта изменило факты соседа")
}
