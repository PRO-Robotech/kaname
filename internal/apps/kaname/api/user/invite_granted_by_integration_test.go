// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_granted_by_integration_test.go — выдача, положенная приглашением,
// несёт выдавшего (PRO-Robotech/kaname#262).
//
// Глагол приглашения с `project_id + role_id` кладёт строку в ту же таблицу
// `kaname.access_bindings`, что `AccessBindingService.Create`. Столбец
// `granted_by_user_id` объявлен аудитом и читается записями об отзыве и
// удалении как актор выдачи. Одно и то же право, положенное двумя глаголами,
// не вправе различаться по полю аудита: правило у обоих одно —
// `authzguard.PrincipalUserID` (человек — его строка, служебная учётка — её
// идентификатор), а не пустое умолчание столбца.
//
// Утверждается СТРОКА в базе, а не значение, отданное дублёру писателя: репо
// пишет значение как пришло, и проба на настоящем Postgres закрывает оба
// звена разом. Пара — по типу вызывающего: человек и служебная учётка. Обе
// стороны нужны: правка, ставящая выдавшим только человека (форма
// `HumanUserID`, которой судится `users.invited_by`), прошла бы половину пары
// и оставила служебной учётке пустой столбец.
package user

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestInviteIntegration_ProjectGrantCarriesTheGranter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	inviter, accID := seedUserWithAccount(t, ctx, pool, "grantedby")
	projID := ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.projects (id, account_id, name, description, labels, created_at)
		VALUES ($1, $2, $3, '', '{}'::jsonb, now())`,
		projID, string(accID), "p-"+strings.ToLower(projID[4:12]))
	require.NoError(t, err)

	cases := []struct {
		name      string
		principal operations.Principal
	}{
		{"человек", operations.Principal{Type: "user", ID: string(inviter)}},
		{"служебная учётка", operations.Principal{Type: "service_account", ID: ids.NewID("sva")}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("granted-by-%d-%s@example.test", i, strings.ToLower(projID[4:10]))
			ops := newFakeUsrOps()
			uc := NewInviteUserUseCase(repo, ops, invPrincAllowAll{}).WithInviteMailRateLimit(cmMailLimit, nil)
			pctx := operations.WithPrincipal(ctx, tc.principal)

			op, err := uc.Execute(pctx, InviteUserInput{
				AccountID: accID,
				Email:     domain.Email(email),
				ProjectID: domain.ProjectID(projID),
				RoleID:    domain.RoleID(domain.ClusterAdminRoleID),
			})
			require.NoError(t, err, "приглашение обязано быть принято")
			require.NotNil(t, op)

			var done *operations.Operation
			require.Eventually(t, func() bool {
				got, gerr := ops.Get(ctx, op.ID)
				if gerr != nil || !got.Done {
					return false
				}
				done = got
				return true
			}, 10*time.Second, 20*time.Millisecond, "операция приглашения обязана завершиться")
			require.Nil(t, done.Error, "приглашение обязано завершиться успехом: %v", done.Error)

			var grantedBy string
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT b.granted_by_user_id
				  FROM kaname.access_bindings b
				  JOIN kaname.users u ON u.id = b.subject_id
				 WHERE b.resource_type = 'project' AND b.resource_id = $1
				   AND b.subject_type = 'user' AND lower(u.email) = lower($2)`,
				projID, email).Scan(&grantedBy),
				"ПРЕДПОСЫЛКА: приглашение с project_id + role_id кладёт выдачу на проект")
			require.Equal(t, tc.principal.ID, grantedBy,
				"выдача, положенная приглашением, несёт выдавшего по тому же правилу, что "+
					"AccessBindingService.Create (kaname#262), а не умолчание столбца ''")
		})
	}
}
