// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// get_seeded_system_role_test.go — роль, ПОСЕЯННАЯ применённой миграцией,
// достижима по тому id, которым её посеяли. Проба задачи #1808.
//
// # ЧТО БЫЛО СЛОМАНО
//
// `kacho-system.viewer` посеян идентификатором длиной 21 (`SystemViewerRoleID`),
// а проверка формы требовала ровно `domain.ShortIDLen` = 20 и стояла ПЕРВЫМ
// стейтментом каждого глагола роли. Арендатор получал роль в ответе `List` и не
// мог прочитать её ни одним путём: `Get`, `GetRoleCompiled`, `Update`, `Delete`,
// `ListAccessBindingsByRole` отвечали `INVALID_ARGUMENT` ещё до чтения.
//
// # ПАРАЛЛЕЛЬНЫЕ ПОЛОСЫ СВЕРЯЮТСЯ МЕЖДУ СОБОЙ
//
// Соседняя полоса того же механизма — `kacho-system.admin`, длина 20 — вела
// себя ИНАЧЕ, и различие никем не решалось (`architecture.md` §«Параллельные
// полосы одного механизма обязаны сверяться МЕЖДУ СОБОЙ»). Поэтому admin стоит
// здесь положительным контролем: без него утверждение про viewer зеленело бы и
// на проверке, которая не отвергает вовсе ничего.
//
// # ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ОБЯЗАТЕЛЕН
//
// Третий случай подаёт НЕПОСЕЯННЫЙ идентификатор той же негодной длины 21.
// Он обязан быть отвергнут: приём расширен ровно на закрытый перечень
// посеянного, а не на длину.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestGetRole_SeededSystemRoleIsReachableByItsSeededID(t *testing.T) {
	cases := []struct {
		name string
		id   string
		seed bool // лежит ли строка в хранилище
		want codes.Code
	}{
		{
			name: "посеянный viewer — длина 21, читается",
			id:   domain.SystemViewerRoleID,
			seed: true,
			want: codes.OK,
		},
		{
			name: "положительный контроль: посеянный admin — длина 20, читается",
			id:   domain.SystemAdminRoleID,
			seed: true,
			want: codes.OK,
		},
		{
			name: "отрицательный контроль: НЕпосеянный id длины 21 отвергается",
			// негодная форма id намеренно: проба УТВЕРЖДАЕТ отказ по длине —
			// приём расширен на закрытый перечень посеянного, а не на длину.
			id:   "rol000000000sysvi3w3r",
			seed: true, // строка есть — отказ обязан прийти от ФОРМЫ, а не от промаха
			want: codes.InvalidArgument,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRoleListFakeRepo()
			if tc.seed {
				repo.roles[tc.id] = domain.Role{
					ID:       domain.RoleID(tc.id),
					Name:     domain.RoleName("kacho-system.viewer"),
					IsSystem: true,
					Rules: domain.Rules{{
						Module: "*", Resources: []string{"*"}, Verbs: []string{"list", "get"},
					}},
					CreatedAt: time.Now().UTC(),
				}
			}

			uc := NewGetRoleUseCase(repo, catalogfixture.Source()).
				WithRelationStore(newRoleFGAStub()) // пустой набор: системная роль — пол каталога

			got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID(tc.id))

			if tc.want == codes.OK {
				require.NoErrorf(t, err,
					"роль %q посеяна применённой миграцией — она обязана читаться по своему id", tc.id)
				require.Equal(t, tc.id, string(got.ID))
				return
			}
			require.Error(t, err, "непосеянный идентификатор негодной формы обязан быть отвергнут")
			require.Equal(t, tc.want, status.Code(err))
		})
	}
}
