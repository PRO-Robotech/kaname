// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// get_seeded_system_role_test.go — системная роль, ПОСЕЯННАЯ миграцией,
// достижима по тому id, который служба отдаёт в ответе `List`. Проба задачи
// kacho#1808, приведённая к kaname#543.
//
// # ЧТО БЫЛО СЛОМАНО
//
// Свод посеял `kacho-system.viewer` идентификатором длиной 21, а проверка формы
// требовала ровно `domain.ShortIDLen` = 20 и стояла ПЕРВЫМ стейтментом каждого
// глагола роли. Арендатор получал роль в ответе `List` и не мог прочитать её ни
// одним путём: `Get`, `GetRoleCompiled`, `Update`, `Delete`,
// `ListAccessBindingsByRole` отвечали `INVALID_ARGUMENT` ещё до чтения.
// kacho#1808 закрыла это закрытым перечнем посеянного; kaname#543 перевела обе
// системные роли на id канонической формы миграцией и перечень сняла. Проба
// утверждает итог: обе роли читаются по своим нынешним id.
//
// # ПАРАЛЛЕЛЬНЫЕ ПОЛОСЫ СВЕРЯЮТСЯ МЕЖДУ СОБОЙ
//
// Обе системные роли — полосы одного механизма (`architecture.md`
// §«Параллельные полосы одного механизма обязаны сверяться МЕЖДУ СОБОЙ»), и
// утверждаются здесь обе: одна без другой зеленела бы и на проверке, которая
// не отвергает вовсе ничего.
//
// # ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ ОБЯЗАТЕЛЕН
//
// Третий случай подаёт идентификатор той же роли длиной 21 при ЛЕЖАЩЕЙ строке.
// Он обязан быть отвергнут формой: исключений у длины больше нет.

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
			name: "посеянный viewer — читается по нынешнему id",
			id:   domain.SystemViewerRoleID,
			seed: true,
			want: codes.OK,
		},
		{
			name: "посеянный admin — читается по нынешнему id",
			id:   domain.SystemAdminRoleID,
			seed: true,
			want: codes.OK,
		},
		{
			name: "отрицательный контроль: id длины 21 отвергается и при лежащей строке",
			// негодная форма id намеренно: проба УТВЕРЖДАЕТ отказ по длине —
			// исключений у длины нет.
			id:   "rol0123456789abcdefgh",
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
					"системная роль %q обязана читаться по своему нынешнему id", tc.id)
				require.Equal(t, tc.id, string(got.ID))
				return
			}
			require.Error(t, err, "идентификатор негодной формы обязан быть отвергнут")
			require.Equal(t, tc.want, status.Code(err))
		})
	}
}
