// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/operationresolver"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Это проверка состояний восстановления, не имитация kill/restart процесса.
// Строка orphan задаётся явно; возраст меняется только для допуска Sweep.
// Мутация делегирования, запись терминала и повтор Update — настоящие пути.
func TestGrantDelegationUpdateOrphanTerminatesBeforeAndAfterCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before commit"
		if committed {
			name = "after commit"
		}
		t.Run(name, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			axes := u.all()
			if committed {
				u.patch("", axes)
				u.axes(axes)
			}
			before := u.get()
			if committed {
				require.NotEqual(t, u.original, before, "Дано: оси действительно расширены")
			} else {
				require.Equal(t, u.original, before, "Дано: строка существует ещё до Update")
			}
			audits := len(u.audit())
			op, err := operations.NewFromContext(asUser(u.ctx, u.usrA), domain.PrefixOperationIAM,
				"Update grant delegation recovery", &iamv1.UpdateGrantDelegationMetadata{
					GrantDelegationId: u.d, AccountId: string(u.accA),
				})
			require.NoError(t, err)
			require.NoError(t, u.ops.Create(u.ctx, op))
			aged, err := u.pool.Exec(u.ctx, `UPDATE kaname.operations SET modified_at = now() - interval '10 minutes' WHERE id = $1 AND done = false`, op.ID)
			require.NoError(t, err)
			require.EqualValues(t, 1, aged.RowsAffected())
			pending, err := u.ops.Get(u.ctx, op.ID)
			require.NoError(t, err)
			require.False(t, pending.Done)
			require.Nil(t, pending.Error)
			require.Nil(t, pending.Response)

			resolver := operationresolver.New(kanamepg.New(u.pool, nil), u.updateCatalog, kanamepg.NewAccessKeyRepo(u.pool))
			reconciler := operations.NewReconciler(u.pool, resolver, operations.ReconcilerConfig{Schema: "kaname"})
			n, err := reconciler.Sweep(u.ctx)
			require.NoError(t, err)
			require.Equal(t, 1, n)
			done, err := u.ops.Get(u.ctx, op.ID)
			require.NoError(t, err)
			require.True(t, done.Done, "orphan обязан перестать быть pending")
			require.NotNil(t, done.Error, "существующая строка не доказывает успех Update")
			require.Equal(t, int32(codes.Internal), done.Error.Code)
			require.Equal(t, "operation interrupted before completion", done.Error.Message)
			require.Nil(t, done.Response)
			require.Equal(t, before, u.get(), "recovery не воспроизводит потерянную мутацию")
			require.Len(t, u.audit(), audits)
			n, err = reconciler.Sweep(u.ctx)
			require.NoError(t, err)
			require.Zero(t, n, "терминальная операция не переклеймливается")
			again, err := u.ops.Get(u.ctx, op.ID)
			require.NoError(t, err)
			require.Equal(t, done, again)

			// Клиент повторяет исходный запрос штатно. После коммита это no-op;
			// до коммита — единственная мутация и единственное событие расширения.
			u.patch("", axes)
			u.axes(axes)
			if !committed {
				audits++
			}
			require.Len(t, u.audit(), audits)
			u.patch("", axes)
			u.axes(axes)
			require.Len(t, u.audit(), audits, "повтор не дублирует аудит изменения")
		})
	}
}
