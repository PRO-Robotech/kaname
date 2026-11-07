// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package target_members

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Единственный разрешённый метод caller-owned tx — Exec; Begin/Commit/Rollback
// у embedded nil tx вызвали бы panic и не могут скрыть смену границы транзакции.
type memberBatchTx struct {
	pgx.Tx
	exec func(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func (tx *memberBatchTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.exec(ctx, sql, args...)
}

func batchMember(i int) Member {
	return Member{BindingID: "binding", RoleID: "role", RuleFP: "rule", ObjectType: "compute.instance", ObjectID: fmt.Sprintf("i-%05d", i), VerificationStatus: domain.VerificationActive}
}

func TestUpsertManyTx_GlobalFirstWinsAcrossChunksAndFullKey(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "caller")
	members := make([]Member, 0, 4101)
	for i := 0; i < 4096; i++ {
		members = append(members, batchMember(i))
	}
	want := append([]Member(nil), members...)
	duplicate := members[0]
	duplicate.VerificationStatus = domain.VerificationRejected
	members = append(members, duplicate)
	for field := 0; field < 4; field++ {
		m := members[0]
		switch field {
		case 0:
			m.BindingID = "other-binding"
		case 1:
			m.RoleID = "other-role"
		case 2:
			m.RuleFP = "other-rule"
		case 3:
			m.ObjectType = "compute.disk"
		}
		m.VerificationStatus = domain.VerificationPending
		members = append(members, m)
		want = append(want, m)
	}
	members = append(members, duplicate)
	var got []Member
	var sizes []int
	tx := &memberBatchTx{exec: func(gotCtx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
		require.Same(t, ctx, gotCtx)
		require.Contains(t, sql, "ON CONFLICT (binding_id, role_id, rule_fp, object_type, object_id)")
		require.Len(t, args, 6)
		var cols [6][]string
		for i, arg := range args {
			cols[i] = arg.([]string)
			require.Len(t, cols[i], len(cols[0]))
		}
		require.LessOrEqual(t, len(cols[0]), 4096)
		sizes = append(sizes, len(cols[0]))
		for i := range cols[0] {
			got = append(got, Member{BindingID: cols[0][i], RoleID: cols[1][i], RuleFP: cols[2][i], ObjectType: cols[3][i], ObjectID: cols[4][i], VerificationStatus: domain.VerificationStatus(cols[5][i])})
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	}}
	require.NoError(t, UpsertManyTx(ctx, tx, members))
	require.Equal(t, []int{4096, 4}, sizes)
	require.Equal(t, want, got, "пять частей ключа и первый статус сохраняются сквозь границу SQL")
}

func TestUpsertManyTx_CallerContextAndSecondChunkFailure(t *testing.T) {
	for _, cancellation := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancellation), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("second chunk SQL failure")
			members := make([]Member, 8193)
			for i := range members {
				members[i] = batchMember(i)
			}
			calls := 0
			tx := &memberBatchTx{exec: func(got context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
				require.Same(t, ctx, got)
				calls++
				if calls == 1 {
					if cancellation {
						cancel()
					}
					return pgconn.CommandTag{}, nil
				}
				if cancellation {
					return pgconn.CommandTag{}, got.Err()
				}
				return pgconn.CommandTag{}, failure
			}}
			err := UpsertManyTx(ctx, tx, members)
			if cancellation {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, failure)
			}
			require.ErrorContains(t, err, "target_members: upsert many (4096)")
			require.Equal(t, 2, calls, "ошибка не разрешает третью партию или успешный возврат")
		})
	}
}

func TestUpsertManyTx_EmptyAndExactBoundary(t *testing.T) {
	require.NoError(t, UpsertManyTx(context.Background(), nil, nil))
	calls := 0
	tx := &memberBatchTx{exec: func(context.Context, string, ...any) (pgconn.CommandTag, error) {
		calls++
		return pgconn.CommandTag{}, nil
	}}
	members := make([]Member, 4096)
	for i := range members {
		members[i] = batchMember(i)
	}
	require.NoError(t, UpsertManyTx(context.Background(), tx, members))
	require.Equal(t, 1, calls, "после полной партии пустой Exec не нужен")
}
