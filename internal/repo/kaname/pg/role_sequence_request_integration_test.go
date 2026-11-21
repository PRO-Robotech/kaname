// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestPreparedRoleSequencePreservesMetadataMaskEmptyMaskAndStaleCAS(t *testing.T) {
	for _, mode := range []string{"metadata", "empty-mask", "stale-CAS"} {
		t.Run(mode, func(t *testing.T) {
			w := delegationUCFixture(t)
			role := roleFinalCreate(t, w, nil, "sequence_request_role")
			full, _ := fullContractActivate(t, w.r)
			factory, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, full, w.r.bundle)
			require.NoError(t, err)
			rd, err := w.r.repo.Reader(w.r.ctx)
			require.NoError(t, err)
			current, version, err := rd.Roles().GetWithVersion(w.r.ctx, role.ID)
			require.NoError(t, err)
			require.NoError(t, rd.Rollback(w.r.ctx))
			proposed := current
			proposed.Description = "exact metadata request"
			mask := []string{"description"}
			if mode == "empty-mask" {
				mask = []string{}
			}
			if mode == "stale-CAS" {
				version = "0"
			}
			var before int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=$1`, string(role.ID)).Scan(&before))
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.owner)}
			writer, err := factory.RoleMutationWriter(w.r.ctx, kaname.RoleMutationRequest{Role: proposed, Update: true, UpdateMask: mask, ExpectedVersion: version}, actor)
			require.NoError(t, err)
			defer writer.Rollback(context.WithoutCancel(w.r.ctx))
			require.NoError(t, grantpolicy.RequireRoleMethod(w.r.ctx, writer, actor, proposed, false), "реальный OLD native gate до записи")
			got, err := writer.RolesW().UpdateCAS(w.r.ctx, proposed, mask, version)
			if mode == "stale-CAS" {
				require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
				require.NoError(t, writer.Rollback(w.r.ctx))
			} else {
				require.NoError(t, err)
				require.NoError(t, writer.Commit(w.r.ctx))
				// Пустая маска фактического roleUpdateArgs означает все mutable поля.
				// Проверяем этот контракт, а не устаревший комментарий о re-touch.
				{
					require.Equal(t, proposed.Description, got.Description)
					var stamp time.Time
					require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT created_at FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=$1 ORDER BY sequence_no DESC LIMIT 1`, string(role.ID)).Scan(&stamp))
					require.Equal(t, got.UpdatedAt, stamp, "ровно зарезервированный owner timestamp потреблён root UPDATE и canonical journal")
				}
			}
			var after int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_role' AND resource_id=$1`, string(role.ID)).Scan(&after))
			want := before
			if mode != "stale-CAS" {
				want++
			}
			require.Equal(t, want, after)
			rd, err = w.r.repo.Reader(w.r.ctx)
			require.NoError(t, err)
			actual, _, err := rd.Roles().GetWithVersion(w.r.ctx, role.ID)
			require.NoError(t, err)
			require.NoError(t, rd.Rollback(w.r.ctx))
			if mode == "stale-CAS" {
				require.Equal(t, current.Description, actual.Description)
				require.Equal(t, current.UpdatedAt, actual.UpdatedAt)
			} else {
				require.Equal(t, proposed.Description, actual.Description)
			}
		})
	}
}
