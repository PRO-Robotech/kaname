// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/stretchr/testify/require"
)

// Проверяем настоящий RR spool до запуска блокируемого apply. Наличие v_get
// не исключает viewer: оба эффекта должны попасть в record и write.
func BindingMirrorViewerStageForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, binding domain.AccessBindingID, account, uid, object string) {
	t.Helper()
	require.True(t, repo.fullContractMatches(bundle), "тот же pool действительно связан с FULL contract")
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	participant, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := participant.stage(ctx, binding, false)
	require.NoError(t, err)
	defer stage.close()
	require.False(t, stage.global)
	require.Equal(t, map[string]bool{account: true}, stage.accounts)
	rows, err := stage.conn.Query(ctx, `SELECT body FROM pg_temp.kaname_binding_stage ORDER BY phase,seq`)
	require.NoError(t, err)
	defer rows.Close()
	recorded, written := map[string]int{}, map[string]int{}
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var command reconcile.BindingCommand
		require.NoError(t, json.Unmarshal(raw, &command))
		if command.Kind == "record" {
			for _, ref := range command.Refs {
				if ref.BindingID == binding && ref.Member.ObjectType == "vpc.network" && ref.Member.ObjectID == object && ref.Tuple.User == "user:"+uid && ref.Tuple.Object == "vpc_network:"+object {
					recorded[ref.Tuple.Relation]++
				}
			}
		}
		if command.Kind == "write" {
			for _, tuple := range command.Tuples {
				if tuple.User == "user:"+uid && tuple.Object == "vpc_network:"+object {
					written[tuple.Relation]++
				}
			}
		}
	}
	require.NoError(t, rows.Err())
	for _, relation := range []string{"viewer", "v_get"} {
		require.Positive(t, recorded[relation], "actual staged ledger record: %s", relation)
		require.Positive(t, written[relation], "actual staged selected write: %s", relation)
	}
}
