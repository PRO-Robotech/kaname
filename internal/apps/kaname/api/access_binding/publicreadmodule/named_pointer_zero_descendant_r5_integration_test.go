// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadmodule_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// После старого retirement самостоятельный legacy Register восстанавливает
// mirror C под независимо удержанным box, НЕ активируя named history F.
// Zero intent обязан завершиться одинаково при обоих порядках последних снятий.
func TestNamedRetirement_ZeroDescendantAfterLowerLegacyReregistration(t *testing.T) {
	for _, finite := range []bool{false, true} {
		for _, parentFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("finite=%t/parentFirst=%t", finite, parentFirst), func(t *testing.T) {
				w, parent, tuples, f, p := r4World(t, true, false)
				holder := r4Holder(t, w, tuples)
				require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
				require.NoError(t, w.reg.Register(w.ctx, parent))
				now := time.Now().UTC().Truncate(time.Microsecond)
				c := now.Add(time.Hour)
				p2 := now.Add(30 * time.Minute)
				require.True(t, now.Before(p2) && p2.Before(c) && c.Before(f))
				require.NoError(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], c)))
				n, _ := r4Receipt(t, w, tuples[1])
				require.Zero(t, n, "реальный owner emit инвалидирует старую квитанцию")
				typ, id, _ := strings.Cut(tuples[0].Object, ":")
				assertHistory := func() {
					var inactive, own bool
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT NOT active,source_version=$1 FROM kaname.resource_registration_pointer WHERE object_type=$2 AND object_id=$3 AND relation='box' AND subject=$4`, f, typ, id, tuples[0].User).Scan(&inactive, &own))
					require.True(t, inactive, "named reactivation в этом сценарии нет")
					require.True(t, own, "чужой P/C не заменяет retained named history F")
				}
				assertHistory()
				var mirrorC bool
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT source_version=$1 FROM kaname.resource_mirror WHERE object_type='probemod.items' AND object_id=$2`, c, id).Scan(&mirrorC))
				require.True(t, mirrorC)
				var journalBefore int64
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT coalesce(max(id),0) FROM kaname.fga_outbox`).Scan(&journalBefore))
				intent := time.Time{}
				if finite {
					intent = p2
				}
				withdraw := func() { require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, intent))) }
				if parentFirst {
					withdraw()
					for _, tuple := range tuples {
						require.Equal(t, 1, r3FactCount(t, w, tuple), "ACTIVE independent holder сохраняется")
					}
					r4Release(t, w, holder, tuples)
				} else {
					r4Release(t, w, holder, tuples)
					require.Zero(t, r3FactCount(t, w, tuples[0]))
					require.Equal(t, 1, r3FactCount(t, w, tuples[1]), "инвалидированная proof не снимает текущий future owner F")
					withdraw()
				}
				wantOwner := 0
				wantCutoff := f
				if finite {
					wantOwner = 1
					wantCutoff = c
				}
				require.Equal(t, wantOwner, r3FactCount(t, w, tuples[1]))
				require.Zero(t, r3FactCount(t, w, tuples[0]))
				n, cutoff := r4Receipt(t, w, tuples[1])
				require.Equal(t, 1, n)
				require.True(t, wantCutoff.Equal(cutoff))
				var mirrors, edges int
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_id IN ('mixed-box','mixed-item')`).Scan(&mirrors))
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id IN ('mixed-box','mixed-item')`).Scan(&edges))
				require.Zero(t, mirrors)
				require.Zero(t, edges)
				assertHistory()
				var ownerRows, namedRows int
				if finite {
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE id>$1 AND event_type='fga.tuple.delete' AND payload->>'object'=$2 AND payload->>'relation'='owner' AND payload->>'user'=$3 AND payload->'protect_holders'='true'::jsonb AND (payload->>'source_version')::timestamptz=$4`, journalBefore, tuples[1].Object, tuples[1].User, c).Scan(&ownerRows))
				} else {
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE id>$1 AND event_type='fga.tuple.delete' AND payload->>'object'=$2 AND payload->>'relation'='owner' AND payload->>'user'=$3 AND payload->'protect_holders'='true'::jsonb AND NOT(payload ? 'source_version')`, journalBefore, tuples[1].Object, tuples[1].User).Scan(&ownerRows))
				}
				require.Equal(t, 1, ownerRows, "zero actual removal и finite control имеют разные, точные journal modes")
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE id>$1 AND event_type='fga.tuple.delete' AND payload->>'object'=$2 AND payload->>'relation'='box' AND payload->>'user'=$3 AND payload->'protect_holders'='true'::jsonb AND (payload->>'source_version')::timestamptz=$4`, journalBefore, tuples[0].Object, tuples[0].User, c).Scan(&namedRows))
				require.Equal(t, 1, namedRows, "named child emit сохраняет собственный C/mode при zero root intent")
			})
		}
	}
}
