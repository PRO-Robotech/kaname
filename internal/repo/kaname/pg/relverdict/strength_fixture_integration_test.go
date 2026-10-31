// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestStrengthFixture_ZeroShareControlsAllCandidates(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, _ := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	for _, share := range []int{100, 50, 0, 100} {
		f.growN(t, ctx, 100, share)
		f.analyze(t, ctx)
		ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject:strSubject, ObjectType:strModelType, Relation:strRelation, Limit:200,
		})
		require.NoError(t, err)
		want := share
		if share > 0 { want++ }
		require.Len(t, ids, want, "доля %d учитывает и специальный объект",share)
		if share > 0 { require.Contains(t, ids, strAllowObj) } else { require.Empty(t, ids) }
	}
}
