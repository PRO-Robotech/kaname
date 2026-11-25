// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveUsesCapturedCoordinateAndSharedEffectLimit(t *testing.T) {
	bundle := nativeBoundaryBundle(t)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	ref := domain.ResourceRef{Type: "iam.account", ID: strings.Repeat("x", grantcoverage.MaxStringBytes)}
	s := &roleSelectorMoveStage{facts: facts, captured: accessLabelSelectorMoveCapture{
		Graphs: map[domain.ResourceRef]accessLabelMoveGraph{
			ref: {Present: true, Object: domain.MirrorObject{ObjectType: ref.Type, ObjectID: ref.ID}},
		},
	}}
	grant := accessLabelMoveGrant{BindingID: "acb-one", Scope: domain.ScopeAnchor{Type: "cluster", ID: domain.ClusterSingletonID},
		Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-one"},
		Tuple:     domain.MembershipTuple{User: "user:usr-one", Relation: "admin", Object: "account:" + ref.ID},
	}
	accountEffects, err := s.compileGrantEffects(t.Context(), bundle, []accessLabelMoveGrant{grant}, &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.Len(t, accountEffects, 1)
	count, size, _ := accountEffects[0].model.Cost()
	require.Positive(t, size)
	n := granteffect.MaxInputBytes/size + 1
	require.Greater(t, n, 1)
	require.LessOrEqual(t, n*count, granteffect.MaxEffects)
	bulk := make([]accessLabelMoveGrant, n)
	for i := range bulk {
		bulk[i] = grant
	}
	_, err = s.compileGrantEffects(t.Context(), bundle, bulk, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)

	grant.Tuple.Object = "account:other"
	_, err = s.compileGrantEffects(t.Context(), bundle, []accessLabelMoveGrant{grant}, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}
