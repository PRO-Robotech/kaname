// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceObjectFinalCommandsUseHeldClockAndAttempt(t *testing.T) {
	for _, offset := range []time.Duration{-time.Second, 0, time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			lifetime, owner, raw := resourceLifetimeFixture(t)
			expires := lifetime.at.Add(offset)
			binding := domain.AccessBinding{ID: "abn_clock", ExpiresAt: &expires}
			input := reconcile.CapturedObjectDiff{
				Binding: reconcile.BindingScope{BindingID: binding.ID, RoleID: "rol_clock", Active: true}, Additive: true,
				Desired: []reconcile.DesiredMember{{RuleFP: "rule_clock", ObjectType: "vpc.subnet", ObjectID: "sub_clock", Status: domain.VerificationActive, Tuples: []domain.MembershipTuple{{User: "user:usr_clock", Relation: "viewer", Object: "subnet:sub_clock"}}}},
				Live:    map[reconcile.MemberCoord]bool{{ObjectType: "vpc.subnet", ObjectID: "sub_clock"}: true},
			}
			prepared := &resourceObjectPreparation{lifetime: lifetime, root: &resourceOutputCapture{bindings: map[string]domain.AccessBinding{"abn_clock": binding}}, inputs: []reconcile.CapturedObjectDiff{input}}
			tx := &resourceDecisionTx{Tx: raw, owner: owner, lifetime: lifetime}
			commands, err := prepared.finalCommands(context.Background(), tx)
			require.NoError(t, err)
			if offset > 0 {
				require.NotEmpty(t, commands)
			} else {
				require.Empty(t, commands)
			}
			require.True(t, prepared.inputs[0].Binding.Active, "final eligibility не переписывает исходный RR факт")
			owner.fence.decisionAt = owner.fence.decisionAt.Add(time.Second)
			_, err = prepared.finalCommands(context.Background(), tx)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "поздние часы не продлевают свидетельство")
		})
	}
}
