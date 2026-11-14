// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/stretchr/testify/require"
)

type delegatedDecisionFailure struct {
	*bindingDecisionFailure
	delegated int
	captured  domain.GrantDelegationID
	failure   error
}

func (f *delegatedDecisionFailure) RunDelegatedBindingDecision(ctx context.Context, actor domain.Subject, b domain.AccessBinding, _ func(domain.AccessBinding, domain.Role) []ab.RelationTuple, _ func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	f.delegated++
	f.captured = b.DelegationID
	return f.failure
}

// Проверяется реальный выбор двери use-case, а не разрешающий mock policy.
// Positive policy, оси и same-TX callbacks отдельно проверяет PG actual API.
func TestDelegatedBindingDecisionOnlyPermissionDenialSelectsException(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ordinary error
		want     int
	}{
		{"ordinary-success", nil, 0},
		{"permission-denied", iamerr.ErrPermissionDenied, 1},
		{"backend-error", errors.New("source database unavailable"), 0},
		{"cancel", context.Canceled, 0},
		{"unconfirmed", kaname.ErrSourceUnconfirmed, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &delegatedDecisionFailure{bindingDecisionFailure: &bindingDecisionFailure{err: tc.ordinary}, failure: errors.New("delegated path reached")}
			u := (&CreateAccessBindingUseCase{delegated: &DelegatedGrantPath{}}).WithBindingDecisions(f)
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "sva-caller"})
			id, err := u.checkBindingDecision(ctx, domain.AccessBinding{ID: "acb-candidate"})
			require.Empty(t, id)
			require.Equal(t, tc.want, f.delegated)
			require.Equal(t, 1, f.called)
			if tc.ordinary == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
func TestDelegatedBindingDecisionWorkerKeepsCapturedIDWithoutOrdinaryFallback(t *testing.T) {
	f := &delegatedDecisionFailure{bindingDecisionFailure: &bindingDecisionFailure{}, failure: iamerr.ErrPermissionDenied}
	u := (&CreateAccessBindingUseCase{delegated: &DelegatedGrantPath{}}).WithBindingDecisions(f)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "sva-caller"})
	_, err := u.doCreate(ctx, domain.AccessBinding{ID: "acb-candidate", DelegationID: "gdl-captured"}, "sva-caller")
	require.Error(t, err)
	require.Zero(t, f.called)
	require.Equal(t, 1, f.delegated)
	require.Equal(t, domain.GrantDelegationID("gdl-captured"), f.captured)
}
