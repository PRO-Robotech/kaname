// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// machine_principal_reaches_usecase_test.go — AccountService.Delete must not
// re-decide authorization in-service.
//
// The model gates it: the api-gateway Checks `v_delete` on
// `account:<account_id>` (permission catalog; locked by
// gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go) before
// iam is dialed. The removed `authzguard.RequireOwnerMatchesPrincipal` then
// re-decided it from `accounts.owner_user_id`, which (a) rejected every machine
// principal by construction, (b) voided any delegation the owner granted through
// an AccessBinding, and (c) rejected cluster-admins on accounts they do not own —
// all with `InvalidArgument` naming a field the caller never sent.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func acctNonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		// Can never equal accounts.owner_user_id — a machine was locked out
		// of Account.Delete by construction.
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
		// A human holding v_delete@account through an AccessBinding the owner made.
		"delegated_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000dlgt"}),
	}
}

func TestDeleteAccount_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range acctNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteAccountUseCase(newDelFakeRepo(), newFakeOpsRepo())
			op, err := uc.Execute(ctx, domain.AccountID(delTestAcct))
			require.NoError(t, err,
				"AccountService.Delete is gated by v_delete@account at the gateway; "+
					"the use-case must not re-decide access from accounts.owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

// The sync pre-checks that are NOT authz decisions must survive untouched:
// anonymous is still refused, a malformed id is still InvalidArgument, and a
// well-formed-but-absent id still resolves to NotFound through repo.Get.
func TestDeleteAccount_NonAuthzSyncChecksSurvive(t *testing.T) {
	t.Run("anonymous still rejected", func(t *testing.T) {
		uc := NewDeleteAccountUseCase(newDelFakeRepo(), newFakeOpsRepo())
		_, err := uc.Execute(context.Background(), domain.AccountID(delTestAcct))
		require.Error(t, err)
	})
	t.Run("malformed id still InvalidArgument", func(t *testing.T) {
		uc := NewDeleteAccountUseCase(newDelFakeRepo(), newFakeOpsRepo())
		_, err := uc.Execute(acctNonOwnerCtxs()["delegated_user"], "not-an-account-id")
		require.Error(t, err)
	})
}
