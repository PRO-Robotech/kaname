// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// account_delete_cleanup_fga_integration_test.go — REAL OpenFGA proof of the
// Account.Delete owner-tuple cleanup (#234 / VBC-17). The FGA model derives
// account admin from the owner self-grant (`define admin: … or owner`), so a live
// `user:<owner>#owner@account:<A>` tuple is STANDING ADMIN. Account.Delete revokes
// the owner self-grant (and the cluster pointer); this test proves that revoking
// those tuples flips the ex-owner's Check(admin/v_get, account) from ALLOW to DENY
// against the canonical fga_model.fga.
//
// Skipped under -short (needs Docker / colima).

import (
	"testing"

	"github.com/stretchr/testify/require"

	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// TestIntegration_AccountDelete_OwnerTupleRevoke_AdminFlipsToDeny_VBC17 — write the
// account-create owner-tuple set, prove the owner resolves admin (via `or owner`),
// then delete the owner self-grant + cluster pointer (the Account.Delete revoke set)
// and prove admin + v_get now DENY (no standing admin on a deleted account).
func TestIntegration_AccountDelete_OwnerTupleRevoke_AdminFlipsToDeny_VBC17(t *testing.T) {
	c := startOpenFGA(t)

	const (
		acc   = "acc_vbc17_A"
		owner = "usr_vbc17_owner"
		bind  = "acb_vbc17_own"
	)
	// What Account.Create materializes (ownerTuples + ownerBinding hierarchy + the
	// forward-reconciled per-object v_get on the account self).
	created := []abrepo.RelationTuple{
		{User: "user:" + owner, Relation: "owner", Object: "account:" + acc},
		{User: "cluster:cluster_kacho_root", Relation: "cluster", Object: "account:" + acc},
		{User: "account:" + acc, Relation: "account", Object: "iam_access_binding:" + bind},
		{User: "user:" + owner, Relation: "v_get", Object: "account:" + acc},
	}
	c.write(t, created)

	// Pre-delete: the owner resolves admin (via `define admin: … or owner`) and v_get.
	require.True(t, c.check(t, "user:"+owner, "admin", "account:"+acc),
		"VBC-17 pre-delete: owner self-grant derives account admin (`admin … or owner`)")
	require.True(t, c.check(t, "user:"+owner, "v_get", "account:"+acc),
		"VBC-17 pre-delete: owner holds the materialized v_get on the account")

	// Account.Delete revoke set: the owner self-grant + the cluster pointer + the
	// owner-binding hierarchy pointer + the owner's v_get self-tuple (the emitted
	// ledger + the cluster pointer the use-case revokes).
	c.delete(t, []abrepo.RelationTuple{
		{User: "user:" + owner, Relation: "owner", Object: "account:" + acc},
		{User: "cluster:cluster_kacho_root", Relation: "cluster", Object: "account:" + acc},
		{User: "account:" + acc, Relation: "account", Object: "iam_access_binding:" + bind},
		{User: "user:" + owner, Relation: "v_get", Object: "account:" + acc},
	})

	// Post-delete: the ex-owner resolves NEITHER admin NOR v_get — no standing admin
	// on a deleted account (the #234 dangling-owner-tuple bug is closed).
	require.False(t, c.check(t, "user:"+owner, "admin", "account:"+acc),
		"VBC-17: after Account.Delete revoke, ex-owner Check(admin, account) DENIES (no standing admin, #234)")
	require.False(t, c.check(t, "user:"+owner, "v_get", "account:"+acc),
		"VBC-17: after Account.Delete revoke, ex-owner Check(v_get, account) DENIES (owner self-tuples removed)")
}
