// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

// caller_authority_default_posture_test.go — the fail-closed posture of the
// inner caller-authority gate must be the DEFAULT, and the permissive posture an
// explicit opt-in.
//
// The gate's tenant arms are unconditionally fail-closed; its no-principal arm
// was not — it read a boolean that defaults to the permissive value, so a
// composition that never set it answered authorization questions about arbitrary
// subjects to a caller with no credentials at all. The knob is legitimate (a
// stand without mTLS cannot tell its two listeners apart), but the knob must
// carry the EXCEPTION, not the rule: an omitted setter has to land on "deny",
// because that is the failure a wiring mistake produces.
//
// This is the same self-review finding recorded on the kacho-vpc reference fix:
// tie fail-closed to the presence of a dependency and a configuration without it
// serves everything to everyone.

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// TestCallerAuthority_DefaultPosture_NoPrincipalNoCert_Denied — a handler built
// WITHOUT any posture setter, reached by a caller with neither a principal nor a
// verified module certificate, must be denied and must not reach the decision.
func TestCallerAuthority_DefaultPosture_NoPrincipalNoCert_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth) // no posture setter at all

	resp, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_victim",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.get",
	})

	if resp != nil {
		t.Errorf("an unauthenticated caller must learn nothing; got allowed=%v", resp.GetAllowed())
	}
	if auth.calls != 0 {
		t.Errorf("denied caller must not reach the authority checker; calls=%d", auth.calls)
	}
	requireDenied(t, err)
}

// TestCallerAuthority_DefaultPosture_ListSubjects_Denied — the enumeration RPC
// under the same default posture: who may act on a resource is not answered to a
// caller that presented nothing.
func TestCallerAuthority_DefaultPosture_ListSubjects_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)

	resp, err := h.ListSubjects(context.Background(), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.listAccessBindings",
	})

	if resp != nil {
		t.Errorf("an unauthenticated caller must learn nothing; got subjects=%v", resp.GetSubjects())
	}
	requireDenied(t, err)
}

// TestCallerAuthority_ExpandRelations_ForeignResource_Denied — ExpandRelations
// discloses a resource's whole userset tree. A tenant that does not administer
// the resource gets nothing back. (The sibling RPCs were already locked; this one
// was not, and an unlocked arm of a shared gate is an arm that can be dropped
// without a red test.)
func TestCallerAuthority_ExpandRelations_ForeignResource_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)

	resp, err := h.ExpandRelations(userCtx("usr_alice"), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Relation: "viewer",
	})

	if resp != nil {
		t.Errorf("no userset tree may be disclosed; got %v", resp.GetTree())
	}
	requireDenied(t, err)
}

// TestCallerAuthority_ExpandRelations_ResourceAdmin_Allowed — the positive arm:
// an administrator of the resource still gets the expansion, so the lock above
// pins a denial and not a dead RPC.
func TestCallerAuthority_ExpandRelations_ResourceAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{"admin|account:acc_mine": true}}
	h := newHandlerWithAuthority(true, auth)

	if _, err := h.ExpandRelations(userCtx("usr_alice"), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_mine"},
		Relation: "viewer",
	}); err != nil {
		t.Fatalf("a resource administrator must pass the gate: %v", err)
	}
}
