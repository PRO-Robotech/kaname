// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard_test

// cluster_admin_shortcircuit_test.go — RBAC explicit-model 2026 P5 (D-9 / КФ-2).
//
// IsClusterAdmin is the FLAT cluster-admin super-gate: a single relation Check
// `cluster:cluster_kacho_root # system_admin @ <subj>`. It is NOT a hierarchical
// `<rel> from cluster` cascade — exactly one tuple = one fact. The same primitive
// is reused by authorize_service.Check (public AuthZ + InternalIAMService.Check)
// AND every write-authz site (requireGrantAuthority / fgaHoldsAdmin) so a
// cluster-admin keeps access after the access-cascade is contracted (КФ-2).
//
// Fail-closed: anonymous / empty principal / nil checker / Check error → false.

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type scFakeChecker struct {
	allow       map[string]bool // subject → allowed
	err         error
	gotSubject  string
	gotRelation string
	gotObject   string
	calls       int
}

func (f *scFakeChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.calls++
	f.gotSubject, f.gotRelation, f.gotObject = subject, relation, object
	if f.err != nil {
		return false, f.err
	}
	return f.allow[subject], nil
}

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "user"})
}

func saCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "service_account"})
}

func TestIsClusterAdmin_Allowed_FlatRelation(t *testing.T) {
	chk := &scFakeChecker{allow: map[string]bool{"user:usr_root": true}}
	if !authzguard.IsClusterAdmin(userCtx("usr_root"), chk) {
		t.Fatalf("cluster-admin must short-circuit to true")
	}
	// Asserts the EXACT flat relation/object — not a `from cluster` cascade.
	if chk.gotRelation != "system_admin" {
		t.Fatalf("relation = %q, want system_admin", chk.gotRelation)
	}
	if chk.gotObject != "cluster:"+domain.ClusterSingletonID {
		t.Fatalf("object = %q, want cluster:%s", chk.gotObject, domain.ClusterSingletonID)
	}
	if chk.gotSubject != "user:usr_root" {
		t.Fatalf("subject = %q, want user:usr_root", chk.gotSubject)
	}
}

func TestIsClusterAdmin_ServiceAccountSubject(t *testing.T) {
	chk := &scFakeChecker{allow: map[string]bool{"service_account:sva_x": true}}
	if !authzguard.IsClusterAdmin(saCtx("sva_x"), chk) {
		t.Fatalf("cluster-admin SA must short-circuit to true")
	}
	if chk.gotSubject != "service_account:sva_x" {
		t.Fatalf("subject = %q, want service_account:sva_x", chk.gotSubject)
	}
}

func TestIsClusterAdmin_NonAdmin_Denied(t *testing.T) {
	chk := &scFakeChecker{allow: map[string]bool{}} // grants nothing
	if authzguard.IsClusterAdmin(userCtx("usr_other"), chk) {
		t.Fatalf("non-cluster-admin must NOT short-circuit")
	}
}

func TestIsClusterAdmin_FailClosed(t *testing.T) {
	// nil checker → false (unwired gate never silently allows).
	if authzguard.IsClusterAdmin(userCtx("usr_root"), nil) {
		t.Fatalf("nil checker must fail-closed to false")
	}
	// anonymous → false.
	if authzguard.IsClusterAdmin(context.Background(), &scFakeChecker{allow: map[string]bool{"user:": true}}) {
		t.Fatalf("anonymous must fail-closed to false")
	}
	// backend error → false (never fail-open on transport failure).
	errChk := &scFakeChecker{err: errors.New("fga down")}
	if authzguard.IsClusterAdmin(userCtx("usr_root"), errChk) {
		t.Fatalf("Check error must fail-closed to false")
	}
}
