// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster_test

// admin_authz_test.go — defense-in-depth ReBAC + authenticated-principal gate
// for InternalClusterService.GrantAdmin / RevokeAdmin (P1 security).
//
// These are use-case-level unit tests (no Postgres): they drive Execute with a
// mock RelationChecker + an injected principal and assert the in-iam authZ
// decision BEFORE any DB mutation. They do NOT replace the existing
// handler_integration_test.go (which exercises the SQL CAS path with an
// allowing checker).
//
// Invariant under test (security.md "AuthN+AuthZ ВЕЗДЕ"): the highest-blast
// internal admin RPCs must perform their OWN per-RPC ReBAC system_admin Check —
// they may not rely solely on the gateway caller-policy. Fail-closed: empty
// principal / nil checker / checker error / not-allowed → PermissionDenied.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/cluster"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeAdminChecker — in-memory authzguard.RelationChecker. Records the last
// Check args and returns a configured decision/error.
type fakeAdminChecker struct {
	allow bool
	err   error

	called   bool
	subject  string
	relation string
	object   string
}

func (f *fakeAdminChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.called = true
	f.subject = subject
	f.relation = relation
	f.object = object
	return f.allow, f.err
}

// The use-cases are constructed with nil writer/txb on the deny path — the
// authZ gate runs FIRST (before any DB access), so a nil writer is never
// dereferenced. A regression that bypasses the gate would nil-panic here,
// which the test would surface as a failure.

const (
	validUserA = "usr0000000000000000a"
	validUserB = "usr0000000000000000b"
)

func ctxUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

// ── GrantAdmin authZ ──────────────────────────────────────────────────────────

func TestGrantAdmin_DeniesWhenPrincipalEmpty(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).WithAdminChecker(chk)

	// Anonymous / empty ctx → no principal. MUST deny without coercing to
	// 'bootstrap' (the old code silently accepted anonymous as bootstrap).
	_, err := uc.Execute(context.Background(), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"empty principal must be PermissionDenied (no anonymous→bootstrap coercion)")
}

func TestGrantAdmin_DeniesWhenNoSystemAdmin(t *testing.T) {
	chk := &fakeAdminChecker{allow: false}
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"caller lacking system_admin must be denied")
	require.True(t, chk.called, "ReBAC Check must be consulted")
	require.Equal(t, "user:"+validUserA, chk.subject)
	require.Equal(t, "system_admin", chk.relation)
	require.Equal(t, "cluster:"+domain.ClusterSingletonID, chk.object)
}

func TestGrantAdmin_DeniesWhenCheckerErrors(t *testing.T) {
	chk := &fakeAdminChecker{err: errors.New("fga backend down")}
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"checker error must fail closed (PermissionDenied), never allow")
}

func TestGrantAdmin_DeniesWhenCheckerNil(t *testing.T) {
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil) // no checker wired
	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"nil checker must fail closed (never silently allow an unwired gate)")
}

// ── RevokeAdmin authZ ─────────────────────────────────────────────────────────

func TestRevokeAdmin_DeniesWhenPrincipalEmpty(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	uc := clusterapp.NewRevokeAdminUseCase(nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(context.Background(), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"empty principal must be PermissionDenied (no anonymous→bootstrap coercion)")
}

func TestRevokeAdmin_DeniesWhenNoSystemAdmin(t *testing.T) {
	chk := &fakeAdminChecker{allow: false}
	uc := clusterapp.NewRevokeAdminUseCase(nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.True(t, chk.called, "ReBAC Check must be consulted")
	require.Equal(t, "system_admin", chk.relation)
	require.Equal(t, "cluster:"+domain.ClusterSingletonID, chk.object)
}

func TestRevokeAdmin_DeniesWhenCheckerErrors(t *testing.T) {
	chk := &fakeAdminChecker{err: errors.New("fga backend down")}
	uc := clusterapp.NewRevokeAdminUseCase(nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"checker error must fail closed")
}

func TestRevokeAdmin_DeniesWhenCheckerNil(t *testing.T) {
	uc := clusterapp.NewRevokeAdminUseCase(nil, nil, nil, nil) // no checker wired
	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"nil checker must fail closed")
}
