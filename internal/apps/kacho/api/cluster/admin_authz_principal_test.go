// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// admin_authz_principal_test.go — the cluster-administration gate must name the
// principal it is actually checking.
//
// The gate spelled its subject as the literal "user:" joined to the principal id.
// That is a string, not a policy, and its consequence is that a MACHINE could be
// granted cluster administration and never use it: the grant path accepts a
// service-account subject and writes the tuple under `service_account:<id>`,
// while the gate asked about `user:<id>` — which names nobody. Issued and
// unusable, by concatenation rather than by decision.
//
// Two things the concatenation did NOT decide, established by reading rather than
// assumed, and locked here so they stay true: an unknown principal type is
// already refused upstream (the id resolver returns empty for anything outside
// the known set), and the bootstrap identity never reaches this gate at all — it
// counts as anonymous here on purpose, because the legitimate bootstrap grant
// runs through the seed's own direct path, never through this use-case.
//
// Each case asserts WHO the gate named, with the checker set to deny. The
// decision is not the subject of the test, and denying keeps the use-case from
// running on past the gate into its writer — which is nil here, since every one
// of these cases is decided before any storage is touched.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	clusterapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/cluster"
)

func ctxPrincipal(typ, id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: typ, ID: id})
}

// grantSubjType / grantSubjID — the smallest well-formed arguments. Every case
// below is decided by the gate, before the arguments matter.
const grantSubjID = validUserB

var grantSubjType = iamv1.ClusterGrantSubjectType_USER

// denyingGate runs GrantAdmin with a checker that refuses, and returns the
// checker so the caller can assert which subject was named.
func denyingGate(t *testing.T, ctx context.Context) *fakeAdminChecker {
	t.Helper()
	chk := &fakeAdminChecker{allow: false}
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).WithAdminChecker(chk)

	_, err := uc.Execute(ctx, grantSubjType, grantSubjID)

	require.Error(t, err, "a refusing checker must produce a denial")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	return chk
}

// A machine principal must be named as a machine. Asking about a user id that
// belongs to no user is not a check — it is a guaranteed miss.
func TestRequireClusterAdmin_MachinePrincipal_NamedAsServiceAccount(t *testing.T) {
	chk := denyingGate(t, ctxPrincipal("service_account", "sva0000000000000000a"))

	require.True(t, chk.called, "the gate must reach the relation check")
	assert.Equal(t, "service_account:sva0000000000000000a", chk.subject,
		"a machine granted cluster administration must be checked as a machine; "+
			"user:<id> names nobody, so the grant is issued and can never be used")
	assert.Equal(t, "system_admin", chk.relation)
}

// A human principal is unchanged — the control that keeps the fix from being a
// rename of the failure rather than a fix.
func TestRequireClusterAdmin_UserPrincipal_NamedAsUser(t *testing.T) {
	chk := denyingGate(t, ctxPrincipal("user", validUserA))

	require.True(t, chk.called)
	assert.Equal(t, "user:"+validUserA, chk.subject)
}

// An unknown principal type is refused before the check, never promoted to a
// user. Already true; locked so it stays true.
func TestRequireClusterAdmin_UnknownPrincipalType_RefusedBeforeCheck(t *testing.T) {
	chk := denyingGate(t, ctxPrincipal("robot", "rbt0000000000000000a"))

	assert.False(t, chk.called,
		"an unresolvable principal must be refused before the check, not asked about as a user")
}

// The bootstrap identity does not reach this gate: it counts as anonymous here on
// purpose, because the legitimate bootstrap grant runs through the seed's own
// direct path. Locked so a future "make bootstrap work here" change is a
// deliberate one.
func TestRequireClusterAdmin_BootstrapIdentity_RefusedBeforeCheck(t *testing.T) {
	chk := denyingGate(t, ctxPrincipal("system", "bootstrap"))

	assert.False(t, chk.called,
		"the bootstrap identity is not addressable through this use-case by design")
}

// An id carrying an FGA separator must never be joined into a subject: it would
// change what the string MEANS rather than who it names. `usr#member` reads as a
// userset reference, `a:b` moves the type boundary.
func TestRequireClusterAdmin_PrincipalIDWithSeparator_RefusedBeforeCheck(t *testing.T) {
	for _, bad := range []string{"usr0000000000000000a#member", "usr:other", "usr a", "usr@x"} {
		chk := denyingGate(t, ctxPrincipal("user", bad))

		assert.False(t, chk.called,
			"id %q must never be joined into a subject string (%q would not name a user)",
			bad, "user:"+bad)
		assert.False(t, strings.Contains(chk.subject, bad))
	}
}
