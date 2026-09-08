// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// force_logout_machine_admin_test.go — the cluster administrator is named to the
// store by the TYPE it actually has.
//
// Why this file exists separately from force_logout_authz_test.go. Every probe in
// that file builds its caller with `ctxAdmin`, which is always a `user`, and its
// checker answers a flat bool regardless of who is asked. Both halves matter: the
// suite could not observe the subject, and never presented a non-interactive one.
// So the gate could ask about a subject that cannot exist and the whole file stayed
// green — the checks were real, they were simply blind to this axis.
//
// The axis is load-bearing rather than theoretical: `cluster system_admin` is seeded
// (migration 0058) to a bootstrap SERVICE ACCOUNT, so on any production-posture
// stand the cluster administrator IS a machine principal. A gate that can only name
// users refuses it by construction, however it was granted, and the refusal is
// indistinguishable from a correct one because the store answers a well-formed "no"
// about the subject it was handed.
//
// A `system` principal (`operations.SystemPrincipal()` = system/bootstrap) is
// refused here and that is deliberate: there is no `system:` subject type in the
// model, so it was never grantable. Previously it was spelled `user:bootstrap` and
// denied by the store; now it is denied without inventing a subject first. The
// outcome is unchanged — this file locks it so the equivalence stays visible.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// subjectKeyedChecker grants `system_admin` to exactly one subject string, so the
// answer depends on WHO is asked. A checker returning a flat bool cannot fail on a
// misnamed subject, which is precisely how this class hides.
type subjectKeyedChecker struct {
	grantedTo string
	asked     []string
}

func (c *subjectKeyedChecker) Check(_ context.Context, subject, _, _ string) (bool, error) {
	c.asked = append(c.asked, subject)
	return subject == c.grantedTo, nil
}

func ctxPrincipal(typ, id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: typ, ID: id})
}

// A SERVICE ACCOUNT holding cluster system_admin must be able to force a logout.
func TestForceLogout_ServiceAccountAdminIsAskedAsServiceAccount(t *testing.T) {
	const saID = "sva6rxe7xcemam63vwcv"

	chk := &subjectKeyedChecker{grantedTo: "service_account:" + saID}
	rec := &fakeForceLogoutRecorder{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(chk).
		WithOperations(&recordingForceLogoutOps{})

	_, err := h.ForceLogout(ctxPrincipal("service_account", saID), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.NoError(t, err,
		"a service account holding cluster system_admin was refused; subjects asked: %v\n"+
			"the store was asked about a subject that cannot exist, so its 'no' is not a "+
			"statement about this caller's grants", chk.asked)
	require.Equal(t, 1, rec.allCnt, "the revocation must be written for an authorized machine admin")
	require.Equal(t, []string{"service_account:" + saID}, chk.asked,
		"a service-account principal must be named service_account:<id>; "+
			"spelling it user:<id> asks the store about somebody else")
}

// Control in the other direction: the human path must keep working unchanged. A fix
// that merely moved the defect from one principal type to the other would pass the
// probe above on its own.
func TestForceLogout_UserAdminIsAskedAsUser(t *testing.T) {
	const usrID = "usr7cst95wa4q3myxey4"

	chk := &subjectKeyedChecker{grantedTo: "user:" + usrID}
	rec := &fakeForceLogoutRecorder{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(chk).
		WithOperations(&recordingForceLogoutOps{})

	_, err := h.ForceLogout(ctxPrincipal("user", usrID), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.NoError(t, err, "a user holding cluster system_admin was refused; asked: %v", chk.asked)
	require.Equal(t, 1, rec.allCnt)
	require.Equal(t, []string{"user:" + usrID}, chk.asked)
	require.Equal(t, domain.UserID(usrID), rec.allBy,
		"the audit actor stays the verified principal")
}

// A principal whose type the model cannot name is refused WITHOUT consulting the
// store. Deciding on an invented subject would answer from somebody else's grants.
func TestForceLogout_UnnameablePrincipalIsRefusedWithoutAsking(t *testing.T) {
	chk := &subjectKeyedChecker{grantedTo: "user:whatever"}
	rec := &fakeForceLogoutRecorder{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(chk).
		WithOperations(&recordingForceLogoutOps{})

	_, err := h.ForceLogout(ctxPrincipal("banana", "whatever"), &iamv1.ForceLogoutRequest{
		UserId: "usr0000000000000victm",
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a principal with an unresolvable type must be refused")
	require.Empty(t, chk.asked, "the store must not be consulted for a subject we invented")
	require.Zero(t, rec.allCnt, "no revocation may be written on deny")
}
