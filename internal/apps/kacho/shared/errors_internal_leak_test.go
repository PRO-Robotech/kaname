// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared_test

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// TestMapRepoErr_Internal_NoLeak — hardening-invariant #1: a wrapped ErrInternal
// must surface a FIXED opaque gRPC message ("internal error"), NEVER the wrapped
// detail. Concrete payload comes from cluster_admin_grant_writer's Revoke, which
// wraps ErrInternal with the target subject id, caller principal id and internal
// row-count — none of that may reach the client.
//
// Regression-lock is at the OBSERVABLE level (message, not only code): a refactor
// that re-echoes the wrapped text must keep this red.
func TestMapRepoErr_Internal_NoLeak(t *testing.T) {
	const (
		subject   = "usr_targetvictim0001"
		principal = "usr_caller00000002"
		total     = 3
	)
	err := iamerr.Wrapf(iamerr.ErrInternal,
		"cluster_admin_grants Revoke: 0 rows (subject=%s, principal=%s, total=%d)",
		subject, principal, total)

	mapped := shared.MapRepoErr(err)

	if got := status.Code(mapped); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
	msg := status.Convert(mapped).Message()
	if msg != "internal error" {
		t.Fatalf("message = %q, want fixed opaque %q", msg, "internal error")
	}
	for _, leak := range []string{subject, principal, "row", "cluster_admin_grants"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("gRPC INTERNAL message leaks %q: %q", leak, msg)
		}
	}
}
