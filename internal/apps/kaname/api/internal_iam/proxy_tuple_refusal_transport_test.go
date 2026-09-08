// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/authz/proxytuple"
)

// The proxy-write rule is transport-free so a consumer's domain layer can import it
// (architecture.md dependency rule). That moves ONE thing to this side of the wall:
// turning the refusal into what the caller actually observes. This test locks that
// observable — the gRPC CODE and the exact MESSAGE — because a security fix is
// regression-locked at the level of what is observed, not at the level of "some
// error came back" (testing.md §Regression-lock).
//
// It also locks the shape of the refusal: a single fixed text with no reason in it.
// A message that named which clause refused would answer, for a caller who is not
// allowed to write the tuple, WHY — and that is an oracle about the rule.
func TestProxyTupleRefusalMapsToPermissionDenied(t *testing.T) {
	t.Parallel()

	// A tuple the rule refuses: a privilege relation on the platform singleton.
	err := validateProxyTuple("vpc", "service_account:sva1", "system_admin", "cluster:cluster_root")
	if err == nil {
		t.Fatal("refused tuple returned nil: the rule is not being applied at this boundary")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("code = %v; want %v", got, codes.PermissionDenied)
	}
	if got := status.Convert(err).Message(); got != "permission denied" {
		t.Fatalf("message = %q; want %q (fixed text, no reason — naming the refusing "+
			"clause would tell a caller who may not write the tuple why)", got, "permission denied")
	}
	// The sentinel must NOT survive to the wire: a caller has no business learning
	// the internal error identity, and errors.Is on it would be a second contract.
	if errors.Is(err, proxytuple.ErrRefused) {
		t.Fatal("the internal sentinel leaked through the transport boundary")
	}

	// Positive control, paired with the negative above: a tuple the rule ACCEPTS must
	// produce no error at all. Without it, a mapping that refused everything — or a
	// rule that had been disconnected and always errored — would read as green.
	if err := validateProxyTuple("vpc", "project:prj1", "project", "vpc_network:net1"); err != nil {
		t.Fatalf("legitimate own-domain project tuple was refused: %v", err)
	}
}
