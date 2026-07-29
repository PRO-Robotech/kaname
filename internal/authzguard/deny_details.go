// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

// deny_details.go — the machine-readable reason on a refusal iam decides itself.
//
// WHY THIS LIVES HERE AND NOT AT EACH REFUSAL SITE
// ------------------------------------------------
// Some RPCs are authorized over the DATA: their catalog row carries no
// required_relation, an empty scope extractor and the scope-filtered marker, so
// the edge runs no per-RPC check and passes the call through. That is correct —
// a method whose answer concerns many individually-owned objects has no single
// object to ask one question about. But the edge was also the only layer that
// attached the detail naming the action, and it still attaches it for the
// neighbouring rows it does check. On the data-filtered band the refusal
// therefore arrived bare: `{"code":7,"message":"permission denied","details":[]}`.
//
// A bare refusal is worse than terse. It is INDISTINGUISHABLE from a catalog
// miss — a method the catalog cannot map to any permission at all, which
// fail-closes to the same code with the same prose. A client (and a test) could
// not tell "you may not read this" from "this method is not in the catalog".
//
// The convention requires the reason to be machine-readable and forbids parsing
// the prose, so the fix belongs on the transport edge of the service, where the
// method name is known, rather than duplicated at each of the refusal sites.
// One place, and every method on the band is covered — including the ones added
// to it later.

import (
	"context"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// denyReason — the token a client keys on. Deliberately the SAME token the
	// edge stamps when IT refuses: a caller must not have to know which layer
	// said no in order to recognise a refusal.
	denyReason = "AUTHZ_DENIED"

	// denyDomain — likewise identical to the edge's, for the same reason.
	denyDomain = "kacho.cloud.iam.v1"
)

// DenyActionLookup — port: full method name (no leading slash) → the permission
// name the catalog gives that method, or "" when the catalog has no row for it
// or the row is exempt. Implemented by *seed.PermissionRegistry.
type DenyActionLookup interface {
	ActionForMethod(fqn string) string
}

// DenyDetailUnary returns an interceptor that attaches the machine-readable
// reason to a refusal that does not already carry one.
//
// What it does NOT attach, and why:
//
//   - the subject — the caller already knows who it is, and echoing it adds
//     nothing a client can act on;
//   - the resource — on a data-filtered method there is no single resource by
//     construction; naming one would be a claim the service cannot make. The
//     edge fills that field only where it resolved a scope object.
//
// A method with no catalog row gets NOTHING attached. That is the whole point:
// an absent action is how a caller recognises a catalog miss, so inventing an
// empty one would erase the distinction this exists to create.
func DenyDetailUnary(catalog DenyActionLookup) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		if err == nil {
			return resp, nil
		}
		return resp, withDenyReason(catalog, info.FullMethod, err)
	}
}

// withDenyReason enriches a PermissionDenied status; everything else is
// returned untouched (a reason token on a NotFound would mislabel the failure).
func withDenyReason(catalog DenyActionLookup, fullMethod string, err error) error {
	if catalog == nil {
		return err
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		return err
	}
	if hasErrorInfo(st) {
		// Already named — a second, possibly disagreeing, reason would be worse
		// than none. The step-up refusal builds its own details, and so may a
		// future site.
		return err
	}
	fqn := strings.TrimPrefix(fullMethod, "/")
	action := catalog.ActionForMethod(fqn)
	if action == "" {
		return err
	}
	// WithDetails APPENDS, so any detail already on the status (the step-up
	// PreconditionFailure that tells the caller what to do about the refusal)
	// survives.
	enriched, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: denyReason,
		Domain: denyDomain,
		Metadata: map[string]string{
			"action": action,
			"fqn":    fqn,
		},
	})
	if derr != nil {
		// Marshalling a fixed, tiny message cannot realistically fail; if it
		// somehow does, the refusal itself must still reach the caller intact.
		return err
	}
	return enriched.Err()
}

func hasErrorInfo(st *status.Status) bool {
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.ErrorInfo); ok {
			return true
		}
	}
	return false
}
