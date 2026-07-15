// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authzguard_test.go — table-driven unit tests for the anti-hijacking guard
// RequireOwnerMatchesPrincipal (see authzguard.go).
//
// This guard is the SINGLE cross-owner privilege-escalation choke point wired
// into all 13 account-owner-scoped mutation use-cases:
//
//	account.Create           group.AddMember      user.Update
//	account.Delete           group.RemoveMember   user.Delete
//	group.Update             role.Update          service_account.Update
//	group.Delete             role.Delete          service_account.Delete
//	project.Delete
//
// Each call-site passes the TARGET account's owner_user_id and denies when it
// does not equal the authenticated principal — otherwise a caller could mutate
// (or delete) resources under an account owned by a DIFFERENT user. The
// mismatch→deny branch (authzguard.go: `if p.ID != ownerUserID`) and the
// empty-identity branch are the security-critical arms; these tests exercise
// them directly with InvalidArgument (a request-body validation failure, NOT
// PermissionDenied) and the stable canonical message.
package authzguard

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

const ownerMismatchMsg = "owner_user_id must match the authenticated principal"

func TestRequireOwnerMatchesPrincipal(t *testing.T) {
	tests := []struct {
		name string
		// principal is placed on ctx via WithPrincipal unless emptyCtx is set.
		principal operations.Principal
		emptyCtx  bool
		ownerID   string
		wantDeny  bool
	}{
		// ── allow: principal IS the account owner ──────────────────────────
		{
			name:      "user owns the account",
			principal: operations.Principal{Type: "user", ID: "usr_alice"},
			ownerID:   "usr_alice",
			wantDeny:  false,
		},
		{
			name:      "service-account owns the account",
			principal: operations.Principal{Type: "service_account", ID: "sva_bot"},
			ownerID:   "sva_bot",
			wantDeny:  false,
		},

		// ── deny: cross-owner mismatch (the escalation branch) ─────────────
		{
			name:      "user targets another user's account",
			principal: operations.Principal{Type: "user", ID: "usr_alice"},
			ownerID:   "usr_bob",
			wantDeny:  true,
		},
		{
			name:      "service-account targets a user-owned account",
			principal: operations.Principal{Type: "service_account", ID: "sva_bot"},
			ownerID:   "usr_alice",
			wantDeny:  true,
		},
		{
			name:      "owner is a strict superstring of principal (no prefix match)",
			principal: operations.Principal{Type: "user", ID: "usr_alice"},
			ownerID:   "usr_alice2",
			wantDeny:  true,
		},
		{
			name:      "principal is a strict superstring of owner (no prefix match)",
			principal: operations.Principal{Type: "user", ID: "usr_alice2"},
			ownerID:   "usr_alice",
			wantDeny:  true,
		},

		// ── deny: anonymous / fallback identities cannot hijack ────────────
		{
			// api-gateway injectAnonymous → {Type:system, ID:anonymous}.
			name:      "api-gateway anonymous injection vs real owner",
			principal: operations.Principal{Type: "system", ID: "anonymous"},
			ownerID:   "usr_alice",
			wantDeny:  true,
		},
		{
			// bare ctx → PrincipalFromContext returns SystemPrincipal
			// {Type:system, ID:bootstrap}; a forwarded fallback must not claim
			// a real owner (internal callers bypass via the internal listener).
			name:     "empty ctx (bootstrap fallback) vs real owner",
			emptyCtx: true,
			ownerID:  "usr_alice",
			wantDeny: true,
		},

		// ── deny: empty identity / empty owner (fail-closed) ───────────────
		{
			name:      "empty principal id vs real owner",
			principal: operations.Principal{Type: "user", ID: ""},
			ownerID:   "usr_alice",
			wantDeny:  true,
		},
		{
			name:      "real principal vs empty owner",
			principal: operations.Principal{Type: "user", ID: "usr_alice"},
			ownerID:   "",
			wantDeny:  true,
		},
		{
			name:      "empty principal and empty owner",
			principal: operations.Principal{Type: "user", ID: ""},
			ownerID:   "",
			wantDeny:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if !tt.emptyCtx {
				ctx = operations.WithPrincipal(ctx, tt.principal)
			}

			err := RequireOwnerMatchesPrincipal(ctx, tt.ownerID)

			if !tt.wantDeny {
				if err != nil {
					t.Fatalf("owner==principal must be allowed, got %v", err)
				}
				return
			}

			// Deny branch: must be a well-formed InvalidArgument gRPC error
			// (NOT PermissionDenied) with the stable canonical message.
			if err == nil {
				t.Fatalf("cross-owner/empty identity must be denied, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("deny must be a gRPC status error, got %v", err)
			}
			if st.Code() != codes.InvalidArgument {
				t.Errorf("deny code = %s, want InvalidArgument", st.Code())
			}
			if st.Message() != ownerMismatchMsg {
				t.Errorf("deny message = %q, want %q", st.Message(), ownerMismatchMsg)
			}
		})
	}
}
