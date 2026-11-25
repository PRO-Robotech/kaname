// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// principal_test.go — principal-helper unit tests.
package authzguard

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPrincipalUserID_User(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})
	if got := PrincipalUserID(ctx); got != "usr_alice" {
		t.Errorf("user: want usr_alice, got %q", got)
	}
}

func TestPrincipalUserID_ServiceAccount(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva_bot"})
	if got := PrincipalUserID(ctx); got != "sva_bot" {
		t.Errorf("sa: want sva_bot, got %q", got)
	}
}

func TestPrincipalUserID_Anonymous(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
	if got := PrincipalUserID(ctx); got != "" {
		t.Errorf("anonymous: want empty, got %q", got)
	}
}

func TestPrincipalUserID_EmptyCtx(t *testing.T) {
	if got := PrincipalUserID(context.Background()); got != "" {
		t.Errorf("empty ctx: want empty, got %q", got)
	}
}

func TestPrincipalUserID_Bootstrap(t *testing.T) {
	// system+bootstrap is treated as anonymous per IsAnonymous;
	// PrincipalUserID returns "" so handlers reject it as identity-less.
	// (Bootstrap legitimacy comes from server-internal call paths,
	// not from this helper.)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "bootstrap"})
	if got := PrincipalUserID(ctx); got != "" {
		t.Errorf("bootstrap-via-IsAnonymous: want empty, got %q", got)
	}
}

// #10: SubjectFromPrincipal is the single FGA-subject builder consolidating the
// previously-inline `subjType:="user"; if SA {…}; subject:=t+":"+id` copies. It is
// fail-closed: unknown / empty principal types yield ("", false) (the inline copies
// over-granted by defaulting unknown→"user").
func TestSubjectFromPrincipal(t *testing.T) {
	tests := []struct {
		name     string
		p        operations.Principal
		wantSubj string
		wantOK   bool
	}{
		{"user", operations.Principal{Type: "user", ID: "usr_a"}, "user:usr_a", true},
		{"service_account", operations.Principal{Type: "service_account", ID: "sva_b"}, "service_account:sva_b", true},
		{"unknown type fail-closed", operations.Principal{Type: "system", ID: "bootstrap"}, "", false},
		{"empty id fail-closed", operations.Principal{Type: "user", ID: ""}, "", false},
		{"empty principal fail-closed", operations.Principal{}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subj, ok := SubjectFromPrincipal(tt.p)
			if subj != tt.wantSubj || ok != tt.wantOK {
				t.Errorf("SubjectFromPrincipal(%+v) = (%q,%v), want (%q,%v)",
					tt.p, subj, ok, tt.wantSubj, tt.wantOK)
			}
		})
	}
}

// PrincipalSubject is the ctx variant: anonymous / empty ctx fail closed.
func TestPrincipalSubject_Ctx(t *testing.T) {
	userCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})
	if subj, ok := PrincipalSubject(userCtx); subj != "user:usr_alice" || !ok {
		t.Errorf("user ctx: got (%q,%v), want (user:usr_alice,true)", subj, ok)
	}
	saCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva_bot"})
	if subj, ok := PrincipalSubject(saCtx); subj != "service_account:sva_bot" || !ok {
		t.Errorf("sa ctx: got (%q,%v), want (service_account:sva_bot,true)", subj, ok)
	}
	anonCtx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
	if subj, ok := PrincipalSubject(anonCtx); subj != "" || ok {
		t.Errorf("anonymous ctx: got (%q,%v), want ('',false)", subj, ok)
	}
	if subj, ok := PrincipalSubject(context.Background()); subj != "" || ok {
		t.Errorf("empty ctx: got (%q,%v), want ('',false)", subj, ok)
	}
}

func TestPublicPrincipalAssuranceSelectsVerifiedOrigin(t *testing.T) {
	user := operations.Principal{Type: "user", ID: "usr_alice"}
	bot := operations.Principal{Type: "service_account", ID: "sva_worker"}
	base := operations.WithPrincipal(t.Context(), user)
	trusted := grpcsrv.WithTrustedPrincipal(base, user, true)
	forwarded := grpcsrv.WithTrustedACR(trusted, "1", true)
	presented := callerorigin.With(base, callerorigin.PresentedCredential)
	presentedBot := callerorigin.With(operations.WithPrincipal(t.Context(), bot), callerorigin.PresentedCredential)
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want operations.Principal
	}{
		{name: "forwarded", ctx: forwarded, want: user},
		{name: "presented", ctx: callerorigin.WithAssurance(presented, "1"), want: user},
		{name: "verified service account", ctx: presentedBot, want: bot},
		{name: "principal alone", ctx: base},
		{name: "unbound forwarded identity", ctx: grpcsrv.WithTrustedPrincipal(t.Context(), user, true)},
		{name: "mismatched forwarded identity", ctx: operations.WithPrincipal(forwarded, bot)},
		{name: "forwarded level unavailable", ctx: trusted},
		{name: "presented level unavailable", ctx: presented},
		{name: "presented level without verification", ctx: callerorigin.WithAssurance(base, "1")},
		{name: "presented level cannot borrow forwarded assurance", ctx: callerorigin.With(forwarded, callerorigin.PresentedCredential)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := RequirePublicPrincipalACR(tc.ctx, "1")
			if tc.want.ID == "" {
				require.Equal(t, codes.PermissionDenied, status.Code(err))
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, actual)
		})
	}
}
