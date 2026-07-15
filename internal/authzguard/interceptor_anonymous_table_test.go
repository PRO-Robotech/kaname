// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// interceptor_w1_6_test.go — read-only suffix matcher: explicit allowlist
// matcher MUST use strings.HasSuffix ONLY.
//
// Why suffix-only (no prefix-or-suffix): a method named `ListAndDelete` would
// match prefix `List` and be wrongly classified as read-only — defeating the
// anti-anon guard. The current `mutatingSuffixes` code (line 33-39 / 54-66)
// uses suffix-matching against the read-only allowlist (mutating polarity
// would invert the list but not change the matcher); suffix-only is the
// secure default.
package authzguard

import (
	"context"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// fakeHandler — passthrough; lets us verify whether interceptor short-circuited.
func fakeHandler(_ context.Context, _ any) (any, error) {
	return "ok", nil
}

func anonCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
}

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

// TestAntiAnon_ReadOnlySuffixAllowed — explicit read-only allowlist
// lets anonymous Get/List/Watch/Resolve/BatchGet/Search/Check/Whoami through.
func TestAntiAnon_ReadOnlySuffixAllowed(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	cases := []string{
		"/kacho.cloud.iam.v1.UserService/Get",
		"/kacho.cloud.iam.v1.UserService/List",
		"/kacho.cloud.iam.v1.SomeService/BatchGet",
		"/kacho.cloud.iam.v1.SomeService/Search",
		"/kacho.cloud.iam.v1.SomeService/Resolve",
		"/kacho.cloud.iam.v1.SomeService/Whoami",
	}
	for _, fm := range cases {
		t.Run(fm, func(t *testing.T) {
			_, err := iceptor(anonCtx(), nil,
				&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
			if err != nil {
				t.Fatalf("read-only method %s should be allowed for anonymous, got %v", fm, err)
			}
		})
	}
}

// TestAntiAnon_MutatingSuffixDeniedForAnon — Approve / Deny / Issue /
// Revoke / Generate / Cancel must be denied for anonymous. These were ALL
// bypassed by the old suffix-allowlist (`mutatingSuffixes`) which didn't
// enumerate them.
func TestAntiAnon_MutatingSuffixDeniedForAnon(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	cases := []string{
		"/kacho.cloud.iam.v1.SAKeyService/Issue",
		"/kacho.cloud.iam.v1.SAKeyService/Revoke",
		"/kacho.cloud.iam.v1.BreakGlassService/ApproveBreakGlassA",
		"/kacho.cloud.iam.v1.BreakGlassService/ApproveBreakGlassB",
		"/kacho.cloud.iam.v1.BreakGlassService/DenyBreakGlass",
	}
	for _, fm := range cases {
		t.Run(fm, func(t *testing.T) {
			_, err := iceptor(anonCtx(), nil,
				&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("mutating %s anonymous → expected PermissionDenied, got %v", fm, err)
			}
		})
	}
}

// TestAntiAnon_SuffixOnlyNotPrefix — matcher must be
// strings.HasSuffix ONLY. A hypothetical RPC like `ListAndDelete` would
// match prefix-`List` and be wrongly allowed. Verify the negative case:
// `*And<Mutating>` style names with a read-prefix are NOT treated as
// read-only.
func TestAntiAnon_SuffixOnlyNotPrefix(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	// Construct a synthetic FullMethod that starts with a read-only token but
	// ends with a non-read-only suffix.
	fm := "/kacho.cloud.iam.v1.SomeService/ListAndDelete"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListAndDelete must NOT be allowed via prefix-match: got %v", err)
	}
}

// TestAntiAnon_WhitelistFullMethodHonored — explicit FullMethod
// whitelist (Account.RegisterMyself / Federation Login / OIDC discovery /
// JWKS / Internal bootstrap) remains anonymously callable.
func TestAntiAnon_WhitelistFullMethodHonored(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	for fm := range whitelistFullMethod {
		_, err := iceptor(anonCtx(), nil,
			&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
		if err != nil {
			t.Fatalf("whitelisted %s should be allowed for anonymous, got %v", fm, err)
		}
	}
}

// TestAntiAnon_AuthenticatedAllowedAnywhere — authenticated user passes
// through regardless of suffix.
func TestAntiAnon_AuthenticatedAllowedAnywhere(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	cases := []string{
		"/kacho.cloud.iam.v1.SAKeyService/Issue",
		"/kacho.cloud.iam.v1.UserService/List",
		"/kacho.cloud.iam.v1.BreakGlassService/DenyBreakGlass",
	}
	for _, fm := range cases {
		t.Run(fm, func(t *testing.T) {
			_, err := iceptor(userCtx("usr_alice"), nil,
				&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
			if err != nil {
				t.Fatalf("authenticated %s should be allowed, got %v", fm, err)
			}
		})
	}
}

// TestAntiAnon_ReadOnlySuffixesList — pins down exact allowlist per
// the readonly-suffix contract. Adding/removing entries here is a security
// boundary change that needs reviewer sign-off.
func TestAntiAnon_ReadOnlySuffixesList(t *testing.T) {
	expected := []string{
		"Get", "List", "Watch", "Resolve",
		"BatchGet", "Search", "Check", "Whoami",
	}
	if len(readonlySuffixes) != len(expected) {
		t.Fatalf("readonlySuffixes length mismatch: got %d, want %d (%v)",
			len(readonlySuffixes), len(expected), expected)
	}
	got := map[string]bool{}
	for _, s := range readonlySuffixes {
		got[s] = true
	}
	for _, s := range expected {
		if !got[s] {
			t.Errorf("readonlySuffixes missing %q", s)
		}
	}
}
