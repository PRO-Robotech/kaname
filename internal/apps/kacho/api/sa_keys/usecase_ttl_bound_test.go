// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_ttl_bound_test.go — the lifetime half of "machine principals are
// exempt from step-up, therefore protected differently".
//
// A service-account key IS the machine's long-lived credential. Exempting the
// machine from interactive re-authentication stays defensible only while the
// credential itself is bounded in time. Three gaps locked here:
//
//  1. `ttl_seconds` had a floor (>= 0) but NO ceiling.
//  2. `ttl_seconds == 0` persisted a NULL `expires_at` — a key that never
//     expires — so the most convenient call shape produced the least safe
//     credential.
//  3. The Hydra OAuth2 client registered for the key carried no
//     `access_token_lifespan`, so every token minted from it inherited the
//     provider-global default.
//
// Assertions are on the OBSERVABLE contract: the gRPC code for an over-long
// TTL, the persisted `expires_at`, and the lifespan actually handed to the
// client registration.
package sa_keys

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ttlHarness — the shared stub set with a pinned clock, so an expiry assertion
// compares against a known instant rather than racing wall-clock.
type ttlHarness struct {
	uc    *IssueSAKeyUseCase
	repo  *stubSAClientRepo
	hydra *stubHydra
	ops   *stubOpsRepo
	trust *fakeTrustedIssuers
	now   time.Time
}

func newTTLHarness(t *testing.T) *ttlHarness {
	t.Helper()
	h := &ttlHarness{
		repo:  &stubSAClientRepo{},
		hydra: &stubHydra{},
		ops:   &stubOpsRepo{},
		trust: &fakeTrustedIssuers{},
		now:   time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
	}
	h.uc = NewIssueSAKeyUseCase(h.repo, &stubTx{}, h.hydra, h.ops).WithTrustedIssuerWriter(h.trust)
	h.uc.now = func() time.Time { return h.now }
	return h
}

func (h *ttlHarness) issue(t *testing.T, in IssueInput) error {
	t.Helper()
	in.ServiceAccountID = "sva_test000000000000"
	in.CreatedByUserID = "usr_admin00000000000"
	_, err := h.uc.Execute(context.Background(), in)
	return err
}

// ── ceiling ──────────────────────────────────────────────────────────────────

// TestIssue_TTLAboveMax_Rejected — a TTL beyond the configured ceiling is
// refused up-front, not silently honoured. Without a ceiling any caller could
// mint a decade-long machine credential.
func TestIssue_TTLAboveMax_Rejected(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.MaxTTL = 90 * 24 * time.Hour

	err := h.issue(t, IssueInput{TTLSeconds: int64((365 * 24 * time.Hour).Seconds())})

	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v (err=%v); want InvalidArgument for a ttl beyond the ceiling",
			status.Code(err), err)
	}
	if msg := status.Convert(err).Message(); msg == "" || !contains(msg, "ttl_seconds") {
		t.Errorf("message = %q; must name the offending field", msg)
	}
	if h.hydra.created {
		t.Error("a rejected TTL must not reach Hydra — no client is registered for a refused key")
	}
	if h.repo.insertOK {
		t.Error("a rejected TTL must not persist a key row")
	}
}

// TestIssue_TTLAtMax_Accepted — the ceiling is inclusive (BVA): a caller may
// request exactly the maximum.
func TestIssue_TTLAtMax_Accepted(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.MaxTTL = 90 * 24 * time.Hour

	if err := h.issue(t, IssueInput{TTLSeconds: int64((90 * 24 * time.Hour).Seconds())}); err != nil {
		t.Fatalf("ttl exactly at the ceiling must be accepted: %v", err)
	}
	waitForOp(t, h.ops)
	if !h.repo.insertOK {
		t.Fatal("the key must be persisted")
	}
	if h.repo.inserted.ExpiresAt == nil {
		t.Fatal("expires_at must be set")
	}
	if got, want := *h.repo.inserted.ExpiresAt, h.now.Add(90*24*time.Hour); !got.Equal(want) {
		t.Errorf("expires_at = %v; want %v", got, want)
	}
}

// TestIssue_NegativeTTL_StillRejected — regression on the one bound that
// already existed.
func TestIssue_NegativeTTL_StillRejected(t *testing.T) {
	h := newTTLHarness(t)
	if code := status.Code(h.issue(t, IssueInput{TTLSeconds: -1})); code != codes.InvalidArgument {
		t.Fatalf("code = %v; want InvalidArgument", code)
	}
}

// TestIssue_MaxTTLUnset_LeavesCeilingOpen — an unconfigured ceiling must not
// fabricate one. Enforcement is opt-in via config; the composition root sets
// it. (Locks the degraded path so it is a deliberate contract, not an accident.)
func TestIssue_MaxTTLUnset_LeavesCeilingOpen(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.MaxTTL = 0

	if err := h.issue(t, IssueInput{TTLSeconds: int64((365 * 24 * time.Hour).Seconds())}); err != nil {
		t.Fatalf("with no ceiling configured the request must pass: %v", err)
	}
}

// ── default: bounded, not "never" ────────────────────────────────────────────

// TestIssue_TTLOmitted_GetsBoundedDefault — omitting ttl_seconds must yield a
// key that EXPIRES.
func TestIssue_TTLOmitted_GetsBoundedDefault(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.DefaultTTL = 90 * 24 * time.Hour
	h.uc.MaxTTL = 365 * 24 * time.Hour

	if err := h.issue(t, IssueInput{}); err != nil { // TTLSeconds omitted → 0
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if h.repo.inserted.ExpiresAt == nil {
		t.Fatal("a key issued without an explicit ttl_seconds must still expire — " +
			"'0 means never' makes the default call the unbounded one")
	}
	if got, want := *h.repo.inserted.ExpiresAt, h.now.Add(90*24*time.Hour); !got.Equal(want) {
		t.Errorf("expires_at = %v; want the configured DefaultTTL %v", got, want)
	}
}

// TestIssue_DefaultTTLUnset_KeepsNonExpiring — with no default configured the
// legacy "no expiry" behaviour is preserved, so wiring the knob is what
// changes behaviour (nothing changes under an un-migrated deployment).
func TestIssue_DefaultTTLUnset_KeepsNonExpiring(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.DefaultTTL = 0

	if err := h.issue(t, IssueInput{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)
	if h.repo.inserted.ExpiresAt != nil {
		t.Errorf("expires_at = %v; want nil when no default is configured",
			*h.repo.inserted.ExpiresAt)
	}
}

// TestIssue_ExplicitTTL_Honoured — a deliberate shorter request wins over the
// default.
func TestIssue_ExplicitTTL_Honoured(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.DefaultTTL = 90 * 24 * time.Hour
	h.uc.MaxTTL = 365 * 24 * time.Hour

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)
	if h.repo.inserted.ExpiresAt == nil {
		t.Fatal("expires_at must be set")
	}
	if got, want := *h.repo.inserted.ExpiresAt, h.now.Add(time.Hour); !got.Equal(want) {
		t.Errorf("expires_at = %v; want %v", got, want)
	}
}

// ── issued-token lifetime ────────────────────────────────────────────────────

// TestIssue_RegistersClientWithAccessTokenLifespan — the OAuth2 client created
// for the key must carry its OWN access-token lifetime, rather than inheriting
// whatever the identity provider happens to default to.
func TestIssue_RegistersClientWithAccessTokenLifespan(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.AccessTokenLifespan = 15 * time.Minute

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if !h.hydra.created {
		t.Fatal("the OAuth2 client must be registered")
	}
	if got, want := h.hydra.gotReq.AccessTokenLifespan, (15 * time.Minute).String(); got != want {
		t.Errorf("access_token_lifespan = %q; want %q — the registered client must pin its own lifespan", got, want)
	}
}

// TestIssue_Federated_RegistersClientWithAccessTokenLifespan — the federated
// (external-IdP) path mints tokens from its own client too; it must pin the
// same lifespan. Omitting it there would leave the federation path unbounded
// while the private_key_jwt path is bounded.
func TestIssue_Federated_RegistersClientWithAccessTokenLifespan(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.AccessTokenLifespan = 15 * time.Minute

	err := h.issue(t, IssueInput{
		TrustedSubjects: []domain.TrustedSubject{{
			Issuer:         "https://kube.cluster.local",
			SubjectPattern: "^system:serviceaccount:ci:deployer$",
			PublicKeyPEM:   testIssuerPublicKeyPEM,
			KeyAlgorithm:   "ES256",
		}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if got, want := h.hydra.gotReq.AccessTokenLifespan, (15 * time.Minute).String(); got != want {
		t.Errorf("federated access_token_lifespan = %q; want %q", got, want)
	}
}

// TestIssue_AccessTokenLifespanUnset_LeavesFieldEmpty — an unconfigured
// lifespan must not fabricate a value; the field stays empty and the provider
// default applies (explicit degradation, not a silent guess).
func TestIssue_AccessTokenLifespanUnset_LeavesFieldEmpty(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.AccessTokenLifespan = 0

	if err := h.issue(t, IssueInput{TTLSeconds: 3600}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if got := h.hydra.gotReq.AccessTokenLifespan; got != "" {
		t.Errorf("access_token_lifespan = %q; want empty when unconfigured", got)
	}
}

// ── срок доверия издателю ────────────────────────────────────────────────────

// TestIssue_Federated_TrustBoundedByDefault — доверие издателю ограничено
// умолчанием, а не десятилетием.
//
// Свойство осталось прежним, измеряется оно теперь по НАШЕЙ таблице (#1124): до
// перевода перечня срок ставился гранту у поставщика и при опущенном TTL
// откатывался к ДЕСЯТИ ГОДАМ — причём достигалось это ФОРМОЙ ВЫЗОВА ПО
// УМОЛЧАНИЮ. Величина пережила бы любую политику смены ключей.
func TestIssue_Federated_TrustBoundedByDefault(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.DefaultTTL = 90 * 24 * time.Hour
	h.uc.MaxTTL = 365 * 24 * time.Hour

	err := h.issue(t, IssueInput{
		TrustedSubjects: []domain.TrustedSubject{{
			Issuer:         "https://kube.cluster.local",
			SubjectPattern: "^system:serviceaccount:ci:deployer$",
			PublicKeyPEM:   testIssuerPublicKeyPEM,
			KeyAlgorithm:   "ES256",
		}},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if len(h.trust.calls) != 1 {
		t.Fatalf("записей перечня = %d; ожидалась 1", len(h.trust.calls))
	}
	got := h.trust.calls[0].expiresAt
	if got == nil {
		t.Fatal("срок доверия не назван: бессрочное доверие постороннему издателю " +
			"переживает любую политику смены ключей")
	}
	if want := h.now.Add(90 * 24 * time.Hour); !got.Equal(want) {
		t.Errorf("срок доверия = %v; ожидалось ограниченное умолчание %v "+
			"(опущенный TTL не покупает десятилетия доверия)", got, want)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
