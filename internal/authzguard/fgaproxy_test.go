// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fgaproxy_test.go — the FGA-proxy authz ReBAC gate + cert-SAN→SA mapping.
//
// Unit-level: the FGA-proxy gate resolves the verified mTLS client-cert SAN
// (SPIRE format spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>) to a deterministic
// ServiceAccount id, then ReBAC-checks `service_account:<sva>#fga_writer@
// iam_fgaproxy:system` via the injected RelationChecker. No DB / no live TLS:
//   - cert-identity injected via grpcsrv.WithCertIdentity;
//   - ReBAC decision injected via a fake RelationChecker.
//
// Scenarios:
//
//	valid SAN → resolved to module SA → ReBAC allow → nil.
//	SA without fga_writer relation → PermissionDenied.
//	SAN references unknown SA (no relation) → PermissionDenied (fail-closed).
//	malformed / foreign-trust-domain SAN → PermissionDenied.
//	unverified peer (verified=false) → PermissionDenied (no trust).
//	SA-cert path never consults required_acr_min (no ACR in ctx) → allow.
package authzguard_test

import (
	"context"
	"crypto/md5" //nolint:gosec // deterministic id derivation, not security
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

func sva(svc string) string {
	sum := md5.Sum([]byte("kacho-" + svc)) //nolint:gosec // deterministic id
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

// fakeChecker records the (subject,relation,object) and returns a canned allow.
// When err is non-nil it is returned verbatim (modelling a backend failure:
// FGA 5xx / network drop / ErrNotConfigured), so the gate can distinguish a
// transport-failed Check from an explicit deny (allowed==false, nil err).
type fakeChecker struct {
	allowSubjects map[string]bool
	err           error
	gotSubject    string
	gotRelation   string
	gotObject     string
}

func (f *fakeChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.gotSubject, f.gotRelation, f.gotObject = subject, relation, object
	if f.err != nil {
		return false, f.err
	}
	return f.allowSubjects[subject], nil
}

func TestRelationWriteGate_C01_B07_ValidSANResolvedAndAllowed(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

	dom, err := gate.Authorize(ctx)
	require.NoError(t, err, "vpc SA with fga_writer relation → allow")
	require.Equal(t, "vpc", dom, "Authorize returns the caller module domain for object-type binding")
	require.Equal(t, "service_account:"+sva("vpc"), chk.gotSubject, "SAN mapped to deterministic sva-id")
	require.Equal(t, "fga_writer", chk.gotRelation)
	require.Equal(t, "iam_fgaproxy:system", chk.gotObject)
}

func TestRelationWriteGate_B08_NoFGAWriterRelationDenied(t *testing.T) {
	// vpc-operator cert resolves to a known SA but ReBAC denies (no relation).
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-vpc-operator/sa/kacho-vpc-operator", true)

	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no fga_writer relation → PermissionDenied")
}

func TestRelationWriteGate_C03_MalformedOrForeignSANDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	for _, san := range []string{
		"spiffe://other-trust-domain/x",      // foreign trust domain — never extracted
		"spiffe://kacho.cloud/garbage",       // wrong path shape
		"spiffe://kacho.cloud/ns//sa/kacho-", // empty segments
		"",                                   // no identity
	} {
		ctx := grpcsrv.WithCertIdentity(context.Background(), san, true)
		_, err := gate.Authorize(ctx)
		require.Equal(t, codes.PermissionDenied, status.Code(err), "malformed SAN %q → PermissionDenied", san)
	}
}

func TestRelationWriteGate_C05_UnverifiedPeerDenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	// Verified=false (TLS peer without verified client-cert) → never trusted.
	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", false)
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "unverified peer → fail-closed")
}

func TestRelationWriteGate_C02_UnknownSADenied(t *testing.T) {
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	// Well-formed SPIRE SAN, but the resolved SA has no fga_writer relation
	// (unknown / unregistered module) → fail-closed PermissionDenied.
	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-unknown", true)
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRelationWriteGate_B09_NoACRConsulted(t *testing.T) {
	// service→service (mTLS-SA) is exempt from required_acr_min: the gate
	// decision is purely the ReBAC relation; there is no ACR floor in the SA path.
	chk := &fakeChecker{allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	// ctx carries NO acr claim of any kind — must still pass on relation alone.
	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)
	_, err := gate.Authorize(ctx)
	require.NoError(t, err, "SA exempt from ACR-floor")
}

func TestRelationWriteGate_D01_DevModeInsecureAllowed(t *testing.T) {
	// Dev-mode (production=false): insecure listener, no verified cert →
	// backward-compat allow. New RPCs must not break dev flow.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk) // dev-mode default

	ctx := context.Background() // no cert-identity ever set (insecure listener)
	dom, err := gate.Authorize(ctx)
	require.NoError(t, err, "dev-mode insecure → allow (backward-compat)")
	require.Empty(t, dom, "dev-mode (no cert) → empty domain disables object-domain binding")
}

func TestRelationWriteGate_D02_ProdModeAnonymousFailClosed(t *testing.T) {
	// Production-mode: no verified cert (anonymous) → fail-closed.
	chk := &fakeChecker{allowSubjects: map[string]bool{}}
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	ctx := context.Background()
	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "prod-mode anonymous → fail-closed")
}

// TestRelationWriteGate_I1_BackendFailureIsUnavailable — backend outage → Unavailable.
//
// A FGA-Check that fails at the transport layer (5xx / network drop /
// ErrNotConfigured) is NOT an authorization decision — it is a backend outage.
// Collapsing it to PermissionDenied would let the outbox drainer poison a
// legitimate owner-tuple intent (it would treat "denied" as a permanent
// rejection). The gate must surface codes.Unavailable (retryable, fail-closed):
// the caller retries, the intent is preserved.
func TestRelationWriteGate_I1_BackendFailureIsUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"fga 5xx / network drop", errors.New("openfga check: status 503: backend unavailable")},
		{"fga not configured", clients.ErrNotConfigured},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A well-formed, verified module cert that resolves to a known SA;
			// the relation WOULD be allowed, but the Check call fails at the
			// backend before any decision can be made.
			chk := &fakeChecker{
				allowSubjects: map[string]bool{"service_account:" + sva("vpc"): true},
				err:           tc.err,
			}
			gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

			ctx := grpcsrv.WithCertIdentity(context.Background(),
				"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

			_, err := gate.Authorize(ctx)
			require.Equal(t, codes.Unavailable, status.Code(err),
				"backend Check failure must be Unavailable (retryable), never PermissionDenied — "+
					"else the drainer poisons a legitimate intent")
			// Backend error text must NOT leak through the gate.
			require.NotContains(t, status.Convert(err).Message(), "openfga",
				"raw backend error must not leak to the caller")
		})
	}
}

// TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied — explicit deny → PermissionDenied.
//
// The other branch: a successful Check that returns allowed==false is a genuine
// authorization decision (the SA lacks fga_writer). That is PermissionDenied —
// NOT Unavailable — so the caller does not pointlessly retry a real deny.
func TestRelationWriteGate_I1_ExplicitDenyIsPermissionDenied(t *testing.T) {
	// Known SA, Check succeeds (nil err) but returns allowed==false.
	chk := &fakeChecker{allowSubjects: map[string]bool{}} // empty → allowed=false, err=nil
	gate := authzguard.NewRelationWriteGate(chk).WithProductionMode(true)

	ctx := grpcsrv.WithCertIdentity(context.Background(),
		"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", true)

	_, err := gate.Authorize(ctx)
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"explicit deny (allowed=false, nil err) must be PermissionDenied, not Unavailable")
}

// TestSANToServiceAccountID — the deterministic mapping contract.
func TestSANToServiceAccountID(t *testing.T) {
	cases := []struct {
		san  string
		want string
		ok   bool
	}{
		{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-vpc", sva("vpc"), true},
		{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-compute", sva("compute"), true},
		{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-nlb", sva("nlb"), true},
		{"spiffe://kacho.cloud/ns/kacho-vpc-operator/sa/kacho-vpc-operator", sva("vpc-operator"), true},
		{"spiffe://kacho.cloud/ns/kacho-system/sa/kacho-api-gateway", sva("api-gateway"), true},
		{"spiffe://other/ns/x/sa/kacho-vpc", "", false},
		{"garbage", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := authzguard.SANToServiceAccountID(c.san)
		require.Equal(t, c.ok, ok, "san=%q parse-ok", c.san)
		if c.ok {
			require.Equal(t, c.want, got, "san=%q → sva-id", c.san)
		}
	}
}
