// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstrap_token

// mint_truthful_ttl_test.go — the expiry reported for a minted bootstrap token
// must be the expiry the token actually has.
//
// The token is signed by the issuer, and its lifetime is a property of the
// issuer's client — this service does not sign and cannot shorten a token after
// the fact. So the only number it may report is the issuer's. Reporting a smaller
// one does not make the bearer live less: it makes the holder believe a
// cluster-admin credential is already dead while it is still accepted — the one
// error that cannot be recovered from, because nobody looks for a token they
// think expired.
//
// The request no longer offers a lifetime parameter: it could not be honoured
// (see the contract test below), and a parameter that cannot be honoured must not
// be accepted.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// TestMintBootstrapToken_ReportedLifetimeIsTheIssuedOne — issuer says 900s, so
// the caller is told 900s.
func TestMintBootstrapToken_ReportedLifetimeIsTheIssuedOne(t *testing.T) {
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{}, &fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 900}}, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(900), res.ExpiresIn,
		"the reported lifetime must be the issuer's, not a shorter number this service invented")
	assert.Equal(t, int64(900), int64(res.ExpiresAt.Sub(res.IssuedAt)/time.Second),
		"expires_at - issued_at must agree with expires_in")
}

// TestMintBootstrapToken_LongerIssuedLifetimeIsReportedHonestly — if the issuer
// mints a longer-lived token than this service would like, the answer is still
// the truth. Understating it is what hides a live credential.
func TestMintBootstrapToken_LongerIssuedLifetimeIsReportedHonestly(t *testing.T) {
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{}, &fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 86400}}, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(86400), res.ExpiresIn,
		"a token that lives 24h must not be reported as expiring sooner")
}

// TestMintBootstrapToken_IssuerSilentOnLifetime_FallsBackToTheProvisionedOne —
// when the issuer states no lifetime, the honest stand-in is the lifespan this
// service provisioned its client with (not a smaller wish).
func TestMintBootstrapToken_IssuerSilentOnLifetime_FallsBackToTheProvisionedOne(t *testing.T) {
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{}, &fakeExchanger{out: ExchangeOutput{AccessToken: "tok"}}, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(MaxTTL/time.Second), res.ExpiresIn,
		"with no issuer-stated lifetime, report the lifespan the client was provisioned with")
}

// TestMintBootstrapTokenRequest_NoUnhonouredTTLField — the parameter is off the
// contract, tag and name reserved.
func TestMintBootstrapTokenRequest_NoUnhonouredTTLField(t *testing.T) {
	d := (&iamv1.MintBootstrapTokenRequest{}).ProtoReflect().Descriptor()

	assert.Nil(t, d.Fields().ByName("ttl_seconds"),
		"a requested lifetime cannot be honoured by the issuer, so it must not be accepted")

	reservedTags := map[int32]bool{}
	for i := 0; i < d.ReservedRanges().Len(); i++ {
		r := d.ReservedRanges().Get(i)
		for n := r[0]; n < r[1]; n++ {
			reservedTags[int32(n)] = true
		}
	}
	assert.True(t, reservedTags[1], "tag 1 must stay reserved (never reused)")

	reservedNames := map[string]bool{}
	for i := 0; i < d.ReservedNames().Len(); i++ {
		reservedNames[string(d.ReservedNames().Get(i))] = true
	}
	assert.True(t, reservedNames["ttl_seconds"], "the name ttl_seconds must stay reserved")

	var _ protoreflect.MessageDescriptor = d
}
