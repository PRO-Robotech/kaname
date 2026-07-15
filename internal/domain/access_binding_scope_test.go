// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// access_binding_scope_test.go — unit tests for Scope.ValidateAgainst +
// DeriveFromResourceType.
package domain_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestScope_String(t *testing.T) {
	cases := []struct {
		s    domain.Scope
		want string
	}{
		{domain.ScopeUnspecified, "SCOPE_UNSPECIFIED"},
		{domain.ScopeCluster, "CLUSTER"},
		{domain.ScopeAccount, "ACCOUNT"},
		{domain.ScopeProject, "PROJECT"},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, tc.s.String())
	}
}

func TestScope_ValidateAgainst_Matched(t *testing.T) {
	require.NoError(t, domain.ScopeCluster.ValidateAgainst("cluster", "cluster_kacho_root"))
	require.NoError(t, domain.ScopeAccount.ValidateAgainst("account", "acc00000000000000a001"))
	require.NoError(t, domain.ScopeProject.ValidateAgainst("project", "prj00000000000000p001"))
}

func TestScope_ValidateAgainst_Mismatched(t *testing.T) {
	cases := []struct {
		s      domain.Scope
		rt, ri string
	}{
		{domain.ScopeCluster, "project", "prj01"},
		{domain.ScopeCluster, "cluster", "wrong_root"},
		{domain.ScopeAccount, "account", "wrong-prefix"},
		{domain.ScopeAccount, "cluster", "cluster_kacho_root"},
		{domain.ScopeProject, "project", "acc00000000000000a001"},
		{domain.ScopeProject, "cluster", "cluster_kacho_root"},
		{domain.ScopeUnspecified, "account", "acc01"},
	}
	for _, tc := range cases {
		err := tc.s.ValidateAgainst(tc.rt, tc.ri)
		require.Error(t, err, "scope=%v rt=%s rid=%s expected mismatch", tc.s, tc.rt, tc.ri)
		require.True(t, errors.Is(err, domain.ErrScopeMismatch))
	}
}

func TestScope_DeriveFromResourceType(t *testing.T) {
	cases := []struct {
		rt   string
		want domain.Scope
	}{
		{"cluster", domain.ScopeCluster},
		// The B2B `organization` resource_type is fully removed; it no longer
		// maps to ScopeCluster. Like any other unknown resource_type it now
		// falls through to the ScopeProject default.
		{"organization", domain.ScopeProject},
		{"account", domain.ScopeAccount},
		{"cloud", domain.ScopeAccount},
		{"project", domain.ScopeProject},
		{"folder", domain.ScopeProject},
		{"vpc_network", domain.ScopeProject},
		{"compute_instance", domain.ScopeProject},
		{"iam_role", domain.ScopeProject},
		{"unknown", domain.ScopeProject},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, domain.DeriveFromResourceType(tc.rt),
			"resource_type=%s expected scope=%v", tc.rt, tc.want)
	}
}
