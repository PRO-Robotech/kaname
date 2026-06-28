// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cluster_admin_grant_test.go — unit tests для self-validating newtype
// `ClusterAdminGrant`.
//
// Покрывает позитивные и негативные паттерны для всех Validate()-вызовов:
//   - ClusterAdminGrant.Validate (cumulative через multierr)
//   - ClusterAdminGrantID.Validate (regex `^cag_[crockford]{17}$`)
//   - GrantSubjectType.Validate (enum user|service_account)
//
// SubjectID не имеет валидации внутри domain-package (см. ids_extended.go
// `IsValidKac127ID` generic-helper); префикс-валидация — на уровне use-case
// (handler принимает только `usr_*`).

package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── ClusterAdminGrantID ──────────────────────────────────────────────────────

func TestClusterAdminGrantID_Validate_Valid(t *testing.T) {
	good := []ClusterAdminGrantID{
		"cag_00000000000000000",
		"cag_zzzzzzzzzzzzzzzzz",
		"cag_abc12345678901234",
	}
	for _, id := range good {
		require.NoError(t, id.Validate(), "valid id %q", id)
	}
}

func TestClusterAdminGrantID_Validate_Invalid(t *testing.T) {
	bad := []ClusterAdminGrantID{
		"",                          // empty
		"cag_",                      // no body
		"cag_short",                 // too short
		"cag_toolongtoolongtoolong", // too long
		"bgg_00000000000000000",     // wrong prefix
		"CAG_00000000000000000",     // upper-case prefix
		"cag_iiiiiiiiiiiiiiiii",     // 'i' not in crockford
		"cag_lllllllllllllllll",     // 'l' not in crockford
		"cag_ooooooooooooooooo",     // 'o' not in crockford
		"cag_uuuuuuuuuuuuuuuuu",     // 'u' not in crockford
		"cag_0000000000000000-",     // dash not allowed
	}
	for _, id := range bad {
		require.Error(t, id.Validate(), "invalid id %q must fail", id)
	}
}

// ── GrantSubjectType ─────────────────────────────────────────────────────────

func TestGrantSubjectType_Validate_Valid(t *testing.T) {
	require.NoError(t, GrantSubjectTypeUser.Validate())
	require.NoError(t, GrantSubjectTypeServiceAccount.Validate())
}

func TestGrantSubjectType_Validate_Invalid(t *testing.T) {
	bad := []GrantSubjectType{
		"",
		"group",
		"User", // case-sensitive
		"USER",
		"unknown",
	}
	for _, st := range bad {
		require.Error(t, st.Validate(), "invalid subject_type %q must fail", st)
	}
}

// ── ClusterAdminGrant ────────────────────────────────────────────────────────

func TestClusterAdminGrant_Validate_HappyPath(t *testing.T) {
	g := ClusterAdminGrant{
		ID:          "cag_00000000000000000",
		ClusterID:   ClusterSingletonID,
		SubjectType: GrantSubjectTypeUser,
		SubjectID:   "usr_00000000000000000",
		GrantedBy:   "usr_s0000000000000000",
		GrantedAt:   time.Now().UTC(),
	}
	require.NoError(t, g.Validate())
}

func TestClusterAdminGrant_Validate_EmptySubjectID(t *testing.T) {
	g := ClusterAdminGrant{
		ID:          "cag_00000000000000000",
		ClusterID:   ClusterSingletonID,
		SubjectType: GrantSubjectTypeUser,
		SubjectID:   "",
		GrantedBy:   "usr_s0000000000000000",
		GrantedAt:   time.Now().UTC(),
	}
	require.Error(t, g.Validate(), "empty subject_id must fail")
}

func TestClusterAdminGrant_Validate_EmptyGrantedBy(t *testing.T) {
	g := ClusterAdminGrant{
		ID:          "cag_00000000000000000",
		ClusterID:   ClusterSingletonID,
		SubjectType: GrantSubjectTypeUser,
		SubjectID:   "usr_00000000000000000",
		GrantedBy:   "",
		GrantedAt:   time.Now().UTC(),
	}
	require.Error(t, g.Validate(), "empty granted_by must fail")
}

func TestClusterAdminGrant_Validate_BadID_BadType(t *testing.T) {
	// Cumulative multierr: bad ID + bad subject_type both reported.
	g := ClusterAdminGrant{
		ID:          "bad",
		ClusterID:   ClusterSingletonID,
		SubjectType: "group",
		SubjectID:   "usr_00000000000000000",
		GrantedBy:   "usr_s0000000000000000",
		GrantedAt:   time.Now().UTC(),
	}
	err := g.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "id")
	require.Contains(t, err.Error(), "subject_type")
}

// IsActive — non-Validate behavioural property (granted_until=nil ⇔ permanent active).

func TestClusterAdminGrant_IsActive(t *testing.T) {
	permanent := ClusterAdminGrant{GrantedUntil: nil}
	require.True(t, permanent.IsActive())

	ts := time.Now().UTC()
	revoked := ClusterAdminGrant{GrantedUntil: &ts}
	require.False(t, revoked.IsActive())
}
