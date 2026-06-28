// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// access_binding_cluster_test.go — unit tests for cluster-scope validation
// added in Item #5 (unify cluster admin into AccessBinding).
//
// Scope:
//   - AccessBinding{ResourceType: "cluster"}.Validate() requires
//     ResourceID = ClusterSingletonID (rejects any other id).
//   - The whitelist accepts "cluster" as a resource_type.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessBinding_Cluster_AcceptedInWhitelist(t *testing.T) {
	require.NoError(t, ResourceType("cluster").Validate(),
		"cluster MUST be accepted as a valid resource_type after Item #5")
}

func TestAccessBinding_Cluster_SingletonAccepted(t *testing.T) {
	b := AccessBinding{
		SubjectType:  SubjectTypeUser,
		SubjectID:    "usr_test0000000000001",
		RoleID:       "rol_test0000000000001",
		ResourceType: "cluster",
		ResourceID:   ClusterSingletonID,
	}
	require.NoError(t, b.Validate(),
		"cluster-scope binding with singleton id MUST pass Validate")
}

func TestAccessBinding_Cluster_NonSingletonRejected(t *testing.T) {
	b := AccessBinding{
		SubjectType:  SubjectTypeUser,
		SubjectID:    "usr_test0000000000001",
		RoleID:       "rol_test0000000000001",
		ResourceType: "cluster",
		ResourceID:   "some-other-cluster-id",
	}
	err := b.Validate()
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "cluster") &&
			strings.Contains(err.Error(), ClusterSingletonID),
		"error must mention expected singleton id; got %q", err.Error())
}

func TestAccessBinding_Account_AcceptsAnyResourceID(t *testing.T) {
	// Regression: the singleton restriction is cluster-scope ONLY; account
	// must still accept arbitrary ids.
	b := AccessBinding{
		SubjectType:  SubjectTypeUser,
		SubjectID:    "usr_test0000000000001",
		RoleID:       "rol_test0000000000001",
		ResourceType: "account",
		ResourceID:   "acc_arbitrary_id_000",
	}
	require.NoError(t, b.Validate())
}
