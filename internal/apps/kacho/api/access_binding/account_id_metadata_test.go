// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// account_id_metadata_test.go — AccessBinding Create/Delete stamp account_id
// into the emitted *Metadata ONLY when the binding is on an account resource
// (ResourceType=="account" → account_id = ResourceID). project / cluster /
// cross-service bindings leave account_id empty (SQL NULL) so they do NOT
// appear in the account-scoped module list (visible per-resource + Internal).
//
// The decision point is the pure helper auditTenantAccountID, reused for both
// the audit_outbox tenant scope and the operation metadata account_id stamp.
// End-to-end propagation (emitted metadata → operations.account_id) is proven
// in the corelib-denormalization integration test.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestAuditTenantAccountID_AccountScope_ReturnsResourceID(t *testing.T) {
	b := domain.AccessBinding{ResourceType: "account", ResourceID: "acc0000000000000abcd"}
	assert.Equal(t, "acc0000000000000abcd", auditTenantAccountID(b),
		"account-scoped binding → account_id = ResourceID (D-9)")
}

func TestAuditTenantAccountID_ProjectScope_Empty(t *testing.T) {
	b := domain.AccessBinding{ResourceType: "project", ResourceID: "prj0000000000000yyyy"}
	assert.Empty(t, auditTenantAccountID(b),
		"project-scoped binding → account_id empty (narrow-scope, NULL → not in account list)")
}

func TestAuditTenantAccountID_ClusterScope_Empty(t *testing.T) {
	b := domain.AccessBinding{ResourceType: "cluster", ResourceID: domain.ClusterSingletonID}
	assert.Empty(t, auditTenantAccountID(b),
		"cluster-scoped binding → account_id empty (narrow-scope)")
}
