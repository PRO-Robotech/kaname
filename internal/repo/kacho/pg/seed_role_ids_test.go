// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// seed_role_ids_test.go
//
// After migration 0008_role_catalog_kac122.sql the legacy
// `rol00000000000000iamvw` / `iamad` seeds were dropped and replaced with
// deterministic md5-based IDs (`rol' || substr(md5('<role.name>'), 1, 17)`).
// Integration tests that need *any* valid system role for a binding now
// reference these helpers rather than the legacy literals so the seed
// catalog can evolve without breaking the suite.
//
// Values computed once (md5 is deterministic):
// iam.role.view -> rolee27bb5ba1efb68cb
// iam.role.admin -> role6859cc35f67d659e
//
// (Verify with: `echo -n iam.role.view | md5sum | head -c17`.)

const (
	seedSystemRoleIDIAMView  = "rolee27bb5ba1efb68cb"
	seedSystemRoleIDIAMAdmin = "role6859cc35f67d659e"
)
