// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// Status enums — currently empty.
//
// Unlike kacho-vpc (PROVISIONING/ACTIVE/AVAILABLE/FAILED/DELETING on
// NetworkInterface), the kacho-iam resources are flat: Account / Project /
// User / ServiceAccount / Group / Role / AccessBinding carry no status
// field. Create/delete are synchronous at the DB level (the worker LRO
// merely wraps the Insert/Delete inside an Operation envelope to keep
// API-style parity with YC).
//
// If a lifecycle state becomes necessary (e.g. Project in `deleting` while
// its peer-service rebindings are in-flight), declare it here as
// `type ProjectStatus string` + constants.
