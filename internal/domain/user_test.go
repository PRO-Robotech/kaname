// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"strings"
	"testing"
)

// TestUser_Validate_AccountIDRequired — User.Validate() must reject a User with
// an empty AccountID (every User belongs to exactly one Account: NOT NULL +
// FK). Previously this was a placeholder no-op (`_ = u.AccountID`).
func TestUser_Validate_AccountIDRequired(t *testing.T) {
	base := User{
		ID:           "usr_00000000000000000",
		AccountID:    "acc_00000000000000000",
		Email:        "u@example.com",
		InviteStatus: InviteStatusActive,
		ExternalID:   "kratos-sub-abc",
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("valid user must pass Validate: %v", err)
	}

	missing := base
	missing.AccountID = ""
	err := missing.Validate()
	if err == nil {
		t.Fatalf("User.Validate must reject an empty AccountID")
	}
	if !strings.Contains(err.Error(), "account_id") {
		t.Errorf("error must mention account_id, got %v", err)
	}
}
