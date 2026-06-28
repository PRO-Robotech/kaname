// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"testing"
	"time"
)

// TestUserTokenRevocation_Validate — self-validating domain entity.
// The user-level "revoke-all-before" marker requires a non-empty
// user_id and a non-zero cutoff; reason is bounded.
func TestUserTokenRevocation_Validate(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name    string
		in      UserTokenRevocation
		wantErr bool
	}{
		{
			name: "valid",
			in:   UserTokenRevocation{UserID: "usr_alice", RevokeBefore: now, Reason: "admin-force-logout"},
		},
		{
			name:    "missing user_id",
			in:      UserTokenRevocation{RevokeBefore: now},
			wantErr: true,
		},
		{
			name:    "zero revoke_before",
			in:      UserTokenRevocation{UserID: "usr_alice"},
			wantErr: true,
		},
		{
			name:    "reason too long",
			in:      UserTokenRevocation{UserID: "usr_alice", RevokeBefore: now, Reason: string(make([]byte, 257))},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
