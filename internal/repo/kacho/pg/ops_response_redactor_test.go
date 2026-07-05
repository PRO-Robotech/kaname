// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ops_response_redactor_test.go — unit tests for the redactor adapter's
// pre-validation. DB integration is exercised via integration tests
// (postgres testcontainer) and newman E2E.
package pg

import (
	"context"
	"testing"
)

func Test_Redactor_EmptyFieldPath_ReturnsError(t *testing.T) {
	r := NewOpsResponseRedactor(nil, "kacho_iam")
	err := r.RedactResponseField(context.Background(), "iop_test", nil)
	if err == nil {
		t.Fatalf("empty field path must error, got nil")
	}
}
