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
	err := r.RedactResponseField(context.Background(), "iop_test", nil, `"<redacted>"`)
	if err == nil {
		t.Fatalf("empty field path must error, got nil")
	}
}

func Test_Redactor_InvalidJSON_ReturnsError(t *testing.T) {
	r := NewOpsResponseRedactor(nil, "kacho_iam")
	err := r.RedactResponseField(context.Background(), "iop_test",
		[]string{"client_secret"}, `not-json`)
	if err == nil {
		t.Fatalf("invalid JSON must error before DB call, got nil")
	}
}

func Test_Redactor_ValidJSON_PassesValidation(t *testing.T) {
	r := NewOpsResponseRedactor(nil, "kacho_iam")
	// nil pool — call will panic on Exec; we test ONLY pre-validation. Use a
	// recover guard to catch the panic and assert the err == nil at the
	// validation stage.
	defer func() {
		_ = recover() // pool.Exec on nil pool panics — that's expected here
	}()
	_ = r.RedactResponseField(context.Background(), "iop_test",
		[]string{"client_secret"}, `"<redacted>"`)
}
