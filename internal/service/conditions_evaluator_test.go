// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// conditions_evaluator_test.go — unit tests for the 7 built-in CEL predicates.
package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

func TestBuiltinEvaluator_MFAFresh_Allows(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, trace, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH,
		"", nil,
		map[string]any{
			"acr_value":    "3",
			"amr_claims":   []string{"webauthn"},
			"current_time": now,
			"mfa_at":       now - 60,
		},
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed; trace=%s", trace)
	}
}

func TestBuiltinEvaluator_MFAFresh_DeniesACR2(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, trace, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH,
		"", nil,
		map[string]any{
			"acr_value":    "2",
			"amr_claims":   []string{"webauthn"},
			"current_time": now,
			"mfa_at":       now - 60,
		},
	)
	if allowed {
		t.Fatalf("expected denied; trace=%s", trace)
	}
	if !strings.Contains(trace, "acr") {
		t.Errorf("trace should mention acr; got %q", trace)
	}
}

func TestBuiltinEvaluator_MFAFresh_DeniesNoWebAuthn(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, trace, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH,
		"", nil,
		map[string]any{
			"acr_value":    "3",
			"amr_claims":   []string{"password"},
			"current_time": now,
			"mfa_at":       now - 60,
		},
	)
	if allowed {
		t.Fatalf("expected denied; trace=%s", trace)
	}
	if !strings.Contains(trace, "webauthn") {
		t.Errorf("trace should mention webauthn; got %q", trace)
	}
}

func TestBuiltinEvaluator_MFAFresh_DeniesStaleMFA(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_MFA_FRESH,
		"", nil,
		map[string]any{
			"acr_value":    "3",
			"amr_claims":   []string{"webauthn"},
			"current_time": now,
			"mfa_at":       now - 20*60,
		},
	)
	if allowed {
		t.Fatalf("expected denied (mfa_at 20min old)")
	}
}

func TestBuiltinEvaluator_NonExpired_Allows(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_NON_EXPIRED,
		"", nil,
		map[string]any{
			"current_time": now,
			"valid_until":  now + 3600,
		},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed")
	}
}

func TestBuiltinEvaluator_NonExpired_Denies(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_NON_EXPIRED,
		"", nil,
		map[string]any{
			"current_time": now,
			"valid_until":  now - 60,
		},
	)
	if allowed {
		t.Fatalf("expected denied (expired)")
	}
}

func TestBuiltinEvaluator_SourceIPInRange_AllowsIPv4(t *testing.T) {
	e := NewBuiltinEvaluator()
	allowed, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_SOURCE_IP_IN_RANGE,
		"",
		map[string]any{"allowed_cidrs": []string{"10.0.0.0/8"}},
		map[string]any{"client_ip": "10.42.5.7"},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed")
	}
}

func TestBuiltinEvaluator_SourceIPInRange_DeniesOutside(t *testing.T) {
	e := NewBuiltinEvaluator()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_SOURCE_IP_IN_RANGE,
		"",
		map[string]any{"allowed_cidrs": []string{"10.0.0.0/8"}},
		map[string]any{"client_ip": "8.8.8.8"},
	)
	if allowed {
		t.Fatalf("expected denied")
	}
}

func TestBuiltinEvaluator_SourceIPInRange_IPv6(t *testing.T) {
	e := NewBuiltinEvaluator()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_SOURCE_IP_IN_RANGE,
		"",
		map[string]any{"allowed_cidrs": []string{"2001:db8::/32"}},
		map[string]any{"client_ip": "2001:db8:beef::1"},
	)
	if !allowed {
		t.Fatalf("expected allowed for IPv6")
	}
}

// BUILTIN_CONDITION_BREAK_GLASS_WINDOW is a deprecated enum value kept for
// wire-compat; the service layer rejects it.

// BUILTIN_CONDITION_JIT_WINDOW is likewise deprecated: no flow sets
// `activated_at`, so the predicate could never gate on real state. A binding
// carrying it is rejected at evaluation (fail-closed: not allowed +
// ErrUnsupportedExpression), never silently "allowed". The enum value stays
// deprecated-in-place for wire-compat.
func TestBuiltinEvaluator_JITWindow_Rejected(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_JIT_WINDOW,
		"",
		map[string]any{"ttl_seconds": int64(3600)},
		map[string]any{
			"current_time": now,
			"activated_at": now - 1800, // would have been "in window" pre-fix
		},
	)
	if allowed {
		t.Fatalf("expected denied — jit_window is deprecated and must fail-closed")
	}
	if !errors.Is(err, ErrUnsupportedExpression) {
		t.Fatalf("expected ErrUnsupportedExpression (deprecated kind); got %v", err)
	}
}

// A free-form expression that used to be recognised as jit_window via the
// substring heuristic must now fall through to the UNSPECIFIED/free-form
// path (delegated to FGA), i.e. NOT be evaluated as the removed builtin.
func TestBuiltinEvaluator_RecogniseExpression_JITWindow_NotRecognised(t *testing.T) {
	e := NewBuiltinEvaluator()
	now := time.Now().Unix()
	allowed, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED,
		`current_time - activated_at < ttl_seconds`,
		map[string]any{"ttl_seconds": int64(3600)},
		map[string]any{
			"current_time": now,
			"activated_at": now - 1800,
		},
	)
	if allowed {
		t.Fatalf("expected not-allowed — jit_window heuristic must no longer match")
	}
	if !errors.Is(err, ErrUnsupportedExpression) {
		t.Fatalf("expected ErrUnsupportedExpression (free-form fallthrough); got %v", err)
	}
}

func TestBuiltinEvaluator_BusinessHours_Allows(t *testing.T) {
	e := NewBuiltinEvaluator()
	// Build a time anchored at 10am UTC.
	tm := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_BUSINESS_HOURS,
		"",
		map[string]any{"start_h": int64(9), "end_h": int64(18), "tz": "UTC"},
		map[string]any{"current_time": tm.Unix()},
	)
	if !allowed {
		t.Fatalf("expected allowed (10am UTC in [9,18))")
	}
}

func TestBuiltinEvaluator_BusinessHours_DeniesAfterHours(t *testing.T) {
	e := NewBuiltinEvaluator()
	tm := time.Date(2026, 5, 19, 22, 0, 0, 0, time.UTC)
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_BUSINESS_HOURS,
		"",
		map[string]any{"start_h": int64(9), "end_h": int64(18), "tz": "UTC"},
		map[string]any{"current_time": tm.Unix()},
	)
	if allowed {
		t.Fatalf("expected denied (10pm UTC outside [9,18))")
	}
}

func TestBuiltinEvaluator_DeviceCompliant_Allows(t *testing.T) {
	e := NewBuiltinEvaluator()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_DEVICE_COMPLIANT,
		"",
		map[string]any{"allowed_attestations": []string{"aaguid-1", "aaguid-2"}},
		map[string]any{"device_attestation": "aaguid-1"},
	)
	if !allowed {
		t.Fatalf("expected allowed")
	}
}

func TestBuiltinEvaluator_DeviceCompliant_DeniesUnknown(t *testing.T) {
	e := NewBuiltinEvaluator()
	allowed, _, _ := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_DEVICE_COMPLIANT,
		"",
		map[string]any{"allowed_attestations": []string{"aaguid-1"}},
		map[string]any{"device_attestation": "aaguid-unknown"},
	)
	if allowed {
		t.Fatalf("expected denied")
	}
}

func TestBuiltinEvaluator_RecogniseExpression_MFAFresh(t *testing.T) {
	e := NewBuiltinEvaluator()
	// Free-form expression that should match MFA_FRESH heuristic.
	now := time.Now().Unix()
	allowed, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED,
		`acr_value == "3" && "webauthn" in amr_claims && current_time - mfa_at < duration("15m")`,
		nil,
		map[string]any{
			"acr_value":    "3",
			"amr_claims":   []string{"webauthn"},
			"current_time": now,
			"mfa_at":       now - 60,
		},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !allowed {
		t.Fatalf("expected recognised + allowed")
	}
}

func TestBuiltinEvaluator_RecogniseExpression_Cache(t *testing.T) {
	e := NewBuiltinEvaluator()
	expr := `current_time < valid_until`
	// First call populates cache.
	_, _, _ = e.Evaluate(iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED, expr, nil,
		map[string]any{"current_time": int64(1), "valid_until": int64(2)})
	// Second call should hit cache (same expression).
	allowed, _, _ := e.Evaluate(iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED, expr, nil,
		map[string]any{"current_time": int64(1), "valid_until": int64(100)})
	if !allowed {
		t.Fatalf("cache hit should still evaluate correctly")
	}
	// Cache populated.
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.cache[expr]; !ok {
		t.Errorf("expected expression to be cached")
	}
}

func TestBuiltinEvaluator_RecogniseExpression_FreeFormReturnsErr(t *testing.T) {
	e := NewBuiltinEvaluator()
	_, _, err := e.Evaluate(
		iamv1.BuiltinCondition_BUILTIN_CONDITION_UNSPECIFIED,
		`some_random_field == "wat"`,
		nil, nil,
	)
	if err == nil {
		t.Fatalf("expected ErrUnsupportedExpression")
	}
}
