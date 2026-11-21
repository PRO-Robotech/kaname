// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAdministrativeQueryRetainsNativeArmsAndPagesExactFacts(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, axis := range []string{"", "kaname.accounts"} {
			sql, err := administrativeQuerySQL(axis, nested)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []string{"f.object_type, f.object_id, f.relation, f.subject", "b.expires_at > $13::timestamptz", "JOIN speaker sp ON sp.subject = f.subject", "ORDER BY src.object_type COLLATE", "$19::text", "LIMIT $8::int"} {
				if !strings.Contains(sql, part) {
					t.Fatalf("lost native predicate/page key %q", part)
				}
			}
			if strings.Contains(sql, "{{") || strings.Contains(sql, "b.expires_at > now()") {
				t.Fatal("unexpanded template or transaction-start expiry")
			}
			public, err := verdictQuerySQL(axis, nested)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(public, "b.expires_at > now()") || strings.Contains(public, "$19") {
				t.Fatal("public read template changed")
			}
		}
	}
}
func TestAdministrativeBudgetAndConditionDecisionTime(t *testing.T) {
	b := &AdministrativeReadBudget{}
	if err := b.Charge(100000, 4096); err != nil {
		t.Fatal(err)
	}
	for _, cost := range [][2]int{{1, 0}, {0, 1}, {-1, 0}, {0, -1}} {
		if !errors.Is(b.Charge(cost[0], cost[1]), ErrAdministrativeSourceLimit) {
			t.Fatal("exhausted/negative budget accepted")
		}
	}
	now := time.Unix(200000, 0)
	input := map[string]any{"current_time": now.Add(-time.Hour), "acr_value": "3", "amr_claims": []string{"webauthn"}, "mfa_at": now.Add(-16 * time.Minute)}
	copy := administrativeContext(input, now)
	if input["current_time"] != now.Add(-time.Hour) {
		t.Fatal("caller context mutated")
	}
	if ok, err := evalCondition("mfa_fresh", nil, copy); err != nil || ok {
		t.Fatalf("postwait MFA must expire: %v %v", ok, err)
	}
	copy["mfa_at"] = now.Add(-time.Minute)
	if ok, err := evalCondition("mfa_fresh", nil, copy); err != nil || !ok {
		t.Fatalf("fresh MFA lost: %v %v", ok, err)
	}
}

func TestAdministrativeConditionPrecedesSourceWithoutMaskingFailures(t *testing.T) {
	at := time.Unix(200000, 0)
	fact := AdministrativeFact{ObjectType: "iam_role", ObjectID: "role", Relation: "admin", Subject: "user:actor", ConditionName: "mfa_fresh"}
	calls := 0
	unconfirmed := func(context.Context, AdministrativeFact, *AdministrativeReadBudget) (bool, error) {
		calls++
		return false, ErrAdministrativeSourceUnconfirmed
	}
	budget := &AdministrativeReadBudget{}
	ok, err := checkAdministrativeCandidate(context.Background(), fact, administrativeContext(nil, at), budget, unconfirmed)
	if ok || err != nil || calls != 0 {
		t.Fatalf("known false poisoned union: %v %v calls=%d", ok, err, calls)
	}
	fresh := administrativeContext(map[string]any{"acr_value": "3", "amr_claims": []string{"webauthn"}, "mfa_at": at.Add(-time.Minute)}, at)
	ok, err = checkAdministrativeCandidate(context.Background(), fact, fresh, budget, unconfirmed)
	if ok || !errors.Is(err, ErrAdministrativeSourceUnconfirmed) || calls != 1 {
		t.Fatalf("satisfied condition bypassed source: %v %v calls=%d", ok, err, calls)
	}
	fact.ConditionName = "unknown-condition"
	ok, err = checkAdministrativeCandidate(context.Background(), fact, fresh, budget, unconfirmed)
	var unknown errUnknownCondition
	if ok || !errors.As(err, &unknown) || calls != 1 {
		t.Fatalf("unknown condition accepted: %v %v calls=%d", ok, err, calls)
	}
	fact.ConditionName = ""
	for _, cause := range []error{errors.New("database unavailable"), ErrAdministrativeSourceLimit, context.Canceled} {
		ok, err = checkAdministrativeCandidate(context.Background(), fact, nil, budget, func(context.Context, AdministrativeFact, *AdministrativeReadBudget) (bool, error) {
			return false, cause
		})
		if ok || !errors.Is(err, cause) {
			t.Fatalf("source error swallowed: %v %v", ok, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err = checkAdministrativeCandidate(ctx, fact, nil, budget, unconfirmed)
	if ok || !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("cancelled check called source: %v %v calls=%d", ok, err, calls)
	}
}
