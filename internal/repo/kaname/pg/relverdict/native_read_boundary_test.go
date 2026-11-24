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

func TestCapturedAdministrativeScopesReplaceBothNativeArms(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, axis := range []string{"", "kaname.accounts"} {
			sql, err := administrativeQuerySQL(axis, nested)
			if err != nil {
				t.Fatal(err)
			}
			bounded, raw, err := capturedAdministrativeSQL(sql, "iam_access_binding", "binding", []AdministrativeScope{{"iam_access_binding", "binding", 0}, {"account", "account", 1}, {"cluster", "cluster", 1}})
			if err != nil {
				t.Fatal(err)
			}
			// В сохранённом вводном SQL-комментарии есть resource_scope_edge.
			// Проверяем чтение таблицы и рекурсивный CTE, а не упоминание имени.
			for _, fragment := range []string{"FROM kaname.resource_scope_edge pe", "FROM scope s", "scope(s_type, s_id, depth) AS ("} {
				if !strings.Contains(sql, fragment) {
					t.Fatalf("исходный запрос не содержит проверяемый обход %q", fragment)
				}
				if strings.Contains(bounded, fragment) {
					t.Fatalf("captured read still expands mutable parents: %q", fragment)
				}
			}
			for _, fragment := range []string{"jsonb_to_recordset($20::jsonb)", "$2::text", "$3::text", "$7::int", "$12::int", scopeJoinGrantOne, scopeJoinFactOne, "JOIN speaker sp ON sp.subject = f.subject", "b.expires_at > $13::timestamptz", "$19::text", "LIMIT $8::int"} {
				if !strings.Contains(bounded, fragment) {
					t.Fatalf("lost semantic arm/predicate %q", fragment)
				}
			}
			if !strings.Contains(string(raw), `"depth":0`) || !strings.Contains(string(raw), `"depth":1`) {
				t.Fatal("anchor/parent distinction lost")
			}
		}
	}
	for _, scopes := range [][]AdministrativeScope{nil, {{"account", "foreign", 0}}, {{"account", "a", 1}}, {{"account", "a", 0}, {"project", "p", 0}}, {{"account", "a", 0}, {"account", "a", 0}}} {
		sql, _ := administrativeQuerySQL("", false)
		if _, _, err := capturedAdministrativeSQL(sql, "account", "a", scopes); !errors.Is(err, ErrAdministrativeSourceUnconfirmed) {
			t.Fatal("invalid scope graph accepted")
		}
	}
}

type deniedNativeBoundary struct{ calls int }

func (b *deniedNativeBoundary) NativeScopes(string, string, string, string) ([]AdministrativeScope, bool, error) {
	b.calls++
	return nil, false, ErrAdministrativeSourceUnconfirmed
}
func TestBoundAdministrativeRejectsBeforeSQLAndNeverResetsBudget(t *testing.T) {
	in := Query{Subject: "user:actor", ObjectType: "account", ObjectID: "a", Relation: "admin", DecisionAt: time.Now()}
	boundary := &deniedNativeBoundary{}
	// nil TX: любой случайный SQL dispatch превратил бы эту проверку в panic.
	_, _, err := askAdministrativeBound(context.Background(), nil, in, nil, boundary, &AdministrativeReadBudget{}, true)
	if !errors.Is(err, ErrAdministrativeSourceUnconfirmed) || boundary.calls != 1 {
		t.Fatalf("missing question fell through: %v", err)
	}
	for _, bound := range []AdministrativeReadBoundary{nil, boundary} {
		_, _, err = askAdministrativeBound(context.Background(), nil, in, nil, bound, nil, true)
		if !errors.Is(err, ErrAdministrativeSourceUnconfirmed) {
			t.Fatal("missing protected state accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = askAdministrativeBound(ctx, nil, in, nil, boundary, &AdministrativeReadBudget{}, true)
	if !errors.Is(err, context.Canceled) || boundary.calls != 1 {
		t.Fatal("cancel ignored")
	}
}

type permittedNativeBoundary struct{}

func (permittedNativeBoundary) NativeScopes(string, string, string, string) ([]AdministrativeScope, bool, error) {
	return nil, true, nil
}
func TestBoundAdministrativeBudgetFailsBeforeQueryOnEveryRoot(t *testing.T) {
	budget := &AdministrativeReadBudget{}
	if err := budget.Charge(100000, 4096); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		in := Query{Subject: "user:actor", ObjectType: "account", ObjectID: id, Relation: "admin", DecisionAt: time.Now()}
		_, _, err := askAdministrativeBound(context.Background(), nil, in, nil, permittedNativeBoundary{}, budget, true)
		if !errors.Is(err, ErrAdministrativeSourceLimit) {
			t.Fatalf("root %s reset budget or ran query: %v", id, err)
		}
	}
}
