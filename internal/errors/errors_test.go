// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package errors

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Sensitive strings a raw *pgconn.PgError carries — they must NEVER reach the
// client-facing message (data-integrity.md / api-conventions.md: no pgx leak).
const (
	secretConstraint = "super_secret_internal_constraint"
	secretMessage    = `duplicate key value violates unique constraint "super_secret_internal_constraint"`
	secretDetail     = "Key (internal_hostid)=(host-42) already exists."
	secretTable      = "internal_secret_table"
)

func mkPgErr(code, constraint string) *pgconn.PgError {
	return &pgconn.PgError{
		Code:           code,
		ConstraintName: constraint,
		Message:        secretMessage,
		Detail:         secretDetail,
		ColumnName:     "internal_hostid",
		TableName:      secretTable,
	}
}

func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, s := range []string{secretConstraint, secretDetail, secretTable, secretMessage} {
		if strings.Contains(out, s) {
			t.Errorf("LEAK: client-facing text %q contains sensitive pgx fragment %q", out, s)
		}
	}
}

// TestWrapPgErr_NotNull_NoColumnLeak — 23502 (not_null_violation) must map to a
// generic InvalidArgument message; the raw Postgres column name (internal schema
// identifier, differs from the public proto field name) must never be echoed.
func TestWrapPgErr_NotNull_NoColumnLeak(t *testing.T) {
	err := WrapPgErr(mkPgErr("23502", ""), "", "")
	if !stderrors.Is(err, ErrInvalidArg) {
		t.Fatalf("want ErrInvalidArg, got %v", err)
	}
	out := StripSentinel(err)
	if strings.Contains(out, "internal_hostid") {
		t.Errorf("LEAK: client-facing text %q echoes raw pg column name", out)
	}
	if out != "a required field is missing" {
		t.Errorf("text = %q; want generic no-leak text", out)
	}
}

// TestWrapPgErr_NoLeak_OnUnmappedConstraints — every fallback path (unknown
// SQLSTATE + unknown constraint per family) must produce a fixed, schema-free
// message and the correct sentinel, never the raw pgErr text.
func TestWrapPgErr_NoLeak_OnUnmappedConstraints(t *testing.T) {
	cases := []struct {
		name     string
		code     string
		sentinel error
		wantText string
	}{
		{"unmapped-sqlstate", "XX000", ErrInternal, "database error"},
		{"unmapped-unique", "23505", ErrAlreadyExists, "resource with these attributes already exists"},
		{"unmapped-fk", "23503", ErrFailedPrecondition, "referenced resource not found or still in use"},
		{"unmapped-check", "23514", ErrInvalidArg, "Illegal argument: value violates a constraint"},
		{"exclusion", "23P01", ErrFailedPrecondition, "resource conflicts with an existing reservation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := WrapPgErr(mkPgErr(c.code, secretConstraint), "", "")
			if !stderrors.Is(err, c.sentinel) {
				t.Fatalf("want sentinel %v, got %v", c.sentinel, err)
			}
			out := StripSentinel(err)
			if out != c.wantText {
				t.Errorf("text = %q; want %q", out, c.wantText)
			}
			assertNoLeak(t, out)
		})
	}
}

// TestWrapPgErr_KnownConstraint_KeepsVerbatimContract — the no-leak hardening
// must NOT regress the constraint-aware verbatim Kachō text contract.
func TestWrapPgErr_KnownConstraint_KeepsVerbatimContract(t *testing.T) {
	err := WrapPgErr(mkPgErr("23505", "accounts_name_unique"), "", "my-acct")
	if !stderrors.Is(err, ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
	if got := StripSentinel(err); got != "Account with name my-acct already exists" {
		t.Errorf("verbatim contract text regressed: %q", got)
	}
}

// TestWrapPgErr_ConditionFK_DirectionSensitive — migration 0048's DB-level
// Condition reference (access_binding_conditions_condition_fk) must map 23503 to
// FailedPrecondition with direction-sensitive, schema-free text: INSERT side →
// "Condition <id> not found"; delete side (kindHint "Condition.Delete", the ON
// DELETE RESTRICT firing on the TOCTOU race) → "condition is in use ...".
func TestWrapPgErr_ConditionFK_DirectionSensitive(t *testing.T) {
	const constraint = "access_binding_conditions_condition_fk"

	insErr := WrapPgErr(mkPgErr("23503", constraint), "", "cnd_x")
	if !stderrors.Is(insErr, ErrFailedPrecondition) {
		t.Fatalf("insert side: want ErrFailedPrecondition, got %v", insErr)
	}
	if got := StripSentinel(insErr); got != "Condition cnd_x not found" {
		t.Errorf("insert side text = %q; want %q", got, "Condition cnd_x not found")
	}
	assertNoLeak(t, StripSentinel(insErr))

	delErr := WrapPgErr(mkPgErr("23503", constraint), "Condition.Delete", "cnd_x")
	if !stderrors.Is(delErr, ErrFailedPrecondition) {
		t.Fatalf("delete side: want ErrFailedPrecondition, got %v", delErr)
	}
	if got := StripSentinel(delErr); got != "condition is in use by access bindings" {
		t.Errorf("delete side text = %q; want in-use text", got)
	}
	assertNoLeak(t, StripSentinel(delErr))
}

// TestWrapPgErr_NonPgError_PassesThrough — a non-pgx error is returned as-is
// (the bridge only translates SQLSTATEs).
func TestWrapPgErr_NonPgError_PassesThrough(t *testing.T) {
	orig := stderrors.New("some domain error")
	if got := WrapPgErr(orig, "", ""); got != orig {
		t.Errorf("non-pg error not passed through: %v", got)
	}
}
