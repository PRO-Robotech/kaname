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

// TestWrapPgErr_NonPgError_PassesThrough — a non-pgx error is returned as-is
// (the bridge only translates SQLSTATEs).
func TestWrapPgErr_NonPgError_PassesThrough(t *testing.T) {
	orig := stderrors.New("some domain error")
	if got := WrapPgErr(orig, "", ""); got != orig {
		t.Errorf("non-pg error not passed through: %v", got)
	}
}
