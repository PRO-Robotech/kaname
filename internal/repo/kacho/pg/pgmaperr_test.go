// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// pgmaperr_test.go — unit coverage for the SQLSTATE→sentinel bridge that moved
// out of internal/errors into this adapter layer (keeping internal/errors
// pgx-free). No DB: exercises wrapPgErr against synthetic *pgconn.PgError values.

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
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
	err := wrapPgErr(mkPgErr("23502", ""), "", "")
	if !stderrors.Is(err, iamerr.ErrInvalidArg) {
		t.Fatalf("want ErrInvalidArg, got %v", err)
	}
	out := iamerr.StripSentinel(err)
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
		{"unmapped-sqlstate", "XX000", iamerr.ErrInternal, "database error"},
		{"unmapped-unique", "23505", iamerr.ErrAlreadyExists, "resource with these attributes already exists"},
		{"unmapped-fk", "23503", iamerr.ErrFailedPrecondition, "referenced resource not found or still in use"},
		{"unmapped-check", "23514", iamerr.ErrInvalidArg, "Illegal argument: value violates a constraint"},
		{"exclusion", "23P01", iamerr.ErrFailedPrecondition, "resource conflicts with an existing reservation"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := wrapPgErr(mkPgErr(c.code, secretConstraint), "", "")
			if !stderrors.Is(err, c.sentinel) {
				t.Fatalf("want sentinel %v, got %v", c.sentinel, err)
			}
			out := iamerr.StripSentinel(err)
			if out != c.wantText {
				t.Errorf("text = %q; want %q", out, c.wantText)
			}
			assertNoLeak(t, out)
		})
	}
}

// TestWrapPgErr_SerializationFailure_Aborted — 40001 (serialization_failure) is a
// transient, retryable concurrency conflict; it must map to the retryable
// ErrAborted (gRPC ABORTED), NOT ErrFailedPrecondition (which tells a client not
// to retry). The message text and the sentinel must agree on "retry".
func TestWrapPgErr_SerializationFailure_Aborted(t *testing.T) {
	err := wrapPgErr(mkPgErr("40001", secretConstraint), "", "")
	if !stderrors.Is(err, iamerr.ErrAborted) {
		t.Fatalf("40001: want ErrAborted (retryable), got %v", err)
	}
	if stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		t.Fatalf("40001: must NOT be FailedPrecondition (non-retryable)")
	}
	out := iamerr.StripSentinel(err)
	if out != "serialization conflict, retry" {
		t.Errorf("text = %q; want %q", out, "serialization conflict, retry")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_ConnFamily_Unavailable — an 08xxx connection-family SQLSTATE maps
// to a retryable ErrUnavailable with a generic, schema-free message.
func TestWrapPgErr_ConnFamily_Unavailable(t *testing.T) {
	err := wrapPgErr(mkPgErr("08006", secretConstraint), "", "")
	if !stderrors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("08006: want ErrUnavailable, got %v", err)
	}
	out := iamerr.StripSentinel(err)
	if out != "database unavailable" {
		t.Errorf("text = %q; want %q", out, "database unavailable")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_KnownConstraint_KeepsVerbatimContract — the no-leak hardening
// must NOT regress the constraint-aware verbatim Kachō text contract.
func TestWrapPgErr_KnownConstraint_KeepsVerbatimContract(t *testing.T) {
	err := wrapPgErr(mkPgErr("23505", "accounts_name_unique"), "", "my-acct")
	if !stderrors.Is(err, iamerr.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
	if got := iamerr.StripSentinel(err); got != "Account with name my-acct already exists" {
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

	insErr := wrapPgErr(mkPgErr("23503", constraint), "", "cnd_x")
	if !stderrors.Is(insErr, iamerr.ErrFailedPrecondition) {
		t.Fatalf("insert side: want ErrFailedPrecondition, got %v", insErr)
	}
	if got := iamerr.StripSentinel(insErr); got != "Condition cnd_x not found" {
		t.Errorf("insert side text = %q; want %q", got, "Condition cnd_x not found")
	}
	assertNoLeak(t, iamerr.StripSentinel(insErr))

	delErr := wrapPgErr(mkPgErr("23503", constraint), "Condition.Delete", "cnd_x")
	if !stderrors.Is(delErr, iamerr.ErrFailedPrecondition) {
		t.Fatalf("delete side: want ErrFailedPrecondition, got %v", delErr)
	}
	if got := iamerr.StripSentinel(delErr); got != "condition is in use by access bindings" {
		t.Errorf("delete side text = %q; want in-use text", got)
	}
	assertNoLeak(t, iamerr.StripSentinel(delErr))
}

// TestWrapPgErr_SubjectRefBeforeDelete_ResourceAware — migration 0050's BEFORE
// DELETE trigger RAISEs 23503 tagged CONSTRAINT='access_binding_subjects_subject_ref'
// when a User/SA/Group is still referenced as a subjects[0..N] grantee. wrapPgErr
// must map it to FailedPrecondition with the canonical resource-aware text derived
// from the repo's "<Resource>.Delete" kindHint (SEC r8), never leaking pgx text.
func TestWrapPgErr_SubjectRefBeforeDelete_ResourceAware(t *testing.T) {
	const constraint = "access_binding_subjects_subject_ref"
	cases := []struct {
		kindHint string
		idHint   string
		want     string
	}{
		{"User.Delete", "usr_x", "User usr_x has active access bindings and cannot be deleted"},
		{"ServiceAccount.Delete", "sva_x", "ServiceAccount sva_x has active access bindings and cannot be deleted"},
		{"Group.Delete", "grp_x", "Group grp_x has active access bindings and cannot be deleted"},
		{"", "prn_x", "Principal prn_x has active access bindings and cannot be deleted"},
	}
	for _, c := range cases {
		err := wrapPgErr(mkPgErr("23503", constraint), c.kindHint, c.idHint)
		if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
			t.Fatalf("kindHint %q: want ErrFailedPrecondition, got %v", c.kindHint, err)
		}
		if got := iamerr.StripSentinel(err); got != c.want {
			t.Errorf("kindHint %q: text = %q; want %q", c.kindHint, got, c.want)
		}
		assertNoLeak(t, iamerr.StripSentinel(err))
	}
}

// TestWrapPgErr_AccountsOwnerFK_CommitTime — accounts_owner_fk is DEFERRABLE
// INITIALLY DEFERRED, so a non-existent account owner is NOT caught by the INSERT
// statement: the 23503 surfaces at COMMIT (writeTx.Commit runs the commit error
// through this same bridge with the owner-id hint recorded by accountWriter.Insert).
// It must map to FailedPrecondition with the canonical "User <id> not found" text —
// NOT the sentinel-only INTERNAL fallback that a raw *pgconn.PgError would trigger.
func TestWrapPgErr_AccountsOwnerFK_CommitTime(t *testing.T) {
	err := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "", "usr_missing")
	if !stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		t.Fatalf("commit-time accounts_owner_fk: want ErrFailedPrecondition, got %v", err)
	}
	if stderrors.Is(err, iamerr.ErrInternal) {
		t.Fatalf("commit-time accounts_owner_fk: must NOT map to ErrInternal")
	}
	out := iamerr.StripSentinel(err)
	if out != "User usr_missing not found" {
		t.Errorf("text = %q; want %q", out, "User usr_missing not found")
	}
	assertNoLeak(t, out)
}

// TestWrapPgErr_NilPassesThrough — a nil error (successful commit) must stay nil
// so writeTx.Commit's wrapping is a no-op on the happy path.
func TestWrapPgErr_NilPassesThrough(t *testing.T) {
	if got := wrapPgErr(nil, "", "usr_x"); got != nil {
		t.Errorf("wrapPgErr(nil) = %v; want nil", got)
	}
}

// TestWrapPgErr_NonPgError_PassesThrough — a non-pgx error is returned as-is
// (the bridge only translates SQLSTATEs).
func TestWrapPgErr_NonPgError_PassesThrough(t *testing.T) {
	orig := stderrors.New("some domain error")
	if got := wrapPgErr(orig, "", ""); got != orig {
		t.Errorf("non-pg error not passed through: %v", got)
	}
}
