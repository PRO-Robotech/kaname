// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package errors — pgx-free sentinel error family for kacho-iam.
//
// Every use-case returns a sentinel-family error (ErrNotFound /
// ErrAlreadyExists / ErrFailedPrecondition / ErrInvalidArg / ErrInternal /
// ErrUnavailable / ErrPermissionDenied / ErrUnauthenticated / ErrAborted);
// the handler layer maps to a gRPC code (shared.MapRepoErr). The within-service
// invariant forbids software-precheck for within-service refs — a within-service
// violation is detected by catching the pgx SQLSTATE and wrapping it in the
// appropriate sentinel. That SQLSTATE→sentinel bridge (which needs pgx/pgconn)
// deliberately lives in the ADAPTER layer (internal/repo/kacho/pg/pgmaperr.go),
// NOT here: this package stays pgx-free so the ~40 use-case/handler files that
// import it for the sentinels never pull pgx into their build closure
// (architecture.md dependency-rule).
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
)

// Sentinel error family (parity with kacho-vpc/service.Err*).
var (
	ErrNotFound           = stderrors.New("not found")
	ErrAlreadyExists      = stderrors.New("already exists")
	ErrFailedPrecondition = stderrors.New("failed precondition")
	ErrInvalidArg         = stderrors.New("invalid argument")
	ErrInternal           = stderrors.New("internal")
	ErrUnavailable        = stderrors.New("unavailable")
	// ErrPermissionDenied — caller is authenticated but lacks the required
	// permission / is not the designated actor (e.g. JitPending
	// non-designated-approver, ComplianceReport FGA gate). Maps to gRPC
	// PERMISSION_DENIED.
	ErrPermissionDenied = stderrors.New("permission denied")
	// ErrUnauthenticated — caller's token does not satisfy the required
	// authentication assurance (step-up acr). Maps to gRPC UNAUTHENTICATED.
	ErrUnauthenticated = stderrors.New("unauthenticated")

	// ErrAborted — a transient concurrency conflict the caller can retry (the
	// operation was aborted, typically a transaction serialization failure).
	// Maps to gRPC ABORTED, the idiomatic "retry the transaction" code — unlike
	// FAILED_PRECONDITION, which tells a well-behaved client NOT to retry.
	ErrAborted = stderrors.New("aborted")

	// ErrSelfRevoke — caller tries to revoke its own cluster admin grant
	// (self-protection). Maps to gRPC FAILED_PRECONDITION with
	// the Kachō text "cannot revoke own cluster admin grant".
	//
	// CHECK constraint cannot express this (constraint doesn't know caller —
	// runtime-property), so the guard lives in the SQL WHERE-clause of
	// the CAS UPDATE in ClusterAdminGrantWriter.Revoke.
	ErrSelfRevoke = stderrors.New("self revoke forbidden")

	// ErrLastAdmin — caller tries to revoke the last remaining active
	// cluster admin (lock-out protection). Maps to gRPC
	// FAILED_PRECONDITION with the Kachō text "cannot revoke last active
	// cluster admin".
	//
	// Implemented via single-statement CAS UPDATE with subquery
	// `(SELECT count(*) FROM cluster_admin_grants WHERE granted_until IS NULL) > 1`
	// — atomic, no separate SELECT-then-UPDATE race window.
	ErrLastAdmin = stderrors.New("last admin revoke forbidden")
)

// Wrapf — standard fmt.Errorf-style wrapper with an explicit sentinel. Use
// in use-cases: `return errors.Wrapf(errors.ErrNotFound, "Account %s not found", id)`.
func Wrapf(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...)
}

// StripSentinel — extracts the "useful" part of the message (after
// "sentinel: ") so the handler layer can show the client the canonical Kachō text
// without the internal prefix (parity with
// kacho-vpc/internal/handler/mapping.go::stripSentinel).
func StripSentinel(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, s := range []error{ErrNotFound, ErrAlreadyExists, ErrFailedPrecondition, ErrInvalidArg, ErrInternal, ErrUnavailable, ErrPermissionDenied, ErrUnauthenticated, ErrAborted, ErrSelfRevoke, ErrLastAdmin} {
		prefix := s.Error() + ": "
		if rest, ok := strings.CutPrefix(msg, prefix); ok {
			return rest
		}
	}
	return msg
}
