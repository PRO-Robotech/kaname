// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_conflict.go — OpenFGA's transactional write-conflict (HTTP 409) as a
// first-class, classifiable outcome of every write/delete path, plus the bounded
// retry that resolves it at the transport boundary.
package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// ErrWriteConflict — OpenFGA ABORTED a transactional write/delete because a
// CONCURRENT transaction touched one or more of the same tuples. On the wire:
//
//	HTTP 409 {"code":"Aborted","message":"transactional write failed due to
//	          conflict: one or more tuples to write were inserted by another
//	          transaction"}
//
// Semantics (verified against openfga/openfga:v1.14.0 + Postgres datastore, the
// version the umbrella chart deploys): the aborted transaction applied NOTHING,
// and the request is safe to retry VERBATIM — the retry either lands or degrades
// to the idempotent already-exists case.
//
// It is therefore neither "already applied" (nothing was written — marking the
// outbox row sent would silently drop the tuple and leave a permanent authz gap)
// nor permanent (retrying is exactly what resolves it).
//
// WHY IT IS THE NORMAL CASE, NOT AN EXOTIC ONE. Every reconcile pass co-commits
// its tuples to kacho_iam.fga_outbox AND writes them synchronously post-commit
// (reconcile.applyAfterCommit). The outbox drainer is NOTIFY-driven, so the SAME
// commit wakes it and it re-applies the SAME tuples row-by-row. Two writers, one
// object, overlapping tuple sets, on every single create — plus N concurrent
// creates under parallel e2e. Before this error existed the 409 collapsed into a
// vocabulary-free "openfga write: status 409" that nobody could classify: the
// sync writer deferred the object's whole tuple-set to the drainer without a
// retry and the drainer's applier fell through to "unclassified ⇒ transient",
// backing off 1s→30s behind its per-object partition head. A millisecond
// conflict became tens of seconds of unmaterialized grant.
var ErrWriteConflict = errors.New("openfga write: transactional conflict")

// IsWriteConflict reports whether err is (or wraps) ErrWriteConflict.
func IsWriteConflict(err error) bool { return errors.Is(err, ErrWriteConflict) }

// Bounded conflict-retry budget. A conflict resolves as soon as the competing
// transaction commits, so a handful of short, JITTERED attempts covers it: the
// whole budget (~150ms worst case) is an order of magnitude below the create
// path's read-your-writes window and three orders below the outbox drainer's
// 1s→30s backoff that the alternative (deferring) buys.
//
// Jitter is not cosmetic: the competing writers here are symmetric (sync writer
// vs drainer vs a sibling reconcile pass), so a fixed backoff would make them
// retry in lock-step and re-collide.
const (
	fgaConflictMaxAttempts = 5
	fgaConflictBaseBackoff = 10 * time.Millisecond
	fgaConflictMaxBackoff  = 160 * time.Millisecond
)

// applyWithConflictRetry runs one OpenFGA write/delete apply, retrying while
// OpenFGA reports a transactional conflict. Safe because an aborted transaction
// applied NOTHING — the retry is the identical request, and once the racer's
// tuples are committed it degrades to the idempotent already-exists reply the
// callers already treat as success.
//
// Returns the LAST error, so an unresolved conflict still surfaces as a typed
// ErrWriteConflict for the caller to classify (read-delta on the sync writer,
// transient-retry on the outbox applier). Context cancellation stops the retry
// loop (graceful shutdown) and surfaces that same last error.
func applyWithConflictRetry(ctx context.Context, apply func(context.Context) error) error {
	backoff := fgaConflictBaseBackoff
	for attempt := 1; ; attempt++ {
		err := apply(ctx)
		if !IsWriteConflict(err) || attempt >= fgaConflictMaxAttempts {
			return err
		}
		// Full jitter over the current window — decorrelates symmetric writers.
		// math/rand is deliberate: this is backoff spread, not a security value.
		// #nosec G404 -- the draw is consumed by time.After four lines below and
		// nowhere else; it is not a secret, a one-time code or an identifier.
		wait := time.Duration(rand.Int64N(int64(backoff)) + 1)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		if backoff < fgaConflictMaxBackoff {
			backoff *= 2
		}
	}
}

// idempotentWriteReply reports whether a 400 body means "the tuple you asked me
// to write is ALREADY there" — the caller's desired post-condition holds, so the
// replay is a success.
//
// Vocabulary is pinned to what the DEPLOYED server actually emits
// (openfga/openfga:v1.14.0, captured live):
//
//	"cannot write a tuple which already exists: user: '…' …: tuple to be written
//	 already existed or the tuple to be deleted did not exist"
//
// Two things this must get right:
//   - the body carries NO "already_exists" token — matching only that token (as
//     the client used to) never fires against the deployed server, so every
//     idempotent replay surfaced as a hard error;
//   - the TRAILER names BOTH directions ("already existed or … did not exist"),
//     so it cannot discriminate. The leading "cannot write a tuple" clause does.
//
// The legacy "already_exists" errorCode marker is kept as an OR for any OpenFGA
// build that emits it.
func idempotentWriteReply(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "already_exists") {
		return true
	}
	return strings.Contains(low, "cannot write a tuple") && strings.Contains(low, "already exist")
}

// idempotentDeleteReply — the delete twin: "the tuple you asked me to delete is
// already gone". Same discrimination rules (leading clause, not the shared
// trailer); legacy "cannot_delete" errorCode kept as an OR.
func idempotentDeleteReply(body string) bool {
	low := strings.ToLower(body)
	if strings.Contains(low, "cannot_delete") {
		return true
	}
	return strings.Contains(low, "cannot delete a tuple") && strings.Contains(low, "not exist")
}

// deleteRejectedAsAbsent reports whether a DELETE request was rejected because at
// least one of its tuples is already gone.
//
// It is the caller's job to only ask this about a DELETE (the shared reply trailer
// names BOTH directions and cannot discriminate; the leading clause can, and
// idempotentDeleteReply keys on it). The error message carries the capped reply body
// verbatim ("openfga write: bad request: <body>"), so the same pinned vocabulary that
// classifies a single-tuple reply classifies a batch one.
//
// WHY IT MATTERS. OpenFGA's write is TRANSACTIONAL: such a batch applied NOTHING and —
// unlike a 409 conflict — replaying it VERBATIM can never succeed, because the absent
// tuple stays absent. Left unclassified, a revoke burned its whole retry budget on a
// request that was impossible by construction while its still-live tuples survived.
// The resolution is to decompose the batch into single-tuple deletes (writeOrDelete),
// where "already absent" is a sound idempotent success per tuple.
func deleteRejectedAsAbsent(err error) bool {
	return err != nil && idempotentDeleteReply(err.Error())
}

// readWriteReply interprets ONE OpenFGA /write reply.
//
//	200                            → nil
//	400 accepted by `idempotent`   → nil (the desired post-condition already holds)
//	400 otherwise                  → "openfga write: bad request: <capped body>"
//	409                            → ErrWriteConflict wrapping the capped body
//	anything else                  → "openfga write: status <code>"
//
// `idempotent` decides whether a 400 body means the caller's desired
// post-condition already holds. It MUST be nil for a request carrying BOTH
// writes and deletes: OpenFGA's write is transactional, so a rejected mixed
// batch applied NOTHING — accepting the write-duplicate marker there would
// silently drop the batch's deletes (a surviving revoke ⇒ over-grant).
//
// Every body read is capped at maxErrBodyBytes so a misbehaving OpenFGA cannot
// bloat the error/log line or spike memory, and every non-2xx body is drained
// (capped) so the keep-alive connection returns to the pool.
func readWriteReply(resp *http.Response, idempotent func(string) bool) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		s := cappedBody(resp)
		if idempotent != nil && idempotent(s) {
			return nil
		}
		return fmt.Errorf("openfga write: bad request: %s", s)
	case http.StatusConflict:
		// Transactional abort — nothing was applied; retryable (see ErrWriteConflict).
		return fmt.Errorf("%w: %s", ErrWriteConflict, cappedBody(resp))
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return fmt.Errorf("openfga write: status %d", resp.StatusCode)
	}
}

// cappedBody reads at most maxErrBodyBytes of the response body.
func cappedBody(resp *http.Response) string {
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(io.LimitReader(resp.Body, maxErrBodyBytes))
	return buf.String()
}
