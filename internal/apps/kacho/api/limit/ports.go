// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package limit — use-cases of InternalLimitService: the lifecycle of a
// resource-count ceiling, plus the two reads owner-services live on.
//
// Clean Architecture: this package defines the narrow ports below and depends on
// nothing but domain + the corelib operation envelope. The concrete adapter (pgx)
// lives in internal/repo and is wired in cmd/kacho-iam/wiring.go.
package limit

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// limitRepo — persistence port.
//
// Withdraw reports whether a row was actually withdrawn. The distinction is not
// bookkeeping: the RPC is idempotent, so "already withdrawn" and "just withdrawn"
// look the same to the caller, and this is the one place that must still tell them
// apart.
type limitRepo interface {
	Get(ctx context.Context, id domain.LimitID) (domain.Limit, error)
	// List returns one page and the cursor for the next. The codec lives in the
	// adapter (it encodes a row's sort key), so the page and its cursor are
	// produced by the same code.
	List(ctx context.Context, limit int, pageToken string, f domain.LimitFilter) ([]domain.Limit, string, error)
	Insert(ctx context.Context, l domain.Limit) (domain.Limit, error)
	Update(ctx context.Context, id domain.LimitID, value int64) (domain.Limit, error)
	Withdraw(ctx context.Context, id domain.LimitID) (domain.Limit, bool, error)
	// StatedFor returns every in-force limit that could apply to one scope
	// object, across all three scopes, read as ONE set. ok=false when the id
	// names neither a project nor an account.
	StatedFor(ctx context.Context, scopeID string) ([]domain.Limit, bool, error)
	// ChangedSince returns limits whose revision is greater than `after`, in
	// revision order, INCLUDING withdrawn ones.
	ChangedSince(ctx context.Context, after int64, limit int) ([]domain.Limit, int64, error)
}

// deltaCursorCodec — the delta cursor's encode/decode pair.
//
// It is a PORT rather than a helper call because the use-case must not own a
// second implementation of the cursor: the codec belongs to the adapter that
// produced the revision, and a second one would agree with the first on every
// valid input and diverge exactly where divergence is invisible.
type deltaCursorCodec interface {
	Encode(revision int64) string
	Decode(cursor string) (int64, error)
}
