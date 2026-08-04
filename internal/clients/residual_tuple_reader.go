// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kacho/services/iam/internal/outboxtypes"
)

// errResidualListingUnbounded — the object's listing did not terminate within the page
// cap. Returned rather than swallowed: see ObjectTuples.
var errResidualListingUnbounded = errors.New("openfga read: object tuple listing did not terminate")

// strongTupleLister — the ONE capability this reader needs: an object-scoped listing at
// HIGHER_CONSISTENCY. Declared here rather than widening RelationQueries, because every
// other consumer of that interface reads to ANSWER a question, while this one reads to
// decide what to REMOVE — and only the second is wrong when the answer is stale.
type strongTupleLister interface {
	ReadTuplesStrong(ctx context.Context, subjectFilter, relationFilter, objectFilter string,
		pageSize int, pageToken string) ([]ConditionalTuple, string, error)
}

// residualReadPageSize — page size for the object-scoped listing below. An object carries
// a handful of proxy-written relationships (a scope pointer plus a creator), so one page
// answers in practice; the loop below exists because "in practice" is not a guarantee and
// a silently truncated read would under-remove — the exact failure this reader is here to
// prevent.
const residualReadPageSize = 100

// residualReadPageCap bounds the pagination loop. It is a liveness guard, not a limit on
// correctness: exhausting it is reported as an error, so the withdrawal refuses and is
// redelivered rather than committing a partial removal.
const residualReadPageCap = 50

// ResidualTupleReader names every relationship currently standing on one object, so a
// withdrawal can take away all of what this proxy could have written instead of only the
// tuple the consumer happened to name.
//
// WHY THE READ IS STRONG. The set is used to decide what to REMOVE. A stale snapshot
// under-reports, and under-reporting here is not a retry that fixes itself later — it is a
// relationship that survives the teardown of its object and keeps answering ALLOW. The
// registration it must see may have been written moments earlier by this same process, so
// replica lag is the ordinary case rather than the unlikely one.
type ResidualTupleReader struct {
	q strongTupleLister
}

// NewResidualTupleReader builds the adapter. nil-safe: a nil querier yields nil, so the
// composition root of a deployment without a configured store gets the queue-only path
// rather than a panic.
func NewResidualTupleReader(q strongTupleLister) *ResidualTupleReader {
	if q == nil {
		return nil
	}
	return &ResidualTupleReader{q: q}
}

// ObjectTuples lists the relationships standing on `object`. Filtering down to the ones
// this proxy owns is the use-case's job — it holds the policy predicate — so the adapter
// returns the object's tuples verbatim and decides nothing.
func (r *ResidualTupleReader) ObjectTuples(ctx context.Context, object string) ([]outboxtypes.RelationTuple, error) {
	if r == nil || object == "" {
		return nil, nil
	}
	var (
		out   []outboxtypes.RelationTuple
		token string
	)
	for page := 0; page < residualReadPageCap; page++ {
		batch, next, err := r.q.ReadTuplesStrong(ctx, "", "", object, residualReadPageSize, token)
		if err != nil {
			return nil, err
		}
		for _, t := range batch {
			out = append(out, outboxtypes.RelationTuple{
				User:     t.User,
				Relation: t.Relation,
				Object:   t.Object,
			})
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
	// A listing that will not end is not a listing we may act on: acting on the prefix
	// would remove some of the object's relationships and leave the rest, which is the
	// partial withdrawal this whole path exists to rule out.
	return nil, errResidualListingUnbounded
}
