// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_batchcheck.go — OpenFGAHTTPClient.BatchCheckWithContext: ONE relation
// question about MANY objects, carried in a single request.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// BatchCheckItem — one question of a batch: the object asked about, plus tuples
// that hold for THIS item only.
//
// Per-item contextual tuples are not a refinement, they are what makes the batched
// question usable at all by the layer that decorates every Check with structural
// facts read from committed rows. Without them that layer has to ask row by row,
// and a batched door it cannot walk through is a door nobody uses.
type BatchCheckItem struct {
	Object     string
	Contextual []authztypes.TupleKey
}

// fgaMaxChecksPerBatchCheck — the relation store's OWN server-side ceiling on one
// batch-check request (`OPENFGA_MAX_CHECKS_PER_BATCH_CHECK`, default 50).
//
// It is the store's number, so it is declared here, on the adapter that talks to
// the store, and NOT imported from the caller that partitions against it — the
// adapter must not depend on the filter. That the two agree is asserted where
// both are visible (TestBatchCapAgreesWithTheFilterPartitionSize), because a
// drift between them is silent in one direction: a partition larger than the cap
// is refused by the store on every page.
//
// Read off the deployed build (openfga/openfga:v1.14.0), not assumed: 51 checks
// are answered `batchCheck received 51 checks, the maximum allowed is 50` with
// HTTP 400; 50 checks are answered HTTP 200.
const fgaMaxChecksPerBatchCheck = 50

// fgaWireBatchCheckItem — one entry of a batch-check request.
//
// `correlation_id` is what the response is keyed by, so it is the only thing
// that ties a verdict back to the object it is about. OpenFGA constrains it to
// `[A-Za-z0-9-]{1,36}`, so the request index — decimal, at most three digits at
// our cap — is a legal and collision-free choice within one request.
type fgaWireBatchCheckItem struct {
	TupleKey         fgaWireTupleKey          `json:"tuple_key"`
	Context          map[string]any           `json:"context,omitempty"`
	ContextualTuples *fgaWireContextualTuples `json:"contextual_tuples,omitempty"`
	CorrelationID    string                   `json:"correlation_id"`
}

type fgaWireContextualTuples struct {
	TupleKeys []fgaWireTupleKey `json:"tuple_keys"`
}

type fgaWireBatchCheckRequest struct {
	AuthorizationModelID string                  `json:"authorization_model_id,omitempty"`
	Checks               []fgaWireBatchCheckItem `json:"checks"`
	Consistency          string                  `json:"consistency,omitempty"`
}

type fgaWireBatchCheckResponse struct {
	Result map[string]struct {
		Allowed bool `json:"allowed"`
		Error   *struct {
			InputError string `json:"input_error"`
			Message    string `json:"message"`
		} `json:"error,omitempty"`
	} `json:"result"`
}

// batchCheckTimeout — the per-call deadline for one batch request.
//
// It is derived from the single-Check budget rather than set independently,
// because the two answer the same question and a drift between them would be
// invisible: a batch that timed out where a single Check would not looks exactly
// like a slow store.
//
// The multiplier is not "one budget per tuple". A batch is resolved by the store
// with its own internal concurrency (openfga's max_concurrent_checks_per_batch
// defaults to the same 50 the batch cap is), so a batch's latency tracks the
// SLOWEST tuple plus marshalling, not the sum: measured on the deployed stand a
// single check answers in ~3ms mean and a batch of 50 in ~19ms — roughly six
// singles, not fifty. Four times the single budget leaves headroom over that
// without letting one partition consume a page's worth of time.
func (c *OpenFGAHTTPClient) batchCheckTimeout() time.Duration {
	return 4 * c.checkTimeout()
}

// BatchCheckWithContext asks ONE relation about MANY objects in a single request
// and returns one verdict per object, positionally.
//
// It exists so a page of visibility filtering costs a number of round-trips
// proportional to the page divided by the store's cap, instead of one round-trip
// per row; see internal/authzfilter, which is its caller.
//
// # Errors are errors, including the ones that look like denials
//
// The single-Check sibling maps a 400 to a clean deny, on the reasoning that a
// malformed tuple can never resolve to a path and surfacing it as an outage
// would fail-closed to a misleading 503. That reasoning does NOT carry over:
// here a 400 is overwhelmingly about the REQUEST — a partition larger than the
// store's cap — and a partition refused wholesale is not fifty objects the
// subject cannot see. Mapping it to denials would filter a page down to nothing
// while reporting success, which is the permanent-invisibility failure mode in a
// new costume. Every non-200 is an error, and the store's own message is carried
// so a configuration fault reads as one.
//
// A per-ITEM error inside a 200 response is different and is honoured as OpenFGA
// defines it: that item did not resolve, which is a deny for that object only.
func (c *OpenFGAHTTPClient) BatchCheckWithContext(
	ctx context.Context, subject, relation string, objects []string, condCtx map[string]any,
) ([]bool, error) {
	items := make([]BatchCheckItem, len(objects))
	for i, o := range objects {
		items[i] = BatchCheckItem{Object: o}
	}
	return c.BatchCheckItems(ctx, subject, relation, items, condCtx)
}

// BatchCheckItems — BatchCheckWithContext where each item may carry tuples that
// hold for that item only. See BatchCheckItem.
func (c *OpenFGAHTTPClient) BatchCheckItems(
	ctx context.Context, subject, relation string, items []BatchCheckItem, condCtx map[string]any,
) ([]bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return nil, ErrNotConfigured
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > fgaMaxChecksPerBatchCheck {
		// Refuse locally rather than let the store refuse: the error is the same
		// fault either way, and asking first would spend a round-trip to be told.
		return nil, fmt.Errorf(
			"openfga batch-check: %d checks exceeds the maximum allowed of %d",
			len(items), fgaMaxChecksPerBatchCheck)
	}

	req := fgaWireBatchCheckRequest{
		AuthorizationModelID: c.AuthorizationModel,
		Checks:               make([]fgaWireBatchCheckItem, 0, len(items)),
	}
	for i, item := range items {
		wire := fgaWireBatchCheckItem{
			TupleKey:      fgaWireTupleKey{User: subject, Relation: relation, Object: item.Object},
			Context:       condCtx,
			CorrelationID: strconv.Itoa(i),
		}
		if len(item.Contextual) > 0 {
			keys := make([]fgaWireTupleKey, 0, len(item.Contextual))
			for _, t := range item.Contextual {
				keys = append(keys, fgaWireTupleKey{User: t.User, Relation: t.Relation, Object: t.Object})
			}
			wire.ContextualTuples = &fgaWireContextualTuples{TupleKeys: keys}
		}
		req.Checks = append(req.Checks, wire)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("openfga batch-check encode: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, c.batchCheckTimeout())
	defer cancel()
	resp, err := c.do(cctx, "POST",
		fmt.Sprintf("http://%s/stores/%s/batch-check", c.Endpoint, c.StoreID), body)
	if err != nil {
		return nil, fmt.Errorf("openfga batch-check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain (capped) before Close so the keep-alive connection returns to the
		// idle pool — same reuse rationale as the sibling Check paths.
		msg := cappedBody(resp)
		return nil, fmt.Errorf("openfga batch-check: status %d: %s", resp.StatusCode, msg)
	}

	var r fgaWireBatchCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("openfga batch-check decode: %w", err)
	}
	// The response is a MAP keyed by correlation id, so alignment is by lookup,
	// never by iteration order. A missing key is refused rather than defaulted to
	// false: a page filtered by a defaulted verdict is short in a way the caller
	// cannot detect, which is exactly what this whole package exists to prevent.
	out := make([]bool, len(items))
	for i := range items {
		verdict, ok := r.Result[strconv.Itoa(i)]
		if !ok {
			return nil, fmt.Errorf(
				"openfga batch-check: no verdict for check %d of %d (relation %q)",
				i, len(items), relation)
		}
		out[i] = verdict.Allowed
	}
	return out, nil
}
