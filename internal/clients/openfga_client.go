// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package clients — peer-сервисов клиенты (адаптеры).
//
// openfga_client.go — port-iface + HTTP impl для openfga операций
// (Check / Write / Delete / Read / ListObjects / Expand). In-memory stub
// lives in openfga_stub_test.go (test-only, never compiled into production).
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RelationTuple — стандартный FGA tuple struct.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

// RelationStore — port-iface для openfga-операций.
type RelationStore interface {
	// Check выполняет authorization check.
	Check(ctx context.Context, subject, relation, object string) (allowed bool, err error)

	// WriteTuples атомарно записывает batch tuples. Idempotent: уже существующий
	// tuple (400 already_exists) = success. Конкурентный transactional abort
	// (409) — НЕ success: ничего не записано; транспорт повторяет его с jitter'ом
	// и, если конфликт пережил бюджет, возвращает ErrWriteConflict (см.
	// openfga_conflict.go), который вызывающий обязан классифицировать как
	// retryable, а не как «уже применено».
	WriteTuples(ctx context.Context, tuples []RelationTuple) error

	// DeleteTuples удаляет batch tuples. Idempotent НА УРОВНЕ НАБОРА: постусловие —
	// «ни одного из этих tuple в сторе нет». Batch применяется транзакционно, но если
	// OpenFGA отверг его из-за уже отсутствующего tuple (частый исход частичного дренажа
	// fga_outbox — транзакционный replay такого запроса не пройдет НИКОГДА), адаптер
	// разбивает набор на однокортежные удаления, где «уже нет» — корректный успех.
	// Конкурентный transactional abort (409) — как у WriteTuples: retryable, не success.
	DeleteTuples(ctx context.Context, tuples []RelationTuple) error
}

// (OpenFGAStubClient lives in openfga_stub_test.go — test-only.)

// ── HTTP REST implementation ──────────────────────────────────────────────

// OpenFGAHTTPClient — HTTP wrapper over the OpenFGA REST API
// (POST /stores/{id}/check, /write, /list-objects, /read, /expand).
//
// Per-operation timeouts are instance fields (not package-level vars) so they
// are populated by the composition root, not at package init() time. A zero
// value falls back to the defaults in openfga_extended.go (fgaTimeout).
type OpenFGAHTTPClient struct {
	Endpoint           string
	StoreID            string
	AuthorizationModel string

	// CheckTimeout / ListTimeout / WriteTimeout — per-operation context
	// deadlines. Zero ⇒ package defaults (see openfga_extended.go).
	CheckTimeout time.Duration
	ListTimeout  time.Duration
	WriteTimeout time.Duration
}

// ErrNotConfigured — returned by the HTTP methods if Endpoint/StoreID are
// empty. The composition root (cmd/kacho-iam) fails fast before constructing
// the client, so this only guards against a programmer wiring error.
var ErrNotConfigured = errors.New("openfga: HTTP client not configured")

type openfgaWriteRequest struct {
	AuthorizationModelID string `json:"authorization_model_id,omitempty"`
	Writes               *struct {
		TupleKeys []openfgaTupleKey `json:"tuple_keys"`
	} `json:"writes,omitempty"`
	Deletes *struct {
		TupleKeys []openfgaTupleKey `json:"tuple_keys"`
	} `json:"deletes,omitempty"`
}

type openfgaTupleKey struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type openfgaCheckRequest struct {
	AuthorizationModelID string          `json:"authorization_model_id,omitempty"`
	TupleKey             openfgaTupleKey `json:"tuple_key"`
	// Consistency — optional OpenFGA read-consistency preference. Empty ⇒ field
	// omitted ⇒ OpenFGA default (MINIMIZE_LATENCY). Set to
	// consistencyHigherConsistency only for the read-after-own-write confirm probe.
	Consistency string `json:"consistency,omitempty"`
}

type openfgaCheckResponse struct {
	Allowed bool `json:"allowed"`
}

// Check — per-RPC authz Check at OpenFGA's default (MINIMIZE_LATENCY) consistency:
// the hot enforcement gate stays cache/replica-eligible (low latency).
func (c *OpenFGAHTTPClient) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return c.check(ctx, subject, relation, object, "")
}

// CheckConsistent — Check forcing HIGHER_CONSISTENCY (strong read-after-write). Used
// by the owner-tuple confirm-gate (in-process iam probe): the tuple was written to
// the SAME store on this create path, so the probe must not be served a stale
// negative from a lagging replica. Idempotent / read-only, same contract as Check.
func (c *OpenFGAHTTPClient) CheckConsistent(ctx context.Context, subject, relation, object string) (bool, error) {
	return c.check(ctx, subject, relation, object, consistencyHigherConsistency)
}

// check is the shared Check transport; consistency is the OpenFGA `consistency`
// wire value ("" ⇒ omitted ⇒ default MINIMIZE_LATENCY).
func (c *OpenFGAHTTPClient) check(ctx context.Context, subject, relation, object, consistency string) (bool, error) {
	if c.Endpoint == "" || c.StoreID == "" {
		return false, ErrNotConfigured
	}
	// Bound the per-RPC authz Check to the configured CheckTimeout (default 200ms):
	// fgaHTTPClient carries no client-level Timeout BY DESIGN (the per-operation
	// budgets differ by an order of magnitude — see openfga_transport.go), so an
	// OpenFGA that accepts the TCP connection but stops responding (GC pause /
	// overload / half-open TCP after a partition) would otherwise hang the
	// authz-interceptor goroutine forever instead of failing closed within the FGA
	// budget (D-47 "FGA outage → Unavailable"). Mirrors the sibling
	// CheckWithContext / c.do() paths, which are already time-bounded.
	cctx, cancel := context.WithTimeout(ctx, c.checkTimeout())
	defer cancel()
	body, _ := json.Marshal(openfgaCheckRequest{
		AuthorizationModelID: c.AuthorizationModel,
		TupleKey:             openfgaTupleKey{User: subject, Relation: relation, Object: object},
		Consistency:          consistency,
	})
	req, _ := http.NewRequestWithContext(cctx, http.MethodPost,
		fmt.Sprintf("http://%s/stores/%s/check", c.Endpoint, c.StoreID),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := fgaHTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("openfga check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		//: a 400 is a client-side validation error (relation absent
		// on the object type, typed-wildcard object, ...) — such a Check can
		// never resolve, so it is a clean DENY, not an outage.
		// Drain (capped) before Close so the keep-alive connection returns to
		// the idle pool instead of being torn down — mirrors the sibling
		// writeOrDelete / listUsersOfType drain paths. Critical on the hot
		// authz path: a degraded OpenFGA emitting a burst of 400s must not also
		// churn fresh TCP connections (fd + TLS/handshake pressure).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Same drain-for-reuse rationale as the 400 branch above: a degraded
		// OpenFGA returning 5xx on every Check must not churn connections.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBodyBytes))
		return false, fmt.Errorf("openfga check: status %d", resp.StatusCode)
	}
	var r openfgaCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return false, fmt.Errorf("openfga check decode: %w", err)
	}
	return r.Allowed, nil
}

// maxTuplesPerWriteRequest mirrors OpenFGA's default maxTuplesPerWrite (100): a
// single /write request may carry at most this many tuple_keys or OpenFGA rejects
// the WHOLE request with a 400 validation_error and applies NONE of them. The
// reconciler's create-path synchronous write (reconcile.applyAfterCommit) batches the
// entire tuple-set of one ReconcileObject pass, which exceeds 100 when the object is
// matched by multiple bounded `*.*` ARM_ANCHOR bindings on a populated account (the
// iam-access-binding read-after-write tail, #232). Chunking here keeps the sync-FGA
// reconciler path (WriteTuples/DeleteTuples) under the wire limit; the async fga_outbox
// drainer already applies row-by-row, so it is unaffected. The admin WriteRaw path
// (WriteConditionalTuples) does NOT chunk — it is bounded instead by the
// InternalAuthorize.WriteTuples handler's per-batch guard, which must count
// writes+deletes COMBINED against this same wire cap (OpenFGA's maxTuplesPerWrite counts
// both directions in one request). Set to exactly OpenFGA's documented
// default (100); the deploy does not lower the server limit (no maxTuplesPerWrite
// override in the umbrella chart).
const maxTuplesPerWriteRequest = 100

func (c *OpenFGAHTTPClient) WriteTuples(ctx context.Context, tuples []RelationTuple) error {
	return c.writeOrDeleteChunked(ctx, tuples, true)
}

func (c *OpenFGAHTTPClient) DeleteTuples(ctx context.Context, tuples []RelationTuple) error {
	return c.writeOrDeleteChunked(ctx, tuples, false)
}

// writeOrDeleteChunked splits the tuple-set into ≤maxTuplesPerWriteRequest batches and
// applies each in its own OpenFGA request, so a large fan-out is not rejected wholesale
// by OpenFGA's per-request limit. Each chunk keeps the idempotent already_exists /
// cannot_delete semantics of writeOrDelete; a chunk error aborts the rest (the
// at-least-once fga_outbox enqueue committed in the writer-tx is the backstop, and the
// caller — applyAfterCommit — logs best-effort).
func (c *OpenFGAHTTPClient) writeOrDeleteChunked(ctx context.Context, tuples []RelationTuple, write bool) error {
	if len(tuples) == 0 {
		return nil
	}
	for start := 0; start < len(tuples); start += maxTuplesPerWriteRequest {
		end := start + maxTuplesPerWriteRequest
		if end > len(tuples) {
			end = len(tuples)
		}
		if err := c.writeOrDelete(ctx, tuples[start:end], write); err != nil {
			return err
		}
	}
	return nil
}

// writeOrDelete applies ONE ≤maxTuplesPerWriteRequest batch, retrying while
// OpenFGA aborts the transaction on a concurrent-write conflict (409 — nothing
// applied, safe to replay; see openfga_conflict.go). Every attempt carries its
// own WriteTimeout deadline.
func (c *OpenFGAHTTPClient) writeOrDelete(ctx context.Context, tuples []RelationTuple, write bool) error {
	err := c.applyBatch(ctx, tuples, write)
	if err == nil || len(tuples) == 1 {
		return err
	}
	if write {
		// ONE GRANT ONLY, and this condition is the whole safety of the branch below.
		//
		// A batch rejected because ≥1 of its tuples is already there applied NOTHING,
		// and a verbatim replay can never succeed — so somebody has to finish the job.
		// WHO finishes it depends on what the batch was:
		//
		//   - one subject's set on ONE object (the fga_outbox applier's row): the caller
		//     has no read of its own and no way to split the work without splitting the
		//     grant, so the completion happens here, and it happens in ONE write of the
		//     missing subset — never tuple by tuple, which would put the half-present
		//     grant back exactly where it was;
		//   - MANY objects in one packed request (the reconciler's sync writer): the
		//     caller owns a per-object resilient path with its own read-delta
		//     (reconcile_adapter.go applyObject → reconcileObjectDelta), and it is
		//     entitled to see the rejection so it can enter it. Completing here instead
		//     would spread one object's relations across separate requests and destroy
		//     the per-object atomicity that path exists to keep.
		//
		// Getting this wrong is not hypothetical: without the guard, a packed chunk of a
		// dozen objects would fall into a per-tuple loop and report success, the resilient
		// path would never be entered, and the creator could read its fresh object but not
		// change it — the very defect the set-shaped row was introduced to remove.
		if !writeRejectedAsExisting(err) || !singleGrant(tuples) {
			return err
		}
		return c.completeGrant(ctx, tuples)
	}
	if !deleteRejectedAsAbsent(err) {
		return err
	}
	// A DELETE batch rejected because ≥1 of its tuples is already gone. OpenFGA's write
	// is TRANSACTIONAL, so nothing was removed, and — unlike a 409 conflict — replaying
	// the identical request can NEVER succeed: the absent tuple stays absent. Because
	// the async fga_outbox drainer applies revoke rows independently, "one of them is
	// already gone" is the ordinary outcome of a partial drain, not an exotic one; before
	// this the access_binding revoke burned its six bounded retries (~3s of worker time)
	// on an impossible request every single time and left the batch's still-live tuples
	// standing until the drainer caught up.
	//
	// Decompose instead of widening the shortcut: "already absent" proves the caller's
	// post-condition only for a request carrying exactly ONE tuple (for a batch it
	// proves the OTHERS did not land), so re-issue each tuple as its own single-tuple
	// delete — precisely the shape where that reading is sound.
	return c.applyEachTuple(ctx, tuples, false)
}

// applyBatch issues ONE request for the given tuples and returns its reply verbatim.
// It carries NO completion policy: the decision of what a rejected batch means, and who
// finishes it, belongs to writeOrDelete above.
//
// The split is not cosmetic. The completion path re-enters the writer for the missing
// subset; when both lived in one function each re-entry hit the same policy branch and
// the two called each other until the test process was killed by its own deadline.
func (c *OpenFGAHTTPClient) applyBatch(ctx context.Context, tuples []RelationTuple, write bool) error {
	if c.Endpoint == "" || c.StoreID == "" {
		return ErrNotConfigured
	}
	if len(tuples) == 0 {
		return nil
	}
	keys := make([]openfgaTupleKey, 0, len(tuples))
	for _, t := range tuples {
		keys = append(keys, openfgaTupleKey(t))
	}
	r := openfgaWriteRequest{AuthorizationModelID: c.AuthorizationModel}
	if write {
		r.Writes = &struct {
			TupleKeys []openfgaTupleKey `json:"tuple_keys"`
		}{TupleKeys: keys}
	} else {
		r.Deletes = &struct {
			TupleKeys []openfgaTupleKey `json:"tuple_keys"`
		}{TupleKeys: keys}
	}
	body, _ := json.Marshal(r)
	// Idempotent replay: writing a tuple that already exists, or deleting one that
	// no longer exists, is a success at the adapter — the desired post-condition
	// already holds. On 400 we MUST read the body so this FGA vocabulary reaches
	// the caller — otherwise a bare "status 400" is mis-classified as a permanent
	// poison by fga_applier.classifyFGA*Err.
	//
	// SINGLE-TUPLE ONLY. OpenFGA's write is TRANSACTIONAL: a rejected request
	// applies NONE of its tuples. So "this tuple already exists" equals "the
	// desired post-condition holds" ONLY when the request carried exactly that one
	// tuple (the hierarchy-tuple and creator-tuple writers, and any single-relation
	// row of the fga_outbox drainer). For a BATCH the same reply means the OTHER
	// tuples did not land — reporting success here would silently lose them. What
	// finishes such a batch is decided one level up, in writeOrDelete: a single
	// grant is completed by read-then-write-missing, a packed multi-object request
	// is handed back to the caller's own per-object read-delta.
	var idempotent func(string) bool
	if len(tuples) == 1 {
		idempotent = idempotentDeleteReply
		if write {
			idempotent = idempotentWriteReply
		}
	}
	err := applyWithConflictRetry(ctx, func(ctx context.Context) error {
		// Bound EVERY attempt to the configured WriteTimeout (default 1s):
		// fgaHTTPClient carries no client-level Timeout BY DESIGN (see
		// openfga_transport.go), so an OpenFGA that accepts the
		// TCP connection but stops responding (GC pause / overload / half-open
		// TCP after a partition) would otherwise hang the calling goroutine
		// forever — especially harmful for the detached, deadline-less
		// access_binding revoke retry loop (delete.go syncRemoveTuples), which
		// has no caller-side deadline to fall back on. Mirrors the sibling
		// Check / WriteConditionalTuples paths, which are already time-bounded.
		cctx, cancel := context.WithTimeout(ctx, c.writeTimeout())
		defer cancel()
		req, _ := http.NewRequestWithContext(cctx, http.MethodPost,
			fmt.Sprintf("http://%s/stores/%s/write", c.Endpoint, c.StoreID),
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := fgaHTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("openfga write: %w", err)
		}
		defer resp.Body.Close()
		return readWriteReply(resp, idempotent)
	})
	return err
}

// singleGrant reports whether every tuple names the same (subject, object) — i.e.
// whether the batch IS one grant, the unit that must reach the store whole.
func singleGrant(tuples []RelationTuple) bool {
	for i := 1; i < len(tuples); i++ {
		if tuples[i].User != tuples[0].User || tuples[i].Object != tuples[0].Object {
			return false
		}
	}
	return len(tuples) > 0
}

// maxGrantCompletionRounds bounds the read→write-missing rounds. Each round that
// ends in "already exists" proves a racing writer COMMITTED at least one tuple of
// the missing set, so the next (strong) read sees it and the set strictly shrinks —
// the budget is therefore derived from the set size, not guessed, and one extra
// round pays for the final clean write.
func maxGrantCompletionRounds(n int) int { return n + 1 }

// completeGrant finishes ONE grant whose batch write was rejected because part of it
// already exists: it reads what the subject already holds on the object and writes
// ONLY the missing subset, in a single transactional request.
//
// Why a read and not a per-tuple loop: the post-condition this adapter promises is
// "all of these tuples are in the store", and the reason the set travels together is
// that a caller must never observe it half-present. Writing the members one by one
// would satisfy the post-condition and violate the reason.
//
// STRONG read: this is the read half of a read-modify-write whose termination depends
// on observing the racer's commit. A replica-lagged read would leave the missing set
// unchanged round after round.
func (c *OpenFGAHTTPClient) completeGrant(ctx context.Context, tuples []RelationTuple) error {
	subject, object := tuples[0].User, tuples[0].Object
	budget := maxGrantCompletionRounds(len(tuples))
	for round := 0; round < budget; round++ {
		have, err := c.readGrant(ctx, subject, object)
		if err != nil {
			return err
		}
		missing := make([]RelationTuple, 0, len(tuples))
		for _, t := range tuples {
			if _, ok := have[t]; !ok {
				missing = append(missing, t)
			}
		}
		if len(missing) == 0 {
			return nil // the whole grant is present — the post-condition holds.
		}
		// applyBatch, NOT writeOrDelete: this IS the completion, and re-entering the
		// policy branch that dispatched here would make the two call each other without
		// end (each nested call gets a fresh budget, so the loop bound below does not
		// bound the recursion).
		err = c.applyBatch(ctx, missing, true)
		if err == nil {
			return nil
		}
		if !writeRejectedAsExisting(err) {
			return err
		}
		// A racer committed ≥1 of the missing tuples; the next strong read sees it.
	}
	return fmt.Errorf("openfga write: grant %s on %s did not converge in %d rounds",
		subject, object, budget)
}

// readGrant returns the tuples the subject already holds on the object, filtered
// server-side by (subject, object) so the reply stays small. Pagination is followed to
// a bound; a grant is a handful of relations, and the bound is defensive.
func (c *OpenFGAHTTPClient) readGrant(ctx context.Context, subject, object string) (map[RelationTuple]struct{}, error) {
	const (
		pageSize = 50
		maxPages = 20
	)
	have := make(map[RelationTuple]struct{})
	token := ""
	for page := 0; page < maxPages; page++ {
		tuples, next, err := c.ReadTuplesStrong(ctx, subject, "", object, pageSize, token)
		if err != nil {
			return nil, fmt.Errorf("openfga read grant %s on %s: %w", subject, object, err)
		}
		for _, t := range tuples {
			have[RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}] = struct{}{}
		}
		if next == "" {
			break
		}
		token = next
	}
	return have, nil
}

// applyEachTuple re-issues every tuple of a rejected batch as its OWN single-tuple
// request, where "already gone" degrades to the idempotent success the adapter
// contract promises.
//
// REVOKE DIRECTION ONLY. Removing access one tuple at a time is safe in a way that
// GRANTING one tuple at a time is not: every tuple removed is access denied, so an
// interrupted decomposition leaves LESS access, never a half-present grant somebody
// can act on. The grant direction therefore completes by read-then-write-missing
// instead (completeGrant above).
//
// It does NOT stop at the first failure: a revoke must remove as much as it can, and
// the tuples are independent once the batch is decomposed. The FIRST genuine error is
// returned so the caller still sees the failure and its retry / durable fga_outbox
// backstop still runs.
func (c *OpenFGAHTTPClient) applyEachTuple(ctx context.Context, tuples []RelationTuple, write bool) error {
	var firstErr error
	for i := range tuples {
		// len==1 ⇒ the single-tuple idempotent path; no further decomposition (no recursion).
		if err := c.writeOrDelete(ctx, tuples[i:i+1], write); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

var _ RelationStore = (*OpenFGAHTTPClient)(nil)
