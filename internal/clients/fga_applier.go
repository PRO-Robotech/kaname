// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_applier.go — concrete drainer.Applier[FGAOutboxEvent] over an
// RelationStore.
//
// kacho-iam half of the fga_outbox drainer. Translates each row of
// `kacho_iam.fga_outbox` into an RelationStore.WriteTuples / DeleteTuples
// call and maps the FGA error vocabulary onto the drainer's three-way
// classification:
//
//	nil                       → drainer marks sent_at (happy path)
//	drainer.ErrAlreadyApplied → drainer marks sent_at (idempotent success)
//	drainer.ErrPermanent      → drainer marks attempt_count = MaxAttempts (poison)
//	anything else             → drainer retries with exp backoff (transient)
//
// FGA error mapping:
//
//	"already_exists" on write    → ErrAlreadyApplied   (HTTP 400 idempotent). Reaches
//	                               this classifier only for a SINGLE-tuple request:
//	                               the adapter decomposes a rejected multi-tuple batch
//	                               per tuple first, because for a batch that same reply
//	                               proves only that SOME member was present.
//	"cannot_delete" on delete    → ErrAlreadyApplied   (HTTP 400 idempotent)
//	ErrWriteConflict (HTTP 409)  → propagated raw      (transient — see below)
//	other 400 / "validation_…"   → ErrPermanent        (bad tuple shape, retry futile)
//	5xx, network drop, timeout   → propagated raw      (transient — drainer retries)
//	unknown event_type           → ErrPermanent        (caller-side bug, retry futile)
//
// The 409 transactional abort is emphatically NOT ErrAlreadyApplied: the aborted
// transaction applied NOTHING, so marking the row sent_at would silently drop the
// tuple and leave a permanent authz gap. It is not permanent either — the retry
// is what resolves it. (The transport already absorbs the common case with a
// short jittered retry, so a conflict reaching the applier means the racer is
// still active and the outbox backoff is the right next step.)
//
// Why text-pattern matching for the 400-class: the underlying OpenFGAHTTPClient
// surfaces those FGA replies as fmt.Errorf strings ("openfga write: status 400: …"
// / "openfga write: bad request: …"). Until that adapter returns a typed error for
// each 400 sub-case, sniffing the substring is the only reliable way to
// distinguish idempotent-already-applied from a genuine poison or transient. Test
// coverage in fga_applier_test.go pins the exact wire strings we depend on. The
// CONFLICT class is already typed (ErrWriteConflict) and is matched with
// errors.Is, not by text.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

// FGAOutboxEvent is the typed payload of one row in `kacho_iam.fga_outbox`.
//
// A row names ONE SUBJECT AND ONE OBJECT and carries either a single relation
// (`relation`, the historical shape every one-relation emitter still writes) or the
// subject's WHOLE relation set on that object (`relations`). When both are present
// the SET is the unit and `relation` is a compatibility echo — see
// DecodeFGAOutboxEvent, which is where that is decided and checked.
//
// The set form exists because the row is the unit that reaches OpenFGA atomically:
// a grant split across rows is applied across calls, and in between it is HALF
// PRESENT — the subject may read the object it has just created and may not change
// it. tuples() renders what the applier writes, so the set moves as one.
type FGAOutboxEvent struct {
	User      string   `json:"user"`                // e.g. "user:usr01"
	Relation  string   `json:"relation,omitempty"`  // single-relation form, e.g. "system_admin"
	Relations []string `json:"relations,omitempty"` // set form, e.g. ["v_get","v_update"]
	Object    string   `json:"object"`              // e.g. "cluster:default"
}

// relationSet returns the row's relation set in emit order — one element for the
// single-relation form, the whole set otherwise.
func (e FGAOutboxEvent) relationSet() []string {
	if len(e.Relations) > 0 {
		return e.Relations
	}
	return []string{e.Relation}
}

// tuples renders the row as the tuple set to apply in ONE call.
func (e FGAOutboxEvent) tuples() []RelationTuple {
	rels := e.relationSet()
	out := make([]RelationTuple, 0, len(rels))
	for _, r := range rels {
		out = append(out, RelationTuple{User: e.User, Relation: r, Object: e.Object})
	}
	return out
}

// Outbox event_type constants — single source of truth for the writer side
// (bootstrap_admin, AccessBindingService, …) and reader side (this applier).
const (
	FGAEventTypeWrite  = "fga.tuple.write"
	FGAEventTypeDelete = "fga.tuple.delete"
)

// DecodeFGAOutboxEvent is the drainer.Decoder[FGAOutboxEvent] for
// `kacho_iam.fga_outbox`.payload. Any malformed JSON or missing required
// field wraps drainer.ErrPermanent → drainer poisons the row instead of
// retrying forever.
func DecodeFGAOutboxEvent(payload []byte) (FGAOutboxEvent, error) {
	var e FGAOutboxEvent
	if err := json.Unmarshal(payload, &e); err != nil {
		return FGAOutboxEvent{}, fmt.Errorf("%w: fga_outbox: invalid json: %s", drainer.ErrPermanent, err)
	}
	if e.User == "" || e.Object == "" {
		return FGAOutboxEvent{}, fmt.Errorf(
			"%w: fga_outbox: incomplete row (user=%q object=%q)",
			drainer.ErrPermanent, e.User, e.Object)
	}
	if e.Relation == "" && len(e.Relations) == 0 {
		return FGAOutboxEvent{}, fmt.Errorf(
			"%w: fga_outbox: row names no relation (user=%q object=%q)",
			drainer.ErrPermanent, e.User, e.Object)
	}
	member := false
	for _, r := range e.Relations {
		if r == "" {
			return FGAOutboxEvent{}, fmt.Errorf(
				"%w: fga_outbox: empty relation in set (user=%q object=%q relations=%v)",
				drainer.ErrPermanent, e.User, e.Object, e.Relations)
		}
		member = member || r == e.Relation
	}
	// `relation` alongside a set is the COMPATIBILITY ECHO the emitter writes so a
	// reader that predates the set form still finds a decodable row instead of
	// poisoning it (see fga_outbox.emitTx). It is ignored — `relations` is the unit —
	// but it must name a member of the set: an echo that points outside it would mean
	// the two readers apply different things, which is the one outcome neither shape
	// is allowed to produce.
	if len(e.Relations) > 0 && e.Relation != "" && !member {
		return FGAOutboxEvent{}, fmt.Errorf(
			"%w: fga_outbox: `relation` %q is not a member of the row's set %v (user=%q object=%q)",
			drainer.ErrPermanent, e.Relation, e.Relations, e.User, e.Object)
	}
	return e, nil
}

// NewFGAApplier returns a drainer.Applier[FGAOutboxEvent] backed by the given
// RelationStore. Caller wires it into drainer.New[clients.FGAOutboxEvent](pool,
// cfg, clients.DecodeFGAOutboxEvent, clients.NewFGAApplier(fga), logger).
func NewFGAApplier(fga RelationStore) drainer.Applier[FGAOutboxEvent] {
	return func(ctx context.Context, eventType string, e FGAOutboxEvent) error {
		// ONE call for the whole row: the row IS the atomic unit (see FGAOutboxEvent).
		// Splitting it here would put the partial state back exactly where it was.
		tup := e.tuples()
		switch eventType {
		case FGAEventTypeWrite:
			err := fga.WriteTuples(ctx, tup)
			return classifyFGAWriteErr(err)
		case FGAEventTypeDelete:
			err := fga.DeleteTuples(ctx, tup)
			return classifyFGADeleteErr(err)
		default:
			return fmt.Errorf("%w: fga_outbox: unknown event_type %q", drainer.ErrPermanent, eventType)
		}
	}
}

// classifyFGAWriteErr maps OpenFGA's reply to the drainer's three-way
// classification for the `fga.tuple.write` case.
//
//	nil                      → nil
//	contains "already_exists" → ErrAlreadyApplied (idempotent: tuple already there)
//	contains "validation_"
//	  or "is undefined"
//	  or "type_not_found"     → ErrPermanent (bad tuple shape — retry can't fix)
//	otherwise                 → raw (treated as transient by drainer)
func classifyFGAWriteErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case IsWriteConflict(err):
		// Transactional abort: NOTHING was applied. Explicit branch (before the
		// permanent-marker scan) so the conflict can never be mistaken for either
		// an idempotent success — which would drop the tuple — or a poison.
		return err
	case containsAny(msg, "already_exists", "already exists"):
		// Wrap with %w so errors.Is(out, ErrAlreadyApplied) ≡ true while
		// preserving the original error text for observability/logs.
		return fmt.Errorf("%w: fga write reports duplicate: %s", drainer.ErrAlreadyApplied, msg)
	case isFGAPermanentMsg(msg):
		return fmt.Errorf("%w: fga write rejected (no retry): %s", drainer.ErrPermanent, msg)
	default:
		// Transient — propagate raw. Drainer will retry with exp backoff.
		return err
	}
}

// classifyFGADeleteErr — same shape as classifyFGAWriteErr but for delete.
// "cannot_delete" / "does not exist" → ErrAlreadyApplied (the desired
// post-condition — tuple absent — is already met).
func classifyFGADeleteErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case IsWriteConflict(err):
		// Transactional abort: the tuple is still there. Retry (see the write twin).
		return err
	case containsAny(msg, "cannot_delete", "does not exist", "not_found", "not found"):
		return fmt.Errorf("%w: fga delete reports tuple absent: %s", drainer.ErrAlreadyApplied, msg)
	case isFGAPermanentMsg(msg):
		return fmt.Errorf("%w: fga delete rejected (no retry): %s", drainer.ErrPermanent, msg)
	default:
		return err
	}
}

// isFGAPermanentMsg detects OpenFGA 400-class validation errors whose retry
// will never succeed (bad tuple shape, undefined type/relation in the model).
//
// IMPORTANT: this check runs AFTER the idempotent-success patterns
// ("already_exists", "cannot_delete", …), so a 400 reply carrying those
// markers is NOT misclassified as permanent — the caller already returned
// ErrAlreadyApplied for them in classifyFGA{Write,Delete}Err.
func isFGAPermanentMsg(msg string) bool {
	return containsAny(msg,
		// OpenFGA validation-error markers.
		"validation_error", "validation_failed",
		"type_not_found", "is undefined in the authorization model",
		"relation_not_found", "relation is undefined",
		"invalid_input",
		// Generic 400 marker — last-resort. Comes AFTER the explicit
		// idempotent checks above, so a 400 with "already_exists" body is
		// already short-circuited as ErrAlreadyApplied.
		"status 400", "bad request",
	)
}

// containsAny — case-insensitive substring scan.
func containsAny(haystack string, needles ...string) bool {
	low := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// Compile-time guard — ensure the returned Applier matches the drainer's
// generic Applier[FGAOutboxEvent] type. If the drainer signature changes,
// this fails to compile here rather than at the wiring site in main.go.
var _ drainer.Applier[FGAOutboxEvent] = NewFGAApplier(nil)

// Compile-time guard — ensure DecodeFGAOutboxEvent matches drainer.Decoder.
var _ drainer.Decoder[FGAOutboxEvent] = DecodeFGAOutboxEvent
