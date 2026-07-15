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
//	"already_exists" on write    → ErrAlreadyApplied   (HTTP 400 idempotent)
//	"cannot_delete" on delete    → ErrAlreadyApplied   (HTTP 400 idempotent)
//	other 400 / "validation_…"   → ErrPermanent        (bad tuple shape, retry futile)
//	5xx, network drop, timeout   → propagated raw      (transient — drainer retries)
//	unknown event_type           → ErrPermanent        (caller-side bug, retry futile)
//
// Why text-pattern matching and not a typed error: the underlying
// OpenFGAHTTPClient currently surfaces FGA replies as fmt.Errorf strings
// ("openfga write: status 400: …" / "openfga write: bad request: …"). Until
// that adapter is reworked to return typed errors, sniffing the substring is
// the only reliable way to distinguish idempotent-already-applied from a
// genuine poison or transient. Test coverage in fga_applier_test.go pins
// the exact wire strings we depend on.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
)

// FGAOutboxEvent is the typed payload of one row in `kacho_iam.fga_outbox`.
// Matches the JSON shape written by bootstrap_admin.go and by
// AccessBindingService.Create/Delete, JIT auto-grant, and BreakGlass.ApproveB.
type FGAOutboxEvent struct {
	User     string `json:"user"`     // e.g. "user:usr01"
	Relation string `json:"relation"` // e.g. "system_admin"
	Object   string `json:"object"`   // e.g. "cluster:default"
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
	if e.User == "" || e.Relation == "" || e.Object == "" {
		return FGAOutboxEvent{}, fmt.Errorf(
			"%w: fga_outbox: incomplete tuple (user=%q relation=%q object=%q)",
			drainer.ErrPermanent, e.User, e.Relation, e.Object)
	}
	return e, nil
}

// NewFGAApplier returns a drainer.Applier[FGAOutboxEvent] backed by the given
// RelationStore. Caller wires it into drainer.New[clients.FGAOutboxEvent](pool,
// cfg, clients.DecodeFGAOutboxEvent, clients.NewFGAApplier(fga), logger).
func NewFGAApplier(fga RelationStore) drainer.Applier[FGAOutboxEvent] {
	return func(ctx context.Context, eventType string, e FGAOutboxEvent) error {
		tup := []RelationTuple{{User: e.User, Relation: e.Relation, Object: e.Object}}
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
