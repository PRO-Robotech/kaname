// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cache_invalidation_applier.go — subject-change cache invalidation pipeline
// (kacho-iam half).
//
// Implements the kacho-corelib/outbox/drainer.Decoder + Applier contracts
// for the subject_change_outbox table. The drainer (wired in
// cmd/kacho-iam/main.go) reads rows pushed by the access_binding writer's
// EmitSubjectChangeEvent + JIT/BG emit-sites, decodes the payload jsonb
// into SubjectChangeEvent, then invokes
// api-gateway InternalAuthzCacheService.InvalidateSubject to drop the
// gateway's per-subject decision-cache entries within ≤ 1s of the revoke
// commit.
package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	apigatewayv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/apigateway/v1"
)

// SubjectChangeEvent — decoded payload of one subject_change_outbox row.
// Mirrors the JSON shape written by access_binding writer's
// EmitSubjectChangeEvent (kacho-iam/internal/repo/kacho/access_binding/iface.go).
//
// Drainer Decoder[T] receives ONLY payload bytes (NOT the other
// denormalised columns); therefore the payload MUST contain the full event
// shape. Migration 0023 backfills payload for every legacy row at upgrade
// time.
type SubjectChangeEvent struct {
	// SubjectID — raw (unprefixed) FGA subject id ("usr_alice" / "sva_bot" /
	// "grp_admins"). FGA-prefix mapping done by the applier
	// (fgaPrefixSwitch) before sending to gateway.
	SubjectID string `json:"subject_id"`

	// EventType — canonical event tag (binding_revoke / binding_grant /
	// jit_revoke / bg_revoke / group_member_change). When empty, decoder
	// derives from Op alias (binding_delete→binding_revoke,
	// binding_upsert→binding_grant).
	EventType string `json:"event_type"`

	// Op — legacy alias (informational; backward compat with the still-served
	// PollSubjectChanges RPC).
	Op string `json:"op"`

	// ResourceType / ResourceID — optional scope hint. MVP gateway ignores
	// them and invalidates per-subject (safe upper bound); per-resource
	// scope is a planned follow-up.
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

// DecodeSubjectChange — drainer.Decoder[SubjectChangeEvent].
//
// Drainer hands us ONLY the payload bytes from the `payload jsonb` column
// (NOT other row columns — that's a fundamental of the generic Drainer[T]
// contract; see kacho-corelib/outbox/drainer/drainer.go).
//
// Failure modes (all wrap drainer.ErrPermanent → drainer poisons the row,
// no retry):
//   - empty payload (defensive: a legacy writer committed an INSERT in a
//     race between ADD COLUMN and UPDATE-backfill; migration 0023 closes
//     this window but we fail-fast on the off chance);
//   - invalid JSON (corrupted column);
//   - empty subject_id (would inevitably trigger gateway InvalidArgument).
func DecodeSubjectChange(payload []byte) (SubjectChangeEvent, error) {
	var e SubjectChangeEvent
	if len(payload) == 0 {
		return e, errors.Join(drainer.ErrPermanent,
			errors.New("subject_change: payload IS NULL — legacy row not backfilled (operator: re-run UPDATE backfill from migration 0023)"))
	}
	if err := json.Unmarshal(payload, &e); err != nil {
		return e, errors.Join(drainer.ErrPermanent,
			fmt.Errorf("subject_change: invalid json payload: %w", err))
	}
	if e.SubjectID == "" {
		return e, errors.Join(drainer.ErrPermanent,
			errors.New("subject_change: subject_id empty"))
	}
	// Backward-compat: derive event_type from legacy op when missing
	// (defensive — migration 0023 backfill already does this in SQL).
	if e.EventType == "" {
		switch e.Op {
		case "binding_delete":
			e.EventType = "binding_revoke"
		case "binding_upsert":
			e.EventType = "binding_grant"
		default:
			e.EventType = e.Op
		}
	}
	return e, nil
}

// NewSubjectChangeApplier — drainer.Applier[SubjectChangeEvent].
//
// Calls api-gateway InternalAuthzCacheService.InvalidateSubject for each
// drained event. Error classification:
//
//   - gateway OK                  → nil (drainer marks sent_at)
//   - codes.NotFound              → drainer.ErrAlreadyApplied
//     (gateway reports "no cache entries for subject"; idempotent success)
//   - codes.InvalidArgument       → drainer.ErrPermanent (bad subject format)
//   - codes.Unavailable           → propagate raw (transient — drainer retries)
//   - codes.DeadlineExceeded      → propagate raw (transient)
//   - codes.Internal / other      → propagate raw (transient by default)
//
// The drainer-arg `eventType` (canonical value scanned from row's event_type
// column) is the single source of truth and overrides the decoded
// payload.EventType in case of drift.
func NewSubjectChangeApplier(cli apigatewayv1.InternalAuthzCacheServiceClient) drainer.Applier[SubjectChangeEvent] {
	return func(ctx context.Context, eventType string, e SubjectChangeEvent) error {
		// FGA-prefix the raw subject id (inline mapping; see fgaPrefixSwitch).
		fga := fgaPrefixSwitch(e.SubjectID)

		// Prefer drainer's column-scanned eventType (canonical source of truth).
		// Fall back to payload's EventType only if drainer somehow passes empty
		// string (shouldn't happen — defensive).
		et := eventType
		if et == "" {
			et = e.EventType
		}

		_, err := cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{
			Subject:      fga,
			ResourceType: e.ResourceType,
			ResourceId:   e.ResourceID,
			EventType:    et,
		})
		if err == nil {
			return nil
		}
		st, ok := status.FromError(err)
		if !ok {
			return err // network / unknown — transient
		}
		switch st.Code() {
		case codes.NotFound:
			// Gateway reports no entries for subject — idempotent success.
			return drainer.ErrAlreadyApplied
		case codes.InvalidArgument:
			return errors.Join(drainer.ErrPermanent, err)
		case codes.Unavailable, codes.DeadlineExceeded, codes.Internal:
			return err // transient — drainer retries with exp backoff
		default:
			return err // default: transient
		}
	}
}

// fgaPrefixSwitch — raw subject id → FGA-prefixed form.
//
// Tiny in-package mapper (3 prefixes — usr/sva/grp). Kept inline rather
// than in a corelib helper; will move once a second consumer emerges.
// Unknown prefix falls through as-is — the gateway will report NotFound
// (no cache entries) → ErrAlreadyApplied → row marked sent_at. Safe
// default for forward-compat with future subject types.
func fgaPrefixSwitch(subjectID string) string {
	switch {
	case strings.HasPrefix(subjectID, "usr_"):
		return "user:" + subjectID
	case strings.HasPrefix(subjectID, "sva_"):
		return "service_account:" + subjectID
	case strings.HasPrefix(subjectID, "grp_"):
		return "group:" + subjectID
	default:
		return subjectID
	}
}

// Compile-time interface check: the function signatures conform to the
// drainer generics.
var (
	_ drainer.Decoder[SubjectChangeEvent] = DecodeSubjectChange
)
