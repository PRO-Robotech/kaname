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

	apigatewayv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/apigateway/v1"
	"github.com/PRO-Robotech/kacho/pkg/authz"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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

	// SubjectType — FGA object type of the subject: user | service_account |
	// group. Written by every emit site (which knows it); absent only on rows
	// committed before the field existed, and those fall back to naming the
	// type from the id prefix — see subjectTypeOf.
	SubjectType string `json:"subject_type,omitempty"`

	// EventType — canonical event tag (binding_revoke / binding_grant /
	// group_member_change). When empty, decoder derives from Op alias
	// (binding_delete→binding_revoke, binding_upsert→binding_grant).
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
		// Name the subject the way the EDGE keys its verdict cache. Failing to
		// name it is NOT an invalidation we performed: sending an unnameable
		// string drops zero entries, the edge answers NotFound, and NotFound is
		// idempotent success below — which would stamp the row sent and lose the
		// revoke with no error anywhere. So this fails before the call.
		//
		// This queue is wired PermanentPolicy: drainer.RetryPermanent, so the row
		// is NOT poisoned — it stays unsent and keeps retrying. That is the
		// intended trade for a revoke: the queue is commutative (no head-of-
		// partition claim), so a stuck row wedges nothing, and it stays visible in
		// the backlog depth and oldest-pending-age metrics. Loud and undelivered
		// beats silently delivered-and-lost. The path is defensive anyway — every
		// producer now writes subject_type, and rows written before it carry ids
		// whose minted prefix names the type.
		fga, err := fgaSubject(e)
		if err != nil {
			return errors.Join(drainer.ErrPermanent, err)
		}

		// Prefer drainer's column-scanned eventType (canonical source of truth).
		// Fall back to payload's EventType only if drainer somehow passes empty
		// string (shouldn't happen — defensive).
		et := eventType
		if et == "" {
			et = e.EventType
		}

		_, err = cli.InvalidateSubject(ctx, &apigatewayv1.InvalidateSubjectRequest{
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

// fgaSubject — subject id + type → the FGA-shaped string the edge keys by.
//
// Composition is delegated to authz.FormatObject: one canonical `<type>:<id>`
// writer for the whole product, which also rejects ids carrying FGA separators
// (':' shifts the type/id boundary, '#' forms a userset reference). A second
// hand-written spelling of the same value is what this function replaces.
//
// The type comes from the event. It is derived from the id ONLY for rows
// committed before the field existed, and a type that cannot be established is
// a terminal error — never a subject sent on a guess.
func fgaSubject(e SubjectChangeEvent) (string, error) {
	t := e.SubjectType
	if t == "" {
		var ok bool
		if t, ok = subjectTypeOf(e.SubjectID); !ok {
			return "", fmt.Errorf(
				"subject_change: cannot name subject %q — no subject_type on the row and "+
					"the id carries no known subject prefix; invalidation would drop nothing",
				e.SubjectID)
		}
	}
	if !knownSubjectType(t) {
		return "", fmt.Errorf("subject_change: unknown subject_type %q for subject %q", t, e.SubjectID)
	}
	return authz.FormatObject(t, e.SubjectID)
}

// knownSubjectType — CLOSED vocabulary. No "everything else" bucket: an
// unrecognised type must not be concatenated into a subject string, because the
// resulting string names nothing and fails silently (the edge simply has no such
// key).
func knownSubjectType(t string) bool {
	switch domain.SubjectType(t) {
	case domain.SubjectTypeUser, domain.SubjectTypeServiceAccount, domain.SubjectTypeGroup:
		return true
	default:
		return false
	}
}

// subjectTypeOf — legacy path: name the type from the id prefix.
//
// Prefixes are the ones ids.NewID actually mints — exactly three characters,
// immediately followed by crockford-base32 with NO separator ("svatt493t8mxrgjzjh8n").
// The mapping that stood here matched "usr_"/"sva_"/"grp_" and therefore matched
// nothing the product produces; every fixture that made it look correct spelled
// subjects by hand.
func subjectTypeOf(subjectID string) (string, bool) {
	switch {
	case strings.HasPrefix(subjectID, domain.PrefixUser):
		return string(domain.SubjectTypeUser), true
	case strings.HasPrefix(subjectID, domain.PrefixServiceAccount):
		return string(domain.SubjectTypeServiceAccount), true
	case strings.HasPrefix(subjectID, domain.PrefixGroup):
		return string(domain.SubjectTypeGroup), true
	default:
		return "", false
	}
}

// Compile-time interface check: the function signatures conform to the
// drainer generics.
var (
	_ drainer.Decoder[SubjectChangeEvent] = DecodeSubjectChange
)
