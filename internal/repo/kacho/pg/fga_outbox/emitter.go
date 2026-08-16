// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package fga_outbox — atomic emit-in-tx helper for kacho_iam.fga_outbox.
//
// Mirror of the SubjectChangeEmitter pattern
// (internal/repo/kacho/pg/subject_change_emitter.go).
//
// Background
//
//	Earlier every FGA tuple mutation in kacho-iam ran via a post-commit sync
//	call to RelationStore.WriteTuples/DeleteTuples (a non-fatal Warn on
//	failure). JIT auto-grant skipped FGA entirely. JIT pending Approve called
//	EmitSubjectErasure (CAEP deletion). BreakGlass.ApproveB never wrote
//	cluster_admin_grants. The cumulative effect — OpenFGA was NOT a reliable
//	source of authz truth.
//
//	All FGA mutations are now unified behind the `fga_outbox` table that
//	powers `bootstrap_admin.go` and the drainer (clients/fga_applier.go).
//	Each grant/revoke emits N rows into `kacho_iam.fga_outbox` in the SAME
//	pgx.Tx as the domain state-change. The drainer asynchronously applies
//	them to OpenFGA (with retry + idempotency). Rollback of the caller tx
//	⇒ no orphan outbox row.
//
//	Per ban #10 — within-service refs/invariants live on
//	DB-level: tx-commit is the atomicity primitive, not "INSERT then call
//	OpenFGA sync then hope".
//
// Schema of `kacho_iam.fga_outbox` (table and NOTIFY trigger — migration
// `0001_initial.sql`; the ordering partition key — `0067_fga_outbox_tuple_key_partition.sql`):
//
//	id            bigserial    PK
//	event_type    text         IN ('fga.tuple.write','fga.tuple.delete')
//	payload       jsonb        {"user":"…","object":"…"} plus EITHER "relation"
//	                           (one relation) OR "relations" (the subject's whole
//	                           set on that object; see emitTx)
//	created_at    timestamptz  default now()
//	sent_at       timestamptz  NULL until drainer applies
//	last_error    text
//	attempt_count int
//	tuple_key     text         `user object` — the GRANT key, filled by a BEFORE
//	                           INSERT trigger, NEVER by a writer. It is the
//	                           drainer's ordering partition, so a second rendering
//	                           of it would split one grant across two partitions
//	                           and lose the write→delete order silently. A payload
//	                           missing a component yields NULL and is refused
//	                           by fga_outbox_tuple_key_present_check at INSERT.
//	                           The COLUMN NAME is historical: until migration 0099
//	                           the key was the whole triple (see PartitionColumn
//	                           below for why it no longer can be).
//
// Drainer event types (clients/fga_applier.go):
//   - clients.FGAEventTypeWrite  = "fga.tuple.write"
//   - clients.FGAEventTypeDelete = "fga.tuple.delete"
package fga_outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// EventTypeWrite / EventTypeDelete — the two event types this table carries.
// Exported so every producer names the row's kind through the package that owns
// the row's shape, instead of repeating the literal at its own INSERT.
const (
	EventTypeWrite  = "fga.tuple.write"
	EventTypeDelete = "fga.tuple.delete"
)

// PartitionColumn is the drainer's ORDERING PARTITION column on this table. It
// lives here, next to the emitter, because the emitter decides what a row IS and
// the partition decides which rows are ordered against each other — a second
// rendering of the name in the wiring would let those two drift apart silently,
// which is the failure mode the table's own doc warns about.
//
// Its stored value is `user || ' ' || object` (migration 0099), NOT the whole
// triple: the unit a row now carries is one subject's WHOLE relation set on one
// object (see emitTx), and a partition has to cover every row it can be ordered
// against. Narrower than that and a revoke of the set could apply ahead of the
// grant it supersedes, which is the exact over-grant migration 0061 closed.
const PartitionColumn = "tuple_key"

// RelationPredicate renders the SQL predicate «this row carries <arg> as one of its
// relations», matching BOTH row shapes — the single-relation payload and the set.
//
// It exists because a reader that keys on `payload->>'relation'` alone sees only the
// FIRST member of a set, and the direction that fails is the quiet one: a query asking
// "is this tuple queued?" answers NO for a tuple that is queued, so a de-duplication
// enqueues a second time and an assertion that a tuple is ABSENT passes without ever
// looking at the row that holds it.
//
// payloadExpr is the jsonb column expression (`payload`, `o.payload`); arg is the
// placeholder or literal carrying the relation.
func RelationPredicate(payloadExpr, arg string) string {
	return "(" + payloadExpr + "->>'relation' = " + arg +
		" OR " + payloadExpr + "->'relations' @> to_jsonb(" + arg + "::text))"
}

// EmitWriteTx INSERTs N grant rows into `kacho_iam.fga_outbox` (event_type
// `fga.tuple.write`) using the caller-supplied transaction.
//
// MUST run in the same pgx.Tx as the domain state-change (AccessBinding
// insert, JIT auto-grant InsertTx, cluster_admin_grants insert). Tx rollback
// ⇒ outbox rows are not visible to the drainer.
//
// len(tuples)==0 is a no-op (returns nil) — caller decides whether 0 tuples
// is an error.
func EmitWriteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, EventTypeWrite, tuples)
}

// EmitDeleteTx INSERTs N revoke rows into `kacho_iam.fga_outbox` (event_type
// `fga.tuple.delete`).
//
// Caller supplies the EXACT tuples that were originally written by EmitWriteTx
// — symmetric revoke. Same atomicity contract as EmitWriteTx.
func EmitDeleteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, EventTypeDelete, tuples)
}

// emitTx enqueues the tuples GROUPED BY (user, object): one row per subject per
// object, carrying that subject's WHOLE relation set on it.
//
// WHY THE ROW IS THE SET AND NOT THE TUPLE. The drainer applies one row per call,
// so the row is the unit that reaches OpenFGA atomically. With a row per tuple the
// subject's verb set arrived one relation at a time — and between the first arrival
// and the last, the subject could read its own freshly created resource but not
// change or delete it. Observed on a stand: read allowed at t, update refused 50 ms
// later, both calls resolving against the same object with exactly one relation
// standing on it. A caller that has just been told it may read its own resource is
// entitled to conclude it may act on it; the set is one grant, so it has to move as
// one. (The synchronous writer already applied a whole object at once — the queue,
// which is the at-least-once path and therefore the one that runs whenever the
// synchronous attempt is skipped, cancelled or lost, did not.)
//
// SHAPE. A group of one relation keeps the historical single-tuple payload
// verbatim, so the many emitters that grant one relation at a time (bootstrap, JIT,
// break-glass, the register proxy) produce byte-identical rows and nothing about
// them changes. Only a genuine SET takes the `relations` form, and only a GRANT set
// additionally carries the compatibility echo — see the branch below for why the two
// directions differ.
func emitTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(tuples) == 0 {
		return nil
	}
	groups := groupByGrant(tuples)
	payloads := make([]string, 0, len(groups))
	for _, g := range groups {
		fields := map[string]any{"user": g.user, "object": g.object}
		if len(g.relations) == 1 {
			fields["relation"] = g.relations[0]
		} else {
			fields["relations"] = g.relations
			if eventType == EventTypeWrite {
				// COMPATIBILITY ECHO — GRANTS ONLY, and the asymmetry is the point.
				//
				// During a rolling upgrade a pod that predates the set form still claims
				// these rows. Given an echo it applies ONE relation and marks the row
				// delivered; given none it cannot decode the row and poisons it.
				//
				// For a GRANT the first outcome is better: the subject ends up with less
				// access than it is owed (fail-closed), the row is consumed, and the next
				// reconcile pass completes it.
				//
				// For a REVOKE it is strictly worse, and irrecoverably so: the row is
				// marked delivered while most of the set SURVIVES ITS OWN REMOVAL — an
				// over-grant that is invisible to the poison ledger, to the wedge warning
				// and to the redrive, because as far as the queue is concerned the work
				// is done. A poisoned revoke, by contrast, is visible in all three and is
				// re-driven on the first model observation after a pod starts — which the
				// end of the rollout guarantees. So revokes carry no echo: better stuck
				// and loud than applied in part and silent.
				fields["relation"] = g.relations[0]
			}
		}
		payload, err := json.Marshal(fields)
		if err != nil {
			return fmt.Errorf("fga_outbox: marshal payload: %w", err)
		}
		payloads = append(payloads, string(payload))
	}
	// ОДИН стейтмент на все строки вместо одного на строку. Порядок строк сохраняется:
	// `unnest` в FROM выдаёт элементы в порядке массива, поэтому возрастающие id
	// назначаются в том же порядке, в каком вызывающий перечислил кортежи, — а на
	// порядке id держится поголовный FIFO партиции у claim'а дренажа (выдача и отзыв
	// одного ключа НЕ коммутативны). Прежняя поштучная вставка давала ровно тот же
	// порядок, только за N обращений к серверу вместо одного.
	if _, err := tx.Exec(ctx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 SELECT $1, p::jsonb, now() FROM unnest($2::text[]) AS p`,
		eventType, payloads,
	); err != nil {
		return fmt.Errorf("fga_outbox: insert %s: %w", eventType, err)
	}
	return nil
}

// grantGroup — one subject's relation set on one object: the unit a row carries and
// the unit the drainer's ordering partition covers.
type grantGroup struct {
	user      string
	object    string
	relations []string
}

// groupByGrant buckets tuples by (user, object), preserving first-seen order for
// both the groups and the relations inside them, and dropping a relation repeated
// within one group.
//
// Order matters twice over: the INSERT assigns ascending ids in slice order, and
// per-partition FIFO — which is what keeps a revoke behind the grant it supersedes
// — rests on those ids. De-duplication matters because OpenFGA rejects a request
// naming the same tuple twice (cannot_allow_duplicate_tuples_in_one_request), and a
// caller that legitimately derives one tuple from two rules would otherwise turn a
// whole grant into a permanent poison.
func groupByGrant(tuples []clients.RelationTuple) []grantGroup {
	type key struct{ user, object string }
	idx := make(map[key]int, len(tuples))
	seen := make(map[clients.RelationTuple]struct{}, len(tuples))
	groups := make([]grantGroup, 0, len(tuples))
	for _, t := range tuples {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		k := key{user: t.User, object: t.Object}
		if i, ok := idx[k]; ok {
			groups[i].relations = append(groups[i].relations, t.Relation)
			continue
		}
		idx[k] = len(groups)
		groups = append(groups, grantGroup{user: t.User, object: t.Object, relations: []string{t.Relation}})
	}
	return groups
}
