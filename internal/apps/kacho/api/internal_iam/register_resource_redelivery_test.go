// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_redelivery_test.go — the producer-cost contract of
// RegisterResource under the DUPLICATE delivery every consumer performs.
//
// THE DUPLICATION. Every resource create in vpc/compute/nlb/storage/registry emits a
// register intent into the service's own fga_register_outbox INSIDE the writer-tx and,
// after the commit, ALSO calls iam.RegisterResource synchronously with the same intent.
// The async register-drainer then delivers that durable row as well. So iam receives
// each registration TWICE, and — before this gate — did the FULL materialisation work
// both times: mirror UPSERT, owner-tuple enqueue, reconcile-event enqueue and a
// synchronous forward reconcile that fans out over every matching binding. Measured on
// the stand: two byte-identical 27-row fga_outbox batches 6.7 ms apart for one created
// network; 2.21 outbox rows per distinct tuple table-wide.
//
// THE COORDINATION. The two paths already carry the discriminator — a monotonic
// source_version. The sync registrar stamps time.Now() AFTER the commit; the drainer
// replays the version the DB stamped INSIDE the writer-tx, i.e. strictly earlier. The
// mirror UPSERT is already guarded `WHERE resource_mirror.source_version <
// EXCLUDED.source_version`, so the drainer's replay updates ZERO rows — it is already a
// detected no-op whose result the use-case discarded. Reading that result and skipping
// the downstream work is the fix.
//
// WHY THIS AND NOT QUEUE DEDUP. Collapsing unsent outbox rows by (event type, payload)
// silently drops a re-grant: grant → revoke → grant folds into grant → revoke, losing
// the grant. This gate keys on APPLIED STATE via a MONOTONIC version, not on queue
// contents, so a later re-registration always carries a newer version (and a revoke
// removes the mirror row outright) and is therefore never swallowed — pinned below.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// ── fakes modelling the monotonic mirror ────────────────────────────────────

// versionedMirror models kacho_iam.resource_mirror's monotonic UPSERT guard: a row is
// written only when the incoming source_version is STRICTLY newer than the stored one,
// and the emitter reports whether it changed anything.
type versionedMirror struct {
	mu       sync.Mutex
	stored   map[string]time.Time
	upserts  int // UpsertTx calls
	deletes  int // DeleteTx calls
	mutated  int // calls that actually changed a row
	labelsOf map[string]map[string]string
}

func newVersionedMirror() *versionedMirror {
	return &versionedMirror{stored: map[string]time.Time{}, labelsOf: map[string]map[string]string{}}
}

func (m *versionedMirror) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	prev, exists := m.stored[key]
	if exists && !row.SourceVersion.After(prev) {
		return false, false, nil // stale/equal replay — 0 rows updated
	}
	// projectionUnchanged: the write advanced only the version. These cases vary labels
	// and nothing else, so labels are what the fake compares (the SQL statement compares
	// parent-scope too — see resource_mirror.UpsertTx).
	unchanged := exists && sameStringMap(m.labelsOf[key], row.Labels)
	m.stored[key] = row.SourceVersion
	m.labelsOf[key] = row.Labels
	m.mutated++
	return true, unchanged, nil
}

// sameStringMap — set equality of two label maps.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (m *versionedMirror) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, tombstone time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if prev, exists := m.stored[key]; exists && !prev.After(tombstone) {
		delete(m.stored, key)
		delete(m.labelsOf, key)
		m.mutated++
	}
	return nil
}

// countingEmitter counts the owner-tuple rows enqueued into fga_outbox.
type countingEmitter struct {
	mu      sync.Mutex
	writes  int
	deletes int
}

func (e *countingEmitter) EmitWriteTx(_ context.Context, _ service.Tx, ts []service.RelationTuple) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writes += len(ts)
	return nil
}

func (e *countingEmitter) EmitDeleteTx(_ context.Context, _ service.Tx, ts []service.RelationTuple) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deletes += len(ts)
	return nil
}

// countingReconcileEvents counts resource_reconcile_outbox enqueues.
type countingReconcileEvents struct {
	mu     sync.Mutex
	events []string // eventType
}

func (r *countingReconcileEvents) EmitTx(_ context.Context, _ service.Tx, eventType, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, eventType)
	return nil
}

func (r *countingReconcileEvents) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// versionedReq is a registerInput carrying an explicit source_version + labels.
type versionedReq struct {
	subject, relation, object string
	labels                    map[string]string
	version                   time.Time
}

func (r *versionedReq) GetSubjectId() string { return r.subject }
func (r *versionedReq) GetRelation() string  { return r.relation }
func (r *versionedReq) GetObject() string    { return r.object }
func (r *versionedReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}
func (r *versionedReq) GetLabels() map[string]string { return r.labels }
func (r *versionedReq) GetParentProjectId() string   { return "prj-1" }
func (r *versionedReq) GetParentAccountId() string   { return "acc-1" }
func (r *versionedReq) GetParentChain() []string     { return nil }

type redeliveryRig struct {
	uc      *RegisterResourceUseCase
	mirror  *versionedMirror
	emitter *countingEmitter
	events  *countingReconcileEvents
	recon   *smObjectReconciler
}

func newRedeliveryRig() *redeliveryRig {
	m := newVersionedMirror()
	e := &countingEmitter{}
	ev := &countingReconcileEvents{}
	rec := &smObjectReconciler{}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}).
		WithReconcile(ev).
		WithObjectReconciler(rec, nil)
	return &redeliveryRig{uc: uc, mirror: m, emitter: e, events: ev, recon: rec}
}

// TestRegisterResource_DrainerReplay_DoesNoDuplicateWork — the core contract. The sync
// registrar delivers first with the post-commit wall-clock version; the drainer replays
// the same registration with the DB version stamped inside the writer-tx (strictly
// earlier). The replay must be recognised as a no-op: no owner-tuple row, no reconcile
// event, no forward reconcile fan-out.
//
// RED before the gate: the use-case discarded the mirror UPSERT's result and re-ran the
// whole materialisation — 2 tuple rows, 2 reconcile events, 2 forward passes.
func TestRegisterResource_DrainerReplay_DoesNoDuplicateWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	inTx := time.Now()                           // stamped by the DB inside the producer's writer-tx
	postCommit := inTx.Add(3 * time.Millisecond) // stamped by the sync registrar after commit

	// (1) The synchronous registrar's delivery — this one does the work.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: postCommit,
	}))
	require.Equal(t, 1, rig.emitter.writes, "the first delivery enqueues the owner tuple")
	require.Equal(t, 1, rig.events.count(), "the first delivery enqueues the reconcile event")
	require.Len(t, rig.recon.snapshot(), 1, "the first delivery drives the forward reconcile")

	// (2) The register-drainer's replay of the SAME registration, carrying the older
	// in-writer-tx version. Nothing about the resource changed.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: inTx,
	}))

	assert.Equal(t, 1, rig.emitter.writes,
		"a replay that changed no mirror row must not enqueue the owner tuple again")
	assert.Equal(t, 1, rig.events.count(),
		"a replay that changed no mirror row must not enqueue another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1,
		"a replay that changed no mirror row must not re-run the forward reconcile fan-out")
	assert.Equal(t, 1, rig.mirror.mutated, "exactly one delivery mutated the mirror")
}

// TestRegisterResource_IdenticalReplay_DoesNoDuplicateWork — the same contract for an
// exactly-equal version (an at-least-once redelivery of the identical row, e.g. a
// drainer retry after a transient error): equal is not newer, so it is a no-op.
func TestRegisterResource_IdenticalReplay_DoesNoDuplicateWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v := time.Now()

	req := func() *versionedReq {
		return &versionedReq{
			subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
			labels: map[string]string{"tier": "gold"}, version: v,
		}
	}
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.NoError(t, rig.uc.Register(ctx, req()))

	assert.Equal(t, 1, rig.emitter.writes, "three identical deliveries do the work once")
	assert.Equal(t, 1, rig.events.count(), "three identical deliveries enqueue one reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1, "three identical deliveries drive one forward reconcile")
}

// TestRegisterResource_NewerVersion_StillMaterializes — the gate must not swallow real
// change. A label UPDATE re-registers the object with a NEWER version; the rematerialise
// path (the closed revoke defect) must still fire in full.
func TestRegisterResource_NewerVersion_StillMaterializes(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v1 := time.Now()

	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: v1,
	}))
	// Label UPDATE — the grant-matching label is removed. This MUST rematerialise, so a
	// now-unmatched grant is revoked by the reconcile pass it drives.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "bronze"}, version: v1.Add(time.Second),
	}))

	assert.Equal(t, 2, rig.emitter.writes, "a newer version re-enqueues the owner tuple")
	assert.Equal(t, 2, rig.events.count(), "a newer version enqueues another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 2, "a newer version re-runs the forward reconcile")
}

// TestRegisterResource_GrantRevokeGrant_NotCollapsed — the anti-trap regression, at the
// producer boundary. The trap the obvious dedup falls into is collapsing
// grant → revoke → grant into grant → revoke. Because this gate keys on a MONOTONIC
// version (and an unregister removes the mirror row outright) rather than on payload
// equality, the second grant is always materialised.
func TestRegisterResource_GrantRevokeGrant_NotCollapsed(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	base := time.Now()

	// GRANT.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: base,
	}))
	// REVOKE (unregister — the resource is deleted).
	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		version: base.Add(time.Second),
	}))
	require.Equal(t, 1, rig.emitter.deletes, "the unregister enqueues the tuple delete")

	// GRANT AGAIN — a re-created resource with the same identity coordinates. The
	// producer-side de-dup must NOT swallow this.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: base.Add(2 * time.Second),
	}))

	assert.Equal(t, 2, rig.emitter.writes,
		"the re-grant after a revoke must be re-emitted — never collapsed into grant → revoke")
	// Three passes, one per step: both grants AND the revoke in between drive their
	// materialisation in-process. The revoke's pass is what keeps withdrawal off the
	// reconcile queue's critical path (see unregister_resource_sync_revoke_test.go);
	// before it, this sequence produced two passes and the middle step's removal waited
	// for the drainer.
	assert.Len(t, rig.recon.snapshot(), 3,
		"grant, revoke and re-grant each drive their own post-commit pass")
}

// TestRegisterResource_UnregisterAlwaysMaterializes — revokes are never gated. An
// unregister always enqueues the tuple delete and the reconcile event, even when the
// mirror row is already gone: a swallowed revoke is an over-grant, and the asymmetry is
// deliberate (fail-closed — the cost saving is taken only on the grant path).
func TestRegisterResource_UnregisterAlwaysMaterializes(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v := time.Now()

	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1", version: v,
	}))
	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1", version: v,
	}))

	assert.Equal(t, 2, rig.emitter.deletes, "every unregister enqueues the tuple delete")
	assert.Equal(t, 2, rig.events.count(), "every unregister enqueues the reconcile event")
}

// unregReq satisfies unregisterInput.
type unregReq struct {
	subject, relation, object string
	version                   time.Time
}

func (r *unregReq) GetSubjectId() string { return r.subject }
func (r *unregReq) GetRelation() string  { return r.relation }
func (r *unregReq) GetObject() string    { return r.object }
func (r *unregReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}

// TestRegisterResource_UnversionedProducer_IsNeverGated — the gate requires positive
// proof of redelivery, and an unversioned producer supplies none.
//
// A caller that sends no source_version maps to '-infinity', which loses EVERY monotonic
// comparison — so after the first write its registrations report `changed = false` for a
// reason that has nothing to do with redelivery. Gating on that would suppress real
// materialisation and push the caller onto the async drain, widening its read-your-writes
// window instead of saving anything.
//
// This is not hypothetical: registry's synchronous registrar sends no source_version, and
// gating it stalled the registry-redesign suite on the live stand (6.8s → >10min of retry
// looping) before this guard was added.
func TestRegisterResource_UnversionedProducer_IsNeverGated(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	// An unversioned producer: source_version is the zero time ⇒ '-infinity'.
	unversioned := func() *versionedReq {
		return &versionedReq{
			subject: "project:prj-1", relation: "project", object: "registry_repository:rep-1",
			labels: map[string]string{"tier": "gold"}, version: time.Time{},
		}
	}
	for i := 0; i < 3; i++ {
		require.NoError(t, rig.uc.Register(ctx, unversioned()))
	}

	assert.Equal(t, 3, rig.emitter.writes,
		"an unversioned register must always enqueue the owner tuple — '-infinity' is not proof of redelivery")
	assert.Equal(t, 3, rig.events.count(),
		"an unversioned register must always enqueue the reconcile event")
	assert.Len(t, rig.recon.snapshot(), 3,
		"an unversioned register must always drive the forward reconcile (its sync fast path)")
}
