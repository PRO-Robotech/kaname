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
// THE COORDINATION. Both deliveries carry the SAME discriminator — the object's
// generation, which the owner stamps once per change. The admission compares it with the
// object's head (Р30 «Приём поколения — CAS»): the second delivery is not newer, so it is
// REJECTED_STALE and writes nothing. Reading that verdict and skipping the downstream work
// is the gate.
//
// WHY THIS AND NOT QUEUE DEDUP. Collapsing unsent outbox rows by (event type, payload)
// silently drops a re-grant: grant → revoke → grant folds into grant → revoke, losing
// the grant. This gate keys on APPLIED STATE via the object's generation, not on queue
// contents, so a later re-registration always carries a newer generation and is never
// swallowed — pinned below.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// ── fakes modelling the admission against the object's head ─────────────────

// versionedMirror models the projection admission: an intent applies only when its
// generation is STRICTLY newer than the object's head — the tombstone of a withdrawal
// included — and the emitter reports whether it applied.
type versionedMirror struct {
	mu       sync.Mutex
	heads    map[string]int64
	upserts  int // UpsertTx calls
	deletes  int // DeleteTx calls
	mutated  int // calls that actually applied
	labelsOf map[string]map[string]string
}

func newVersionedMirror() *versionedMirror {
	return &versionedMirror{heads: map[string]int64{}, labelsOf: map[string]map[string]string{}}
}

func (m *versionedMirror) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	if row.Generation <= m.heads[key] {
		return false, false, nil // REJECTED_STALE — nothing written
	}
	// projectionUnchanged: the write advanced only the generation. These cases vary
	// labels and nothing else, so labels are what the fake compares (the trigger compares
	// parent-scope too).
	prev, exists := m.labelsOf[key]
	unchanged := exists && sameStringMap(prev, row.Labels)
	m.heads[key] = row.Generation
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

func (m *versionedMirror) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, generation int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if generation <= m.heads[key] {
		return false, nil // REJECTED_STALE
	}
	m.heads[key] = generation // the tombstone
	delete(m.labelsOf, key)
	m.mutated++
	return true, nil
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

// versionedReq is a registerInput carrying an explicit generation + labels.
type versionedReq struct {
	subject, relation, object string
	labels                    map[string]string
	generation                int64
}

func (r *versionedReq) GetTuples() []*iamv1.RegisteredTuple {
	return []*iamv1.RegisteredTuple{{SubjectId: r.subject, Relation: r.relation}}
}
func (r *versionedReq) GetObject() string            { return r.object }
func (r *versionedReq) GetGeneration() int64         { return r.generation }
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
	// На объекте стоит то, что кладёт его регистрация: снятие обязано его назвать.
	standing := standingResidual{tuples: []service.RelationTuple{
		{User: "project:prj-1", Relation: "project", Object: "vpc_network:net-1"},
	}}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, &recordingPublisher{}, standing).
		WithReconcile(ev).
		WithObjectReconciler(rec, nil)
	return &redeliveryRig{uc: uc, mirror: m, emitter: e, events: ev, recon: rec}
}

// TestRegisterResource_SecondDeliveryOfOneGeneration_DoesNoDuplicateWork — the core
// contract. The sync registrar and the drainer deliver the SAME generation; whichever
// arrives second is not newer than the head and must be recognised as a no-op: no
// owner-tuple row, no reconcile event, no forward reconcile fan-out.
//
// RED before the gate: the use-case discarded the admission's verdict and re-ran the
// whole materialisation — 2 tuple rows, 2 reconcile events, 2 forward passes.
func TestRegisterResource_SecondDeliveryOfOneGeneration_DoesNoDuplicateWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	req := func() *versionedReq {
		return &versionedReq{
			subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
			labels: map[string]string{"tier": "gold"}, generation: 1,
		}
	}

	// (1) The first delivery — this one does the work.
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.Equal(t, 1, rig.emitter.writes, "the first delivery enqueues the owner tuple")
	require.Equal(t, 1, rig.events.count(), "the first delivery enqueues the reconcile event")
	require.Len(t, rig.recon.snapshot(), 1, "the first delivery drives the forward reconcile")

	// (2) The other delivery of the SAME generation; and a third, as an at-least-once
	// retry would. Nothing about the resource changed.
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.NoError(t, rig.uc.Register(ctx, req()))

	assert.Equal(t, 1, rig.emitter.writes,
		"a delivery not newer than the head must not enqueue the owner tuple again")
	assert.Equal(t, 1, rig.events.count(),
		"a delivery not newer than the head must not enqueue another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1,
		"a delivery not newer than the head must not re-run the forward reconcile fan-out")
	assert.Equal(t, 1, rig.mirror.mutated, "exactly one delivery applied")
}

// TestRegisterResource_OlderGeneration_DoesNoWork — a late delivery of an OLDER
// generation (the producer's queue reordered two changes) changes nothing either.
func TestRegisterResource_OlderGeneration_DoesNoWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "bronze"}, generation: 3,
	}))
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, generation: 2,
	}))

	assert.Equal(t, 1, rig.emitter.writes, "the older generation enqueues nothing")
	assert.Equal(t, 1, rig.events.count(), "the older generation enqueues no reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1, "the older generation drives no forward reconcile")
}

// TestRegisterResource_NewerGeneration_StillMaterializes — the gate must not swallow
// real change. A label UPDATE re-registers the object with a NEWER generation; the
// rematerialise path (the closed revoke defect) must still fire in full.
func TestRegisterResource_NewerGeneration_StillMaterializes(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, generation: 1,
	}))
	// Label UPDATE — the grant-matching label is removed. This MUST rematerialise, so a
	// now-unmatched grant is revoked by the reconcile pass it drives.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "bronze"}, generation: 2,
	}))

	assert.Equal(t, 2, rig.emitter.writes, "a newer generation re-enqueues the owner tuple")
	assert.Equal(t, 2, rig.events.count(), "a newer generation enqueues another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 2, "a newer generation re-runs the forward reconcile")
}

// TestRegisterResource_GrantRevokeGrant_NotCollapsed — the anti-trap regression, at the
// producer boundary. The trap the obvious dedup falls into is collapsing
// grant → revoke → grant into grant → revoke. Because this gate keys on the object's
// generation rather than on payload equality, the second grant — a newer generation than
// the tombstone — is always materialised.
func TestRegisterResource_GrantRevokeGrant_NotCollapsed(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	// GRANT.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, generation: 1,
	}))
	// REVOKE (unregister — the resource is deleted).
	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		object:     "vpc_network:net-1",
		generation: 2,
	}))
	require.Equal(t, 1, rig.emitter.deletes, "the unregister enqueues the tuple delete")

	// GRANT AGAIN — newer than the tombstone. The producer-side de-dup must NOT swallow
	// this.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, generation: 3,
	}))

	assert.Equal(t, 2, rig.emitter.writes,
		"the re-grant after a revoke must be re-emitted — never collapsed into grant → revoke")
	// Three passes, one per step: both grants AND the revoke in between drive their
	// materialisation in-process (see unregister_resource_sync_revoke_test.go).
	assert.Len(t, rig.recon.snapshot(), 3,
		"grant, revoke and re-grant each drive their own post-commit pass")
}

// TestRegisterResource_StaleWithdrawal_ChangesNothing — a withdrawal not newer than the
// head is REJECTED_STALE: no tuple delete, no reconcile event, no forward pass. The head
// proves a newer state of the object was already applied (or a newer withdrawal), and
// removing its tuples now would revoke what that state still grants. Twin by one fact:
// the first withdrawal of the same generation applied in full.
func TestRegisterResource_StaleWithdrawal_ChangesNothing(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	withdraw := func() *unregReq {
		return &unregReq{object: "vpc_network:net-1", generation: 2}
	}

	require.NoError(t, rig.uc.Unregister(ctx, withdraw()))
	require.Equal(t, 1, rig.emitter.deletes, "twin: the first withdrawal enqueues the tuple delete")
	require.Equal(t, 1, rig.events.count(), "twin: the first withdrawal enqueues the reconcile event")
	require.Len(t, rig.recon.snapshot(), 1, "twin: the first withdrawal drives its pass")

	require.NoError(t, rig.uc.Unregister(ctx, withdraw()),
		"a stale withdrawal is a success of the call: the proxy is idempotent")
	assert.Equal(t, 1, rig.emitter.deletes, "a stale withdrawal enqueues no tuple delete")
	assert.Equal(t, 1, rig.events.count(), "a stale withdrawal enqueues no reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1, "a stale withdrawal drives no pass")

	// A registration not newer than the tombstone does not bring the object back.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, generation: 1,
	}))
	assert.Equal(t, 0, rig.emitter.writes, "a registration not newer than the tombstone writes no tuple")
}

// unregReq satisfies unregisterInput.
type unregReq struct {
	object     string
	generation int64
}

func (r *unregReq) GetObject() string    { return r.object }
func (r *unregReq) GetGeneration() int64 { return r.generation }

// TestRegisterResource_WithoutGeneration_IsRefused — there is no admission without a
// generation (Р30 «Поколение и проекция», NTF3-174 (н)): `0` is INVALID_ARGUMENT naming
// the field, nothing reaches the admission, nothing is enqueued. The inherited path
// «an unversioned producer always applies» is gone. Twin by one fact: generation 1
// applies.
func TestRegisterResource_WithoutGeneration_IsRefused(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	reg := func(g int64) *versionedReq {
		return &versionedReq{subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
			labels: map[string]string{"tier": "gold"}, generation: g}
	}

	for _, c := range []struct {
		name string
		call func() error
		desc string
	}{
		{"register 0", func() error { return rig.uc.Register(ctx, reg(0)) }, "required"},
		{"register -1", func() error { return rig.uc.Register(ctx, reg(-1)) }, "must be positive"},
		{"unregister 0", func() error {
			return rig.uc.Unregister(ctx, &unregReq{object: "vpc_network:net-1"})
		}, "required"},
	} {
		err := c.call()
		require.Error(t, err, c.name)
		require.Equal(t, codes.InvalidArgument, status.Code(err), "%s: %v", c.name, err)
		field, desc := fieldViolation(err)
		assert.Equal(t, "generation", field, c.name)
		assert.Equal(t, c.desc, desc, c.name)
	}
	assert.Zero(t, rig.mirror.upserts+rig.mirror.deletes, "a refused intent never reaches the admission")
	assert.Zero(t, rig.emitter.writes+rig.emitter.deletes, "a refused intent enqueues nothing")

	require.NoError(t, rig.uc.Register(ctx, reg(1)), "twin: generation 1 applies")
	assert.Equal(t, 1, rig.emitter.writes)
}

// fieldViolation — поле и описание первого нарушения BadRequest отказа.
func fieldViolation(err error) (field, desc string) {
	for _, d := range status.Convert(err).Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			v := br.GetFieldViolations()[0]
			return v.GetField(), v.GetDescription()
		}
	}
	return "", ""
}
