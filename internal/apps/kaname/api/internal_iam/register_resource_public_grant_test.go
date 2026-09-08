// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_public_grant_test.go — publishing a resource for anonymous
// read is a TUPLE intent, not a statement about the resource.
//
// kacho-registry publishes a repository by proxying the wildcard read tuple
// `user:* # v_get @ registry_repository:<reg>/<repo>` — and that intent carries
// no parent scope and no labels, because none of that changed. The mirror row is
// keyed by the SAME object as the repository's own registration, so treating the
// grant like a registration would:
//
//	on register   — overwrite the repository's parent scope with the empty one
//	                the grant carries (containment lost: bindings scoped to the
//	                owning project stop matching it);
//	on unregister — DELETE the repository's mirror row outright, while the
//	                repository still exists (making a repository private would
//	                erase it from the authz projection).
//
// So a pure grant writes/deletes the tuple and touches nothing else.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// mirrorSpy records the mirror rows written and removed, keeping the last state
// per object so the test can assert the repository's parent scope survives.
type mirrorSpy struct {
	mu      sync.Mutex
	rows    map[string]service.ResourceMirrorRow
	upserts int
	deletes int
}

func newMirrorSpy() *mirrorSpy {
	return &mirrorSpy{rows: map[string]service.ResourceMirrorRow{}}
}

func (m *mirrorSpy) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	if prev, ok := m.rows[key]; ok && !row.SourceVersion.After(prev.SourceVersion) {
		return false, false, nil
	}
	m.rows[key] = row
	// These cases are about the wildcard grant, which writes no projection at all; they
	// never claim staleness-freedom, so the guarded entry point stays in force.
	return true, false, nil
}

func (m *mirrorSpy) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, tombstone time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if prev, ok := m.rows[key]; ok && !prev.SourceVersion.After(tombstone) {
		delete(m.rows, key)
	}
	return nil
}

func (m *mirrorSpy) row(key string) (service.ResourceMirrorRow, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[key]
	return r, ok
}

func (m *mirrorSpy) counts() (upserts, deletes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upserts, m.deletes
}

// grantReq — a register/unregister input as the public-grant intent really
// arrives: tuple only, no parent scope, no labels.
type grantReq struct {
	subject, relation, object string
	parentProject             string
	labels                    map[string]string
	version                   time.Time
}

func (r *grantReq) GetSubjectId() string { return r.subject }
func (r *grantReq) GetRelation() string  { return r.relation }
func (r *grantReq) GetObject() string    { return r.object }
func (r *grantReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}
func (r *grantReq) GetLabels() map[string]string { return r.labels }
func (r *grantReq) GetParentProjectId() string   { return r.parentProject }
func (r *grantReq) GetParentAccountId() string   { return "" }
func (r *grantReq) GetParentChain() []string     { return nil }

const publicGrantObject = "registry_repository:reg53eeeg3578y4ah0q9/team/app"

func publicGrantRig() (*RegisterResourceUseCase, *mirrorSpy, *countingEmitter, *countingReconcileEvents) {
	m := newMirrorSpy()
	e := &countingEmitter{}
	ev := &countingReconcileEvents{}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}).WithReconcile(ev)
	return uc, m, e, ev
}

// mirrorKey — ключ строки зеркала для утверждений ниже: имя типа в словаре
// КАТАЛОГА плюс идентификатор.
//
// Перевод спрашивается у ТОГО ЖЕ дублёра, что провязан в use-case этих проб
// (`seededCatalogTypes`), а не выписывается второй копией: разойдясь, ожидание
// и продукт совпадали бы ровно там, где совпадают, и проба перестала бы
// утверждать про ключ хоть что-нибудь.
func mirrorKey(t *testing.T, object string) string {
	t.Helper()
	ti := tupleIntent{object: object}
	fgaType, oid := ti.splitObject()
	dotted, ok, err := seededCatalogTypes{}.DottedTypeTx(context.Background(), nil, fgaType)
	require.NoError(t, err)
	if !ok {
		dotted = fgaType
	}
	return dotted + ":" + oid
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestRegisterResource_PublicGrant_LeavesTheResourceProjectionAlone — the grant
// must not restate the resource: the repository's parent scope survives it.
func TestRegisterResource_PublicGrant_LeavesTheResourceProjectionAlone(t *testing.T) {
	uc, mirror, emitter, events := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	// (1) The repository registers itself: parent scope + labels.
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: publicGrantObject,
		parentProject: "prj0000000000000proj", labels: map[string]string{"tier": "gold"},
		version: base,
	}))
	row, ok := mirror.row(key)
	require.True(t, ok, "the repository registration writes the mirror row")
	require.Equal(t, "prj0000000000000proj", row.ParentProjectID)

	upsertsBefore, _ := mirror.counts()
	eventsBefore := events.count()

	// (2) The repository is made public: wildcard read tuple, nothing else, and
	// necessarily a LATER version (it is a later outbox row).
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	assert.Equal(t, 2, emitter.writes, "the grant tuple is enqueued")
	row, ok = mirror.row(key)
	require.True(t, ok, "the repository must still be projected")
	assert.Equal(t, "prj0000000000000proj", row.ParentProjectID,
		"publishing a repository must not blank its parent scope")
	assert.Equal(t, map[string]string{"tier": "gold"}, row.Labels,
		"publishing a repository must not blank its labels")

	upsertsAfter, _ := mirror.counts()
	assert.Equal(t, upsertsBefore, upsertsAfter, "a pure grant does not restate the resource projection")
	assert.Equal(t, eventsBefore, events.count(), "a pure grant changes no projection, so it enqueues no reconcile event")
}

// TestUnregisterResource_PublicGrant_DoesNotDeleteTheResourceProjection —
// making a repository private removes the wildcard tuple, not the repository.
func TestUnregisterResource_PublicGrant_DoesNotDeleteTheResourceProjection(t *testing.T) {
	uc, mirror, emitter, _ := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: publicGrantObject,
		parentProject: "prj0000000000000proj", version: base,
	}))
	require.NotEqual(t, 0, emitter.writes)

	// The repository goes private: the wildcard tuple is withdrawn.
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: "user:*", relation: "v_get", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	assert.Equal(t, 1, emitter.deletes, "the grant tuple is withdrawn")
	row, ok := mirror.row(key)
	require.True(t, ok, "withdrawing the public grant must NOT delete the repository's projection")
	assert.Equal(t, "prj0000000000000proj", row.ParentProjectID)
	_, deletes := mirror.counts()
	assert.Equal(t, 0, deletes, "a pure grant withdrawal must not reach the mirror at all")
}

// TestUnregisterResource_Repository_StillDeletesTheProjection — the guard is
// narrow: an ordinary hierarchy unregister (the repository itself going away)
// still removes the projection.
func TestUnregisterResource_Repository_StillDeletesTheProjection(t *testing.T) {
	uc, mirror, _, _ := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	base := time.Now()
	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: publicGrantObject,
		parentProject: "prj0000000000000proj", version: base,
	}))
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: "project:prj0000000000000proj", relation: "project", object: publicGrantObject,
		version: base.Add(5 * time.Millisecond),
	}))

	_, ok := mirror.row(key)
	assert.False(t, ok, "removing the repository must still remove its projection")
}
