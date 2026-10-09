// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_public_grant_test.go — publishing a resource for anonymous read is
// its OWN path, not a statement about the resource (приёмка NTF-3, Р30 «Публикация для
// анонимного чтения»; NTF3-186).
//
// kacho-registry publishes a repository with SetPublicReadPublication — an intent that
// carries the publication's version and the incarnation's generation and nothing about
// the resource. The mirror row is keyed by the SAME object as the repository's own
// registration, so a publication that restated the resource would overwrite its parent
// scope with an empty one, and closing it would erase the repository from the authz
// projection while the repository still exists. So the publication reaches the
// publication port and nothing else; the object's own withdrawal takes the publication
// with it; a registration of a type that admits publication drops a publication of an
// earlier incarnation; a type that admits none never reaches the port.
import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// mirrorSpy records the mirror rows written and removed, keeping the last state
// per object so the test can assert the repository's parent scope survives.
type mirrorSpy struct {
	mu      sync.Mutex
	rows    map[string]service.ResourceMirrorRow
	heads   map[string]int64 // the object's head, tombstone included
	upserts int
	deletes int
}

func newMirrorSpy() *mirrorSpy {
	return &mirrorSpy{rows: map[string]service.ResourceMirrorRow{}, heads: map[string]int64{}}
}

func (m *mirrorSpy) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	if row.Generation <= m.heads[key] {
		return false, false, nil // REJECTED_STALE: not newer than the head
	}
	m.heads[key] = row.Generation
	m.rows[key] = row
	// These cases are about the wildcard grant, which writes no projection at all; they
	// never claim staleness-freedom, so the guarded entry point stays in force.
	return true, false, nil
}

func (m *mirrorSpy) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, generation int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if generation <= m.heads[key] {
		return false, nil // REJECTED_STALE
	}
	m.heads[key] = generation // the tombstone
	delete(m.rows, key)
	return true, nil
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

// objReq — the object's own registration (one structural tuple) and withdrawal.
type objReq struct {
	object        string
	parentProject string
	labels        map[string]string
	generation    int64
}

func (r *objReq) GetObject() string { return r.object }
func (r *objReq) GetTuples() []*iamv1.RegisteredTuple {
	return []*iamv1.RegisteredTuple{{SubjectId: "project:" + r.parentProject, Relation: "project"}}
}
func (r *objReq) GetGeneration() int64         { return r.generation }
func (r *objReq) GetLabels() map[string]string { return r.labels }
func (r *objReq) GetParentProjectId() string   { return r.parentProject }
func (r *objReq) GetParentAccountId() string   { return "" }
func (r *objReq) GetParentChain() []string     { return nil }

// pubReq — the owner's publication intent as it really arrives.
type pubReq struct {
	object           string
	published        bool
	version          time.Time
	objectGeneration int64
}

func (r *pubReq) GetObject() string          { return r.object }
func (r *pubReq) GetPublished() bool         { return r.published }
func (r *pubReq) GetObjectGeneration() int64 { return r.objectGeneration }
func (r *pubReq) GetPublicationVersion() *timestamppb.Timestamp {
	if r.version.IsZero() {
		return nil
	}
	return timestamppb.New(r.version)
}

const publicGrantObject = "registry_repository:reg53eeeg3578y4ah0q9/team/app"

func publicGrantRig() (*RegisterResourceUseCase, *mirrorSpy, *countingEmitter, *countingReconcileEvents, *recordingPublisher) {
	m := newMirrorSpy()
	e := &countingEmitter{}
	ev := &countingReconcileEvents{}
	pub := &recordingPublisher{}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, pub, noResidual{}).WithReconcile(ev)
	return uc, m, e, ev, pub
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
	fgaType, oid := objectRef(object).split()
	dotted, ok, err := seededCatalogTypes{}.DottedTypeTx(context.Background(), nil, fgaType)
	require.NoError(t, err)
	if !ok {
		dotted = fgaType
	}
	return dotted + ":" + oid
}

// ── tests ────────────────────────────────────────────────────────────────────

const (
	publicGrantID     = "reg53eeeg3578y4ah0q9/team/app"
	publicGrantDotted = "registry.repositories"
)

// TestPublish_LeavesTheResourceProjectionAlone — the publication must not restate the
// resource: the repository's parent scope and labels survive it, the admission and the
// journal are not touched, no reconcile event is enqueued; the publication port gets
// the owner's version, the incarnation and the catalog key of the object's head.
func TestPublish_LeavesTheResourceProjectionAlone(t *testing.T) {
	uc, mirror, emitter, events, pub := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	require.NoError(t, uc.Register(ctx, &objReq{
		object: publicGrantObject, parentProject: "prj0000000000000proj",
		labels: map[string]string{"tier": "gold"}, generation: 1,
	}))
	row, ok := mirror.row(key)
	require.True(t, ok, "the repository registration writes the mirror row")
	require.Equal(t, "prj0000000000000proj", row.ParentProjectID)
	upsertsBefore, deletesBefore := mirror.counts()
	eventsBefore := events.count()
	writesBefore := emitter.writes
	callsBefore := len(pub.seen())

	v := time.Now().Add(5 * time.Millisecond)
	require.NoError(t, uc.Publish(ctx, &pubReq{object: publicGrantObject, published: true, version: v, objectGeneration: 1}))
	require.NoError(t, uc.Publish(ctx, &pubReq{object: publicGrantObject, published: false, version: v.Add(time.Second), objectGeneration: 1}))

	assertPublications(t, []publicationCall{
		{kind: "apply", objectType: "registry_repository", objectID: publicGrantID, headType: publicGrantDotted,
			published: true, version: v, objectGeneration: 1},
		{kind: "apply", objectType: "registry_repository", objectID: publicGrantID, headType: publicGrantDotted,
			published: false, version: v.Add(time.Second), objectGeneration: 1},
	}, pub.seen()[callsBefore:], "the publication is applied in the owner's order, for its incarnation")
	row, ok = mirror.row(key)
	require.True(t, ok, "the repository must still be projected")
	assert.Equal(t, "prj0000000000000proj", row.ParentProjectID, "publishing must not blank the parent scope")
	assert.Equal(t, map[string]string{"tier": "gold"}, row.Labels, "publishing must not blank the labels")
	ups, dels := mirror.counts()
	assert.Equal(t, upsertsBefore, ups, "a publication does not reach the admission")
	assert.Equal(t, deletesBefore, dels, "closing a publication does not withdraw the object")
	assert.Equal(t, writesBefore, emitter.writes, "a publication is not a bare tuple in the journal")
	assert.Zero(t, emitter.deletes, "closing a publication is not a bare tuple delete")
	assert.Equal(t, eventsBefore, events.count(), "a publication changes no projection, so it enqueues no reconcile event")
}

// TestUnregisterResource_Repository_TakesItsPublication — the object's withdrawal
// removes its projection AND takes its publication with it: a repository's id is its
// name, and a publication surviving the repository would open the next one so named.
// The registration that preceded it dropped a publication of an earlier incarnation
// (none here — the port's own business).
func TestUnregisterResource_Repository_TakesItsPublication(t *testing.T) {
	uc, mirror, _, _, pub := publicGrantRig()
	ctx := context.Background()
	key := mirrorKey(t, publicGrantObject)

	require.NoError(t, uc.Register(ctx, &objReq{object: publicGrantObject, parentProject: "prj0000000000000proj", generation: 1}))
	require.NoError(t, uc.Unregister(ctx, &objReq{object: publicGrantObject, generation: 2}))

	_, ok := mirror.row(key)
	assert.False(t, ok, "removing the repository must remove its projection")
	assertPublications(t, []publicationCall{
		{kind: "drop-stale", objectType: "registry_repository", objectID: publicGrantID, headType: publicGrantDotted},
		{kind: "withdraw", objectType: "registry_repository", objectID: publicGrantID},
	}, pub.seen(), "the registration drops a stale incarnation's publication, the withdrawal takes the object's")
}

// TestUnregisterResource_StaleWithdrawal_LeavesThePublication — a withdrawal not newer
// than the head is REJECTED_STALE and takes nothing, the publication included.
func TestUnregisterResource_StaleWithdrawal_LeavesThePublication(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	ctx := context.Background()
	require.NoError(t, uc.Register(ctx, &objReq{object: publicGrantObject, parentProject: "prj0000000000000proj", generation: 3}))
	require.NoError(t, uc.Unregister(ctx, &objReq{object: publicGrantObject, generation: 2}))
	for _, c := range pub.seen() {
		assert.NotEqual(t, "withdraw", c.kind, "a stale withdrawal reached the publication port")
	}
}

// TestUnregisterResource_TypeWithoutPublications_LeavesThePublicationPortAlone — the
// legal twin of the cases above: an object whose type admits no publication has none to
// withdraw or drop, and neither its registration nor its removal reaches the port.
func TestUnregisterResource_TypeWithoutPublications_LeavesThePublicationPortAlone(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	ctx := context.Background()
	const network = "vpc_network:enp0000000000000net1"

	require.NoError(t, uc.Register(ctx, &objReq{object: network, parentProject: "prj0000000000000proj", generation: 1}))
	require.NoError(t, uc.Unregister(ctx, &objReq{object: network, generation: 2}))
	assert.Empty(t, pub.seen(), "a type that admits no publication must not reach the publication port")
}

// TestPublish_StoreFailureIsARefusal — a publication the store did not take is an ERROR
// to the caller, never a quiet success: the consumer's durable queue redelivers it only
// if it hears a refusal.
func TestPublish_StoreFailureIsARefusal(t *testing.T) {
	uc, _, _, _, pub := publicGrantRig()
	pub.err = assertAnError
	err := uc.Publish(context.Background(), &pubReq{object: publicGrantObject, published: true, version: time.Now(), objectGeneration: 1})
	require.Error(t, err)
	assert.ErrorIs(t, err, assertAnError)
}

// TestPublish_RefusesWhatItCannotOrder — the intent without a version, without an
// incarnation, or for a type that admits no publication is refused with the field named
// and reaches nothing; its twin — the same intent, well-formed — applies.
func TestPublish_RefusesWhatItCannotOrder(t *testing.T) {
	v := time.Date(2026, 10, 7, 1, 2, 3, 0, time.UTC)
	for _, c := range []struct {
		name  string
		req   *pubReq
		field string
		desc  string
	}{
		{"without a version", &pubReq{object: publicGrantObject, published: true, objectGeneration: 1}, "publication_version", "required"},
		{"without an incarnation", &pubReq{object: publicGrantObject, published: true, version: v}, "object_generation", "required"},
		{"type admits no publication", &pubReq{object: "storage_volume:vol-41", published: true, version: v, objectGeneration: 1},
			"object", "type storage_volume does not admit public read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			uc, _, _, _, pub := publicGrantRig()
			err := uc.Publish(context.Background(), c.req)
			require.Error(t, err)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
			field, desc := fieldViolation(err)
			assert.Equal(t, c.field, field)
			assert.Equal(t, c.desc, desc)
			assert.Empty(t, pub.seen(), "a refused intent reaches no publication")

			require.NoError(t, uc.Publish(context.Background(), &pubReq{object: publicGrantObject, published: true, version: v, objectGeneration: 1}),
				"twin: the well-formed intent applies")
		})
	}
}
