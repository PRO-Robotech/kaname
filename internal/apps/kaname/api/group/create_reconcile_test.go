// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// create_reconcile_test.go — rbac-contract-a-fix (forward-mat, C-01b) RED→GREEN
// unit proof that group Create SYNCHRONOUSLY materializes per-object access on the
// freshly-created iam_group object right after the writer-tx commits.
//
// Regression (Contract-A flat model): the flat authorization model
// (`proto/kaname/cloud/iam/v1/fga_model.fga`, still the canonical declaration —
// stage S6 removed the external ENGINE, not the model) dropped the
// `<rel> from account` ACCESS cascade on iam_group, so a Group created inside an
// account got NO admin/v_* tuple by derivation. The async reconcile event
// (EmitReconcileEvent → worker drain) materializes it eventually, but a client
// that polls Operation.Get to done and immediately GETs the group races the
// asynchronous drain → 403. The fix: Create co-commits the reconcile event AND
// synchronously calls ReconcileObject("iam.group", id) post-commit (best-effort,
// non-fatal — the periodic sweep / event drain remain as defense-in-depth), so the
// owner/account-admin per-object tuple is observable when the Operation is done.
//
// This white-box test pins that the use-case INVOKES the ObjectReconciler with the
// correct dotted type + id AFTER the writer-tx commits. RED before the fix (no
// synchronous call), GREEN after.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	grouprepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// fakeGroupCreateRepo — kanamerepo.Repository whose Writer() records the group
// Create DML + reconcile-event emit. Reader() is unused.
type fakeGroupCreateRepo struct{ w *fakeGroupCreateWriter }

func (r *fakeGroupCreateRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return nil, assertNotCalled("Reader")
}
func (r *fakeGroupCreateRepo) Writer(context.Context) (kanamerepo.Writer, error) { return r.w, nil }
func (r *fakeGroupCreateRepo) Close()                                            {}

// fakeGroupCreateWriter embeds kanamerepo.Writer (nil) — only the methods doCreate
// touches are overridden; any other call panics (narrow-path guard).
type fakeGroupCreateWriter struct {
	kanamerepo.Writer
	gw *fakeGroupCreateGroupWriter

	committed       bool
	reconcileEvents []reconcileEventRec
	audited         int
	fgaWriteEmitted int
}

type reconcileEventRec struct {
	eventType, objectType, objectID string
}

func (w *fakeGroupCreateWriter) GroupsW() grouprepo.WriterIface { return w.gw }

func (w *fakeGroupCreateWriter) EmitAuditEvent(context.Context, service.AuditEvent) error {
	w.audited++
	return nil
}
func (w *fakeGroupCreateWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	w.fgaWriteEmitted++
	return nil
}
func (w *fakeGroupCreateWriter) EmitReconcileEvent(_ context.Context, eventType, objectType, objectID string) error {
	w.reconcileEvents = append(w.reconcileEvents, reconcileEventRec{eventType, objectType, objectID})
	return nil
}
func (w *fakeGroupCreateWriter) Commit(context.Context) error   { w.committed = true; return nil }
func (w *fakeGroupCreateWriter) Rollback(context.Context) error { return nil }

// fakeGroupCreateGroupWriter satisfies grouprepo.WriterIface; only Insert is used.
type fakeGroupCreateGroupWriter struct{ inserted domain.Group }

func (g *fakeGroupCreateGroupWriter) Insert(_ context.Context, in domain.Group) (domain.Group, error) {
	g.inserted = in
	return in, nil
}
func (g *fakeGroupCreateGroupWriter) Update(context.Context, domain.Group, []string) (domain.Group, error) {
	return domain.Group{}, assertNotCalled("group.Update")
}
func (g *fakeGroupCreateGroupWriter) Delete(context.Context, domain.GroupID) error {
	return assertNotCalled("group.Delete")
}
func (g *fakeGroupCreateGroupWriter) AddMember(context.Context, domain.GroupMember) error {
	return assertNotCalled("group.AddMember")
}
func (g *fakeGroupCreateGroupWriter) RemoveMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) error {
	return assertNotCalled("group.RemoveMember")
}

// recordingObjectReconciler captures the THREE entry points in SEPARATE slices, and the
// separation is the whole point: a double that recorded the two forward entries into one
// slice would make the test green on either of them, i.e. it would stop being able to see
// the very thing it is here to pin.
//
// The create hot-path must take the PROVEN forward entry (ReconcileObjectForwardNoStale):
// the id was minted in the writer-tx that has just committed, so the object cannot carry
// anything stale, and the guarded entry's "does this object have members?" read is a
// question whose answer is known in advance. It must take neither the guarded forward nor
// the FULL EXCLUSIVE pass.
type recordingObjectReconciler struct {
	calls               []struct{ objectType, objectID string } // FULL ReconcileObject
	forwardCalls        []struct{ objectType, objectID string } // GUARDED ReconcileObjectForward
	forwardNoStaleCalls []struct{ objectType, objectID string } // PROVEN ReconcileObjectForwardNoStale
}

func (r *recordingObjectReconciler) ReconcileObject(_ context.Context, objectType, objectID string) error {
	r.calls = append(r.calls, struct{ objectType, objectID string }{objectType, objectID})
	return nil
}

func (r *recordingObjectReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.forwardCalls = append(r.forwardCalls, struct{ objectType, objectID string }{objectType, objectID})
	return nil
}

func (r *recordingObjectReconciler) ReconcileObjectForwardNoStale(_ context.Context, objectType, objectID string) error {
	r.forwardNoStaleCalls = append(r.forwardNoStaleCalls, struct{ objectType, objectID string }{objectType, objectID})
	return nil
}

func TestGroupCreate_SyncReconcilesObject(t *testing.T) {
	w := &fakeGroupCreateWriter{gw: &fakeGroupCreateGroupWriter{}}
	repo := &fakeGroupCreateRepo{w: w}
	rec := &recordingObjectReconciler{}

	uc := NewCreateGroupUseCase(repo, nil).WithObjectReconciler(rec)

	g := domain.Group{
		ID:        domain.GroupID("grp0000000000000abcd"),
		AccountID: domain.AccountID("acc0000000000000aaaa"),
		Name:      domain.GroupName("grp-recon"),
	}
	_, err := uc.doCreate(context.Background(), g, "usr00000000000000zzzz")
	require.NoError(t, err)

	// Writer-tx committed (DML + reconcile-event emit atomic).
	assert.True(t, w.committed, "writer-tx must commit")
	// The async event is still co-committed (defense-in-depth).
	require.Len(t, w.reconcileEvents, 1)
	assert.Equal(t, "iam.group", w.reconcileEvents[0].objectType)

	// IAM-FMB throughput fix: the create hot-path takes the ADDITIVE forward fast-path
	// (SHARE lock, single-object) so the owner/account-admin per-object tuple is
	// materialized by the time Operation is done WITHOUT serializing on the account's
	// single owner binding under a parallel create burst. It must NOT take the FULL
	// EXCLUSIVE ReconcileObject on this path (that remains the async at-least-once backstop).
	//
	// And it takes the PROVEN entry, not the guarded one. The guarded entry first reads
	// whether the object has members and routes it to the FULL EXCLUSIVE pass when it does
	// — on a create that read cannot come back non-empty, because the id was minted in the
	// writer-tx that has just committed. Asserting the ENTRY rather than "some forward
	// happened" is what keeps the distinction visible: both entries materialize the same
	// tuples, so a test that accepted either would be green with the guarded one back.
	require.Len(t, rec.forwardNoStaleCalls, 1,
		"group Create must synchronously take the PROVEN forward entry post-commit")
	assert.Equal(t, "iam.group", rec.forwardNoStaleCalls[0].objectType)
	assert.Equal(t, "grp0000000000000abcd", rec.forwardNoStaleCalls[0].objectID)
	assert.Empty(t, rec.forwardCalls,
		"create hot-path must NOT take the GUARDED forward entry — its member-read is answerable in advance")
	assert.Empty(t, rec.calls, "create hot-path must NOT take the FULL EXCLUSIVE ReconcileObject (forward only)")
}

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *fakeGroupCreateWriter) EmitInviteMail(_ context.Context, userID, _, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	return nil
}
