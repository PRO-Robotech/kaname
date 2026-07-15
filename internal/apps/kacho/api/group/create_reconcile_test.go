// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// create_reconcile_test.go — rbac-contract-a-fix (forward-mat, C-01b) RED→GREEN
// unit proof that group Create SYNCHRONOUSLY materializes per-object access on the
// freshly-created iam_group object right after the writer-tx commits.
//
// Regression (Contract-A flat model): the flat OpenFGA model removed the
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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	grouprepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeGroupCreateRepo — kachorepo.Repository whose Writer() records the group
// Create DML + reconcile-event emit. Reader() is unused.
type fakeGroupCreateRepo struct{ w *fakeGroupCreateWriter }

func (r *fakeGroupCreateRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return nil, assertNotCalled("Reader")
}
func (r *fakeGroupCreateRepo) Writer(context.Context) (kachorepo.Writer, error) { return r.w, nil }
func (r *fakeGroupCreateRepo) Close()                                           {}

// fakeGroupCreateWriter embeds kachorepo.Writer (nil) — only the methods doCreate
// touches are overridden; any other call panics (narrow-path guard).
type fakeGroupCreateWriter struct {
	kachorepo.Writer
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

// recordingObjectReconciler captures every ReconcileObject call.
type recordingObjectReconciler struct {
	calls []struct{ objectType, objectID string }
}

func (r *recordingObjectReconciler) ReconcileObject(_ context.Context, objectType, objectID string) error {
	r.calls = append(r.calls, struct{ objectType, objectID string }{objectType, objectID})
	return nil
}

func TestGroupCreate_SyncReconcilesObject(t *testing.T) {
	w := &fakeGroupCreateWriter{gw: &fakeGroupCreateGroupWriter{}}
	repo := &fakeGroupCreateRepo{w: w}
	rec := &recordingObjectReconciler{}

	uc := NewCreateGroupUseCase(repo, nil).WithObjectReconciler(rec)

	g := domain.Group{
		ID:        domain.GroupID("grp00000000000000abcd"),
		AccountID: domain.AccountID("acc00000000000000aaaa"),
		Name:      domain.GroupName("grp-recon"),
	}
	_, err := uc.doCreate(context.Background(), g, "usr00000000000000zzzz")
	require.NoError(t, err)

	// Writer-tx committed (DML + reconcile-event emit atomic).
	assert.True(t, w.committed, "writer-tx must commit")
	// The async event is still co-committed (defense-in-depth).
	require.Len(t, w.reconcileEvents, 1)
	assert.Equal(t, "iam.group", w.reconcileEvents[0].objectType)

	// The fix: a SYNCHRONOUS ReconcileObject is invoked post-commit so the owner/
	// account-admin per-object tuple is materialized by the time Operation is done.
	require.Len(t, rec.calls, 1, "group Create must synchronously ReconcileObject post-commit")
	assert.Equal(t, "iam.group", rec.calls[0].objectType)
	assert.Equal(t, "grp00000000000000abcd", rec.calls[0].objectID)
}
