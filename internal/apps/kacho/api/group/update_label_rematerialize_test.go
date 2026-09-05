// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// update_label_rematerialize_test.go — a group label change must re-materialize the
// object, both durably and IMMEDIATELY.
//
// iam.group is label-selectable (domain.labelSelectableTypes carries "iam.group";
// kacho_iam.groups.labels — migration 0041, GIN — is probed by `labels @> match_labels`
// in the iam-direct scan spec), so removing a label that an ARM_LABELS grant matches is
// a REVOCATION: the per-object member row and its FGA tuples must go. Two feeds reach
// the same reconciler for that:
//
//   - CROSS-SERVICE (vpc/compute/nlb): the owning service re-calls
//     InternalIAMService.RegisterResource on a label update, and RegisterResource runs
//     ReconcileObjectForward in-process. The forward's delete-stale guard sees the
//     object already has members, delegates to the FULL ReconcileObject, and the stale
//     grant is revoked there and then.
//
//   - IAM-DIRECT (this path): Group.Update did NEITHER half. Unlike Group.Create — which
//     co-commits a resource_reconcile_outbox event AND runs ReconcileObjectForward
//     post-commit — the update path emitted no reconcile event at all and re-materialized
//     nothing in-process. So the revoke had no at-least-once queue behind it and no
//     accelerator in front of it: it converged only when the 30s periodic sweep
//     (KACHO_IAM_RECONCILE_SWEEP_INTERVAL_MS) happened to reach the binding.
//
// Adding only the in-process pass would be an accelerator with no durable backstop; adding
// only the event makes revoke latency the DEPTH OF THE GLOBAL RECONCILE QUEUE — strictly
// FIFO, drained by one worker at roughly five events/second, each event a FULL O(scope)
// recompute, against an e2e suite emitting five to eight events/second, i.e. a multi-minute
// backlog. Measured on the stand for the sibling iam.project path: the label-clear event was
// enqueued at 19:59:18.97 and drained at 20:06:49.82 (7m30s), and the tuple only died at
// 20:00:23 when the 30s sweep happened to reach that binding — 65s after the clear, long
// past any client budget. Hence this pins BOTH halves.
//
// Like every other post-commit pass the in-process half runs OFF the Operation.done path
// (ban #9): done reports that the group row is durable, never that its tuples converged.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	accountrepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/account"
	grouprepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

const (
	gremGroupID = "grp0000000000000rmt1"
	gremAcctID  = "acc0000000000000rmt1"
	gremOwnerID = "usr0000000000000rmt1"
)

// ── recording ObjectReconciler (mutex-guarded: the pass is detached) ────────────
//
// Distinct from create_reconcile_test.go's recorder, which is called synchronously on
// the create path and therefore needs no locking.

type gremReconciler struct {
	mu    sync.Mutex
	calls []string
}

func (r *gremReconciler) record(c string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

func (r *gremReconciler) trace() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

// awaitTrace waits (bounded) for `want`, then returns the trace. The pass is detached
// from the operation worker, so operations.Wait does not imply it has run.
func (r *gremReconciler) awaitTrace(want string, budget time.Duration) []string {
	deadline := time.Now().Add(budget)
	for {
		calls := r.trace()
		for _, c := range calls {
			if c == want {
				return calls
			}
		}
		if time.Now().After(deadline) {
			return calls
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *gremReconciler) ReconcileObjectForward(_ context.Context, objectType, objectID string) error {
	r.record("object_forward:" + objectType + ":" + objectID)
	return nil
}

// ReconcileObjectForwardNoStale — ДОКАЗАННЫЙ вход того же прохода. Дублёр обязан
// отвечать на оба, иначе он не удовлетворяет порту; тела совпадают, потому что
// различие входов — про блокировки и чтение у настоящего реконсайлера, а не про
// то, что видит этот тест.
func (r *gremReconciler) ReconcileObjectForwardNoStale(_ context.Context, objectType, objectID string) error {
	r.record("object_forward_nostale:" + objectType + ":" + objectID)
	return nil
}

func (r *gremReconciler) ReconcileObject(_ context.Context, objectType, objectID string) error {
	r.record("object_full:" + objectType + ":" + objectID)
	return nil
}

var _ ObjectReconciler = (*gremReconciler)(nil)

// ── tests ──────────────────────────────────────────────────────────────────────

// TestUpdateGroup_LabelChange_RematerializesObject — clearing a label must co-commit the
// durable reconcile event AND run the in-process object-forward for THIS group, so the
// revoke neither waits out the FIFO reconcile backlog nor depends on the 30s sweep.
func TestUpdateGroup_LabelChange_RematerializesObject(t *testing.T) {
	repo := newGremRepo(domain.Labels{"labelrevoke": "treska"})
	rec := &gremReconciler{}
	uc := NewUpdateGroupUseCase(repo, newLcgOps()).WithObjectReconciler(rec, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: gremOwnerID})

	_, err := uc.Execute(ctx, UpdateGroupInput{
		ID:         gremGroupID,
		Labels:     nil, // proto3 map ⇒ nil body; "labels" in the mask means CLEAR
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	// Durable half — co-committed in the SAME writer-tx as the label write (ban #10),
	// so the revoke has an at-least-once queue behind it even if the process dies here.
	assert.Contains(t, repo.reconciled(), wantReconcileEvent,
		"a label change must co-commit the reconcile event (the at-least-once backstop the "+
			"group update path was missing entirely — without it a revoke converged only when "+
			"the 30s periodic sweep happened to reach the binding)")

	// Accelerator half — the in-process pass the cross-service RegisterResource twin runs.
	want := "object_forward:iam.group:" + gremGroupID
	calls := rec.awaitTrace(want, 5*time.Second)
	assert.Contains(t, calls, want,
		"a label change must re-materialize the group in-process (the forward's delete-stale "+
			"guard routes an object that already has members onto the FULL recompute, which is "+
			"what actually revokes the now-unmatched grant) — leaving it to the FIFO reconcile "+
			"queue made revoke latency a function of unrelated queue depth (measured 7m30s)")
}

// TestUpdateGroup_NonLabelChange_NoRematerialization — a description update cannot flip
// selector membership, so it must emit neither the reconcile event nor the O(scope) pass.
func TestUpdateGroup_NonLabelChange_NoRematerialization(t *testing.T) {
	repo := newGremRepo(domain.Labels{"labelrevoke": "treska"})
	rec := &gremReconciler{}
	uc := NewUpdateGroupUseCase(repo, newLcgOps()).WithObjectReconciler(rec, nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: gremOwnerID})

	newDesc := domain.Description("renamed for the audit trail")
	_, err := uc.Execute(ctx, UpdateGroupInput{
		ID:          gremGroupID,
		Description: &newDesc,
		UpdateMask:  []string{"description"},
	})
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	// Give a stray detached pass a chance to show up before asserting its absence.
	time.Sleep(200 * time.Millisecond)
	assert.Empty(t, repo.reconciled(),
		"only a labels change can flip selector membership — a non-label update must not "+
			"enqueue a reconcile event")
	assert.Empty(t, rec.trace(),
		"only a labels change can flip selector membership — a non-label update must not "+
			"schedule an O(scope) re-materialization")
}

// TestUpdateGroup_LabelChange_NilReconcilerStillEmitsEvent — the accelerator is optional;
// an unwired reconciler must keep the durable half (and must not panic).
func TestUpdateGroup_LabelChange_NilReconcilerStillEmitsEvent(t *testing.T) {
	repo := newGremRepo(domain.Labels{"labelrevoke": "treska"})
	uc := NewUpdateGroupUseCase(repo, newLcgOps()) // no WithObjectReconciler
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: gremOwnerID})

	_, err := uc.Execute(ctx, UpdateGroupInput{
		ID:         gremGroupID,
		Labels:     nil,
		UpdateMask: []string{"labels"},
	})
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	assert.Contains(t, repo.reconciled(), wantReconcileEvent,
		"a nil reconciler drops only the accelerator — the durable event stays")
}

// ── narrow fake repo: only the methods doUpdate touches are implemented ─────────

type reconcileRec struct{ eventType, objectType, objectID string }

// wantReconcileEvent — the exact record doUpdate must co-commit on a label change.
var wantReconcileEvent = reconcileRec{shared.ReconcileEventUpsert, "iam.group", gremGroupID}

type gremRepo struct {
	mu        sync.Mutex
	grp       domain.Group
	reconcile []reconcileRec
}

func newGremRepo(initial domain.Labels) *gremRepo {
	return &gremRepo{grp: domain.Group{
		ID: gremGroupID, AccountID: gremAcctID, Name: "remat-grp", Labels: initial,
		CreatedAt: time.Now().UTC(),
	}}
}

func (r *gremRepo) reconciled() []reconcileRec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]reconcileRec{}, r.reconcile...)
}

func (r *gremRepo) recordReconcile(rec reconcileRec) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reconcile = append(r.reconcile, rec)
}

func (r *gremRepo) group() domain.Group {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.grp
}

func (r *gremRepo) setLabels(l domain.Labels) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grp.Labels = l
}

func (r *gremRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &gremReader{parent: r}, nil
}
func (r *gremRepo) Writer(context.Context) (kachorepo.Writer, error) {
	return &gremWriter{parent: r}, nil
}
func (r *gremRepo) Close() {}

// gremReader embeds kachorepo.Reader (nil): any method Execute does not use panics.
type gremReader struct {
	kachorepo.Reader
	parent *gremRepo
}

func (r *gremReader) Groups() grouprepo.ReaderIface     { return &gremGroupRdr{parent: r.parent} }
func (r *gremReader) Accounts() accountrepo.ReaderIface { return &gremAcctRdr{} }
func (r *gremReader) Rollback(context.Context) error    { return nil }

type gremGroupRdr struct {
	grouprepo.ReaderIface
	parent *gremRepo
}

func (r *gremGroupRdr) Get(context.Context, domain.GroupID) (domain.Group, error) {
	return r.parent.group(), nil
}

type gremAcctRdr struct{ accountrepo.ReaderIface }

func (r *gremAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{ID: id, Name: "acct", OwnerUserID: gremOwnerID, CreatedAt: time.Now().UTC()}, nil
}

// gremWriter embeds kachorepo.Writer (nil): any method doUpdate does not use panics.
type gremWriter struct {
	kachorepo.Writer
	parent *gremRepo
}

func (w *gremWriter) GroupsW() grouprepo.WriterIface { return &gremGroupWtr{parent: w.parent} }
func (w *gremWriter) EmitAuditEvent(context.Context, service.AuditEvent) error {
	return nil
}
func (w *gremWriter) EmitReconcileEvent(_ context.Context, eventType, objectType, objectID string) error {
	w.parent.recordReconcile(reconcileRec{eventType, objectType, objectID})
	return nil
}
func (w *gremWriter) Commit(context.Context) error   { return nil }
func (w *gremWriter) Rollback(context.Context) error { return nil }

type gremGroupWtr struct {
	grouprepo.WriterIface
	parent *gremRepo
}

func (w *gremGroupWtr) Update(_ context.Context, g domain.Group, mask []string) (domain.Group, error) {
	for _, m := range mask {
		if m == "labels" {
			w.parent.setLabels(g.Labels)
		}
	}
	return w.parent.group(), nil
}

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *gremWriter) EmitInviteMail(_ context.Context, userID, _, to, _ string) error {
	if to == "" {
		return fmt.Errorf("invite mail: recipient required")
	}
	if userID == "" {
		return fmt.Errorf("invite mail: user id required")
	}
	return nil
}
