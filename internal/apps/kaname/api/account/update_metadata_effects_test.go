// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package account

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	rowrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Дублёр меняет OLD после синхронного Get, перед открытием каждой попытки.
// Изменения строки и события становятся видимыми только при Commit.
type metadataEffectsFactory struct {
	repo    *labelRoutingRepo
	old     []domain.Labels
	opens   int
	missing bool
	audits  []service.AuditEvent
}

func (f *metadataEffectsFactory) AccountMetadataWriter(_ context.Context, target domain.Account, mask []string, _ domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	old := maps.Clone(f.old[f.opens])
	f.opens++
	staged := &labelRoutingRepo{lcaRepo: newLcaRepo(old)}
	staged.acct = f.repo.acct
	staged.acct.Labels = old
	base := &metadataEffectsBaseWriter{factory: f, staged: staged}
	if f.missing {
		return base, nil
	}
	var changed []string
	if shared.MaskAllows(mask, "labels") && !maps.Equal(old, target.Labels) {
		changed = append(changed, "labels")
	}
	return &metadataEffectsWriter{metadataEffectsBaseWriter: base, changed: changed}, nil
}

func (f *metadataEffectsFactory) ExecutePreparedWrite(ctx context.Context, open func(context.Context) (kaname.Writer, error), action func(context.Context, kaname.Writer) error) error {
	for f.opens < len(f.old) {
		w, err := open(ctx)
		if err != nil {
			return err
		}
		if err = action(ctx, w); err != nil {
			_ = w.Rollback(ctx)
			return err
		}
		if f.opens < len(f.old) {
			// Первая успешная запись не коммитится: следующая попытка читает новый OLD.
			if err = w.Rollback(ctx); err != nil {
				return err
			}
			continue
		}
		return w.Commit(ctx)
	}
	panic("нет попытки")
}

type metadataEffectsBaseWriter struct {
	kaname.SemanticAuthorityWriter
	factory   *metadataEffectsFactory
	staged    *labelRoutingRepo
	audits    []service.AuditEvent
	reconcile []string
}

func (w *metadataEffectsBaseWriter) AccountsW() rowrepo.WriterIface {
	return &labelRoutingRow{repo: w.staged}
}
func (w *metadataEffectsBaseWriter) EmitAuditEvent(_ context.Context, ev service.AuditEvent) error {
	w.audits = append(w.audits, ev)
	return nil
}
func (w *metadataEffectsBaseWriter) EmitReconcileEvent(_ context.Context, _, _ string, id string) error {
	w.reconcile = append(w.reconcile, id)
	return nil
}
func (w *metadataEffectsBaseWriter) Commit(context.Context) error {
	w.factory.repo.acct = w.staged.acct
	w.factory.repo.writes += w.staged.writes
	w.factory.repo.reconcil = append(w.factory.repo.reconcil, w.reconcile...)
	w.factory.audits = append(w.factory.audits, w.audits...)
	return nil
}
func (w *metadataEffectsBaseWriter) Rollback(context.Context) error { return nil }

type metadataEffectsWriter struct {
	*metadataEffectsBaseWriter
	changed []string
}

func (w *metadataEffectsWriter) MetadataChangedFields() []string {
	return append([]string(nil), w.changed...)
}

type metadataEffectsReconciler struct{ calls chan string }

func (r *metadataEffectsReconciler) ReconcileObjectForward(_ context.Context, typ, id string) error {
	r.calls <- typ + ":" + id
	return nil
}

func (r *metadataEffectsReconciler) ReconcileObject(_ context.Context, typ, id string) error {
	r.calls <- "full:" + typ + ":" + id
	return nil
}

func TestUpdateAccountUsesCommittedMetadataEffects(t *testing.T) {
	requested := domain.Labels{"tier": "requested"}
	concurrent := domain.Labels{"tier": "concurrent"}
	for _, tc := range []struct {
		name       string
		initial    domain.Labels
		old        []domain.Labels
		wantChange bool
		missing    bool
	}{
		{name: "sync_noop_transaction_delta", initial: requested, old: []domain.Labels{concurrent}, wantChange: true},
		{name: "sync_delta_transaction_noop", initial: concurrent, old: []domain.Labels{requested}},
		{name: "retry_discards_first_delta", initial: requested, old: []domain.Labels{concurrent, requested}},
		{name: "retry_uses_last_delta", initial: requested, old: []domain.Labels{requested, concurrent}, wantChange: true},
		{name: "protected_missing_effects", initial: requested, old: []domain.Labels{concurrent}, missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &labelRoutingRepo{lcaRepo: newLcaRepo(maps.Clone(tc.initial))}
			factory := &metadataEffectsFactory{repo: repo, old: tc.old, missing: tc.missing}
			ops := &labelRoutingOps{lcaOps: newLcaOps()}
			reconciler := &metadataEffectsReconciler{calls: make(chan string, 2)}
			uc := NewUpdateAccountUseCase(repo, ops).WithAccountLabelAuthorityWriter(factory).WithObjectReconciler(reconciler)
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: lcaOwnerID})
			op, err := uc.Execute(ctx, UpdateAccountInput{ID: lcaAcctID, Labels: maps.Clone(requested), UpdateMask: []string{"labels"}})
			require.NoError(t, err)
			require.NotNil(t, op)
			wait, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			require.NoError(t, operations.Wait(wait))
			if tc.missing {
				require.False(t, ops.done)
				require.NotNil(t, ops.failure)
				require.Equal(t, int32(codes.Unavailable), ops.failure.Code)
				require.Zero(t, repo.writes)
				require.Equal(t, tc.initial, repo.acct.Labels)
			} else {
				require.True(t, ops.done)
				require.Nil(t, ops.failure)
				require.Equal(t, len(tc.old), factory.opens)
				require.Equal(t, 1, repo.writes, "фиксируется только последняя попытка")
				require.Equal(t, requested, repo.acct.Labels)
			}
			if tc.wantChange {
				require.Len(t, factory.audits, 1)
				require.Equal(t, []string{"labels"}, factory.audits[0].Payload["changed_fields"])
				require.Equal(t, []string{lcaAcctID}, repo.reconciled())
				select {
				case call := <-reconciler.calls:
					require.Equal(t, "iam.account:"+lcaAcctID, call)
				case <-wait.Done():
					t.Fatal("нет post-commit reconcile фактического изменения")
				}
			} else {
				require.Empty(t, factory.audits, "синхронная или отменённая дельта не создаёт audit")
				require.Empty(t, repo.reconciled(), "синхронная или отменённая дельта не создаёт outbox")
			}
		})
	}
}

var _ kaname.AccountMetadataWriterFactory = (*metadataEffectsFactory)(nil)
var _ kaname.PreparedWriteExecutor = (*metadataEffectsFactory)(nil)
var _ kaname.MetadataUpdateEffects = (*metadataEffectsWriter)(nil)
