// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// kaname#1034: reuse того же приватного bundle, без второго startup cache.
func (p *GroupMembershipParticipant) GroupLifecycleWriter(ctx context.Context, kind kaname.GroupMutation, g domain.Group) (kaname.Writer, error) {
	if kind != kaname.GroupCreate && kind != kaname.GroupUpdate && kind != kaname.GroupDelete {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	w, err := p.groupObjectWriter(ctx, string(kind), g)
	if err != nil {
		return nil, err
	}
	return w, nil
}
func (p *GroupMembershipParticipant) groupObjectWriter(ctx context.Context, kind string, g domain.Group) (*authorityWriteTx, error) {
	if p == nil || p.repo == nil || g.ID == "" || strings.ContainsAny(string(g.ID)+string(g.AccountID), ":#* \t\r\n") {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	read := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}) (groupMembershipScope, error) {
		if kind == "delete" {
			return groupMembershipScope{global: true}, nil
		}
		var s groupMembershipScope
		if kind == "create" {
			if g.AccountID == "" {
				return s, kaname.ErrInvalidAuthorityFencePlan
			}
			err := q.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_group_object_scopes($1,$2)`, string(g.ID), string(g.AccountID)).Scan(&s.accounts, &s.global)
			return s, err
		}
		err := q.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_group_object_scopes($1)`, string(g.ID)).Scan(&s.accounts, &s.global)
		return s, err
	}
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		initial, err := read(p.repo.master)
		if err != nil {
			return nil, err
		}
		in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityGroup, Bundle: p.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
		if !initial.global {
			in.Plan.Mode = kaname.AuthorityFenceAccounts
			for _, a := range initial.accounts {
				in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
				in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
			}
		}
		// Отсутствующий объект после DELETE требует global: owner ref тут уже нет.
		w, err := p.repo.coordinatedAuthorityWriter(ctx, in, "participant")
		if err != nil {
			return nil, err
		}
		actual, err := read(w.tx)
		same := err == nil && initial.global == actual.global && (actual.global || slices.Equal(initial.accounts, actual.accounts))
		if same {
			f := w.AuthorityFence()
			same = (actual.global && f.Mode() == kaname.AuthorityFenceGlobal) || (!actual.global && f.Mode() == kaname.AuthorityFenceAccounts && slices.EqualFunc(actual.accounts, f.Accounts(), func(a string, b domain.AccountID) bool { return a == string(b) }))
		}
		if same && ctx.Err() == nil {
			return w, nil
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		re := w.Rollback(cleanup)
		cancel()
		if re != nil && !errors.Is(re, pgx.ErrTxClosed) {
			return nil, errors.Join(err, re)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}

// NewGroupObjectReconciler отдаёт настоящий single-object engine. Его full-binding
// entry закрыт; старый полный sweep отдельно остаётся обязательным остатком.
func (p *GroupMembershipParticipant) NewGroupObjectReconciler(logger *slog.Logger) (*reconcile.Reconciler, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	var halves catalog.Halves
	if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	return reconcile.New(&groupObjectTransactions{participant: p, facts: facts}, logger, catalog.Fixed{F: facts}), nil
}

type groupObjectTransactions struct {
	participant *GroupMembershipParticipant
	facts       *catalog.Facts
}

func (*groupObjectTransactions) WithTx(context.Context, func(context.Context, reconcile.ReconcileStore) error) error {
	return errors.New("group participant requires a single object intent")
}
func (p *groupObjectTransactions) WithObjectTx(ctx context.Context, typ, id string, fn func(context.Context, reconcile.ReconcileStore) error) error {
	if typ != "iam.group" || fn == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	w, err := p.participant.groupObjectWriter(ctx, "reconcile", domain.Group{ID: domain.GroupID(id)})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = fn(ctx, &reconcileStore{tx: w.tx, cat: p.facts, decisionAt: w.AuthorityFence().DecisionAt()}); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}
func (s *reconcileStore) bindingScope(b domain.AccessBinding, role domain.Role) reconcile.BindingScope {
	out := bindingScopeFrom(s.cat, b, role)
	// Legacy caller сохраняет прежний контракт; participant использует единый
	// post-wait decision_at, включая forward batch и полный single-object путь.
	if !s.decisionAt.IsZero() && b.ExpiresAt != nil && !b.ExpiresAt.After(s.decisionAt) {
		out.Active = false
	}
	return out
}

var _ kaname.GroupLifecycleWriterFactory = (*GroupMembershipParticipant)(nil)
var _ reconcile.ObjectTxRunner = (*groupObjectTransactions)(nil)
