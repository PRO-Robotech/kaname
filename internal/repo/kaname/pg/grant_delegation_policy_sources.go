// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

func sameDelegationScope(a, b delegationScope) bool {
	return a.global == b.global && a.creator == b.creator && slices.Equal(a.accounts, b.accounts) && slices.Equal(a.refs, b.refs)
}
func delegationPolicyError(err error) error {
	if policyRetry(err) {
		return errors.Join(iamerr.ErrAborted, err)
	}
	return err
}

// Caller и сохранённый creator kaname#1032 могут опираться на разные источники.
// Оба census выполнены в ОДНОМ RR snapshot до любых authority/business locks.
// Итоговый epoch token перечитывается для полного union, а не склеивается из JSON.
func (p *GrantDelegationParticipant) discoverDelegationPolicy(ctx context.Context, tx pgx.Tx, policy *GrantPolicyWriters, kind kaname.GrantDelegationMutation, proposed domain.GrantDelegation) (*policyPlan, delegationScope, error) {
	scope, err := readDelegationScope(ctx, tx, kind, proposed)
	if err != nil {
		return nil, scope, err
	}
	actor := grantpolicy.Actor(ctx)
	in := policyWriteRequest{actor: actor, kind: kaname.AuthorityDelegation, owners: scope.refs, global: scope.global}
	// OLD/NEW delegation producer пишет epoch delegate и сохранённого автора.
	// Их exclusive keys предвыбраны до GD row/pair locks, без upgrade в DML.
	in.mutationSubjects = append(in.mutationSubjects, domain.Subject{Type: domain.SubjectType(scope.creator.Type), ID: domain.SubjectID(scope.creator.ID)})
	for _, ref := range scope.refs {
		if ref.Kind == "role" {
			in.readRoles = append(in.readRoles, domain.RoleID(ref.ID))
		}
		if ref.Kind == "service_account" {
			in.mutationSubjects = append(in.mutationSubjects, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(ref.ID)})
		}
	}
	plan, err := policy.discoverPolicyPlan(ctx, tx, in)
	if err != nil {
		return nil, scope, err
	}
	if kind == kaname.GrantDelegationUpdate {
		creator := domain.Subject{Type: domain.SubjectType(scope.creator.Type), ID: domain.SubjectID(scope.creator.ID)}
		if creator != actor {
			in.actor = creator
			other, e := policy.discoverPolicyPlanWithRows(ctx, tx, in, plan.rows)
			if e != nil {
				return nil, scope, e
			}
			plan.rows = other.rows
			plan.global = plan.global || other.global
			for account := range other.accounts {
				plan.add(account, "", false)
			}
			for key := range other.guards {
				plan.add("", key, false)
			}
			for key := range other.exclusive {
				plan.write(key)
			}
		}
	}
	plan.finishClassification()
	keys := []string{"*"}
	if !plan.global {
		for key := range plan.guards {
			if key != "*" {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&plan.epochs); err != nil {
		return nil, scope, err
	}
	return plan, scope, ctx.Err()
}

// Один leased pool slot. RR завершён ДО fresh RC coordinator, без business
// locks и без all-account inventory под fence. При конфликте вся попытка
// откатывается; последующая классификация снова читает текущие источники.
func (p *GrantDelegationParticipant) openDelegationPolicyWriter(ctx context.Context, kind kaname.GrantDelegationMutation, proposed domain.GrantDelegation) (kaname.Writer, error) {
	if p == nil || p.repo == nil || p.repo.master == nil || proposed.ID == "" || (kind != kaname.GrantDelegationCreate && kind != kaname.GrantDelegationUpdate) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	actor := grantpolicy.Actor(ctx)
	if actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := p.bundle.Validate(); err != nil {
		return nil, err
	}
	policy := &GrantPolicyWriters{repo: p.repo, bundle: p.bundle}
	conn, err := p.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return nil, e
		}
		plan, scope, e := p.discoverDelegationPolicy(ctx, snapshot, policy, kind, proposed)
		var bindingAccounts []string
		var bindingEpoch json.RawMessage
		if e == nil {
			intent := plan.intent(p.bundle)
			if intent.Plan.Mode == kaname.AuthorityFenceAccounts {
				for _, account := range intent.Plan.Accounts {
					bindingAccounts = append(bindingAccounts, string(account))
				}
			}
			e = snapshot.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, bindingAccounts).Scan(&bindingEpoch)
		}
		cleanup := policyRollback(ctx, snapshot)
		if cleanup != nil {
			return nil, errors.Join(e, cleanup)
		}
		if e != nil {
			if policyRetry(e) {
				continue
			}
			return nil, e
		}
		intent := plan.intent(p.bundle)
		if e = validateAuthorityIntent(intent); e != nil {
			return nil, e
		}
		owners, e := json.Marshal(intent.Owners)
		if e != nil {
			return nil, e
		}
		tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			return nil, e
		}
		w, e := p.repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, "participant")
		if e == nil {
			var actual delegationScope
			actual, e = readDelegationScope(ctx, tx, kind, proposed)
			if e == nil && !sameDelegationScope(actual, scope) {
				e = kaname.ErrAuthorityClassificationChanged
			}
		}
		candidate := &grantDelegationWriteTx{authorityWriteTx: w, bundle: p.bundle, policy: policy, policyPlan: plan, policyScope: scope, policyKind: kind, policyProposed: proposed, bindingEpoch: bindingEpoch, bindingAccounts: bindingAccounts}
		if e == nil {
			e = candidate.protectDelegationSources(ctx)
		}
		if e != nil {
			cleanup = policyRollback(ctx, tx)
			if cleanup != nil {
				return nil, errors.Join(e, cleanup)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if policyRetry(e) {
				continue
			}
			return nil, delegationPolicyError(e)
		}
		w.tx = &policyLeaseTx{Tx: tx, conn: conn}
		transferred = true
		return candidate, nil
	}
	return nil, delegationPolicyError(kaname.ErrAuthorityClassificationChanged)
}

// Staged Revoke имеет собственный полный read-set, guard union и recheck.
// Embedded Create/Update refresh не должен подменять его nil policy либо clock-only.
func (w *grantDelegationRevokeTx) RefreshGrantDelegationDecision(ctx context.Context) error {
	if w == nil || w.stage == nil || w.applied {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return delegationRevokeStageError(w.stage.recheck(ctx, w.authorityWriteTx))
}

// Порядок совпадает с withdrawal stage: policy guards, затем A epoch rows.
// Epoch metadata читается в том же RR, а после обоих ожиданий SQL обновляет
// private participant decision_at. Под fence нет повторного inventory walk.
func (w *grantDelegationWriteTx) protectDelegationSources(ctx context.Context) error {
	if err := w.policy.protectPolicyPlan(ctx, w.authorityWriteTx, w.policyPlan); err != nil {
		return err
	}
	var at time.Time
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, w.bindingAccounts, []byte(w.bindingEpoch)).Scan(&at); err != nil {
		return err
	}
	w.fence.decisionAt = at.UTC()
	return ctx.Err()
}
