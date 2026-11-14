// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// GrantDelegationParticipant хранит единственный immutable startup handoff.
// Это обычный writer protocol, без включения публичных D1/D2/D3 gates.
type GrantDelegationParticipant struct {
	repo   *Repository
	bundle *granteffect.Bundle
}

func NewGrantDelegationParticipant(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*GrantDelegationParticipant, error) {
	if repo == nil || repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	if err := validatePolicyEpochStorage(ctx, repo); err != nil {
		return nil, err
	}
	return &GrantDelegationParticipant{repo: repo, bundle: bundle}, nil
}

type delegationScope struct {
	accounts []string
	global   bool
	refs     []kaname.AuthorityOwnerRef
	creator  domain.GrantDelegationActor
}

func readDelegationScope(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, kind kaname.GrantDelegationMutation, proposed domain.GrantDelegation) (delegationScope, error) {
	var s delegationScope
	current := proposed
	if kind == kaname.GrantDelegationUpdate {
		var roles []string
		var account, delegate string
		err := q.QueryRow(ctx, `SELECT account_id,delegate_id,role_ids,delegated_by_type,delegated_by_id FROM kaname.grant_delegations WHERE id=$1`, string(proposed.ID)).Scan(&account, &delegate, &roles, &current.DelegatedBy.Type, &current.DelegatedBy.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s, grantDelegationNotFound(proposed.ID)
		}
		if err != nil {
			return s, err
		}
		current.AccountID = domain.AccountID(account)
		current.DelegateID = domain.ServiceAccountID(delegate)
		current.RoleIDs = make([]domain.RoleID, len(roles))
		for i, r := range roles {
			current.RoleIDs[i] = domain.RoleID(r)
		}
	}
	s.creator = current.DelegatedBy
	s.refs = []kaname.AuthorityOwnerRef{{Kind: "account", ID: string(current.AccountID)}, {Kind: "service_account", ID: string(current.DelegateID)}}
	roles := append(slices.Clone(current.RoleIDs), proposed.RoleIDs...)
	slices.Sort(roles)
	roles = slices.Compact(roles)
	for _, r := range roles {
		s.refs = append(s.refs, kaname.AuthorityOwnerRef{Kind: "role", ID: string(r)})
	}
	// Неверная/неизвестная форма не становится расширением открытой TX.
	if len(s.refs) > kaname.MaxAuthorityOwnershipRefs {
		s.global = true
		s.refs = nil
		return s, nil
	}
	refs, err := json.Marshal(s.refs)
	if err != nil {
		return s, err
	}
	err = q.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_discover($1::jsonb)`, refs).Scan(&s.accounts, &s.global)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "P1035" {
		// Отсутствующий anchor не доказывает account-local область. Global
		// выбирается до locks; штатная проверка use-case решит существование.
		s.global = true
		s.refs = nil
		err = nil
	}
	if len(s.accounts) > kaname.MaxAuthorityFenceAccounts {
		s.global = true
	}
	return s, err
}
func (s delegationScope) intent(bundle *granteffect.Bundle) kaname.AuthorityWriteIntent {
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityDelegation, Bundle: bundle, Owners: s.refs, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	if !s.global {
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range s.accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
		}
	}
	return in
}
func (p *GrantDelegationParticipant) GrantDelegationWriter(ctx context.Context, kind kaname.GrantDelegationMutation, proposed domain.GrantDelegation) (kaname.Writer, error) {
	return p.openDelegationPolicyWriter(ctx, kind, proposed)
}

type grantDelegationWriteTx struct {
	*authorityWriteTx
	bundle          *granteffect.Bundle
	policy          *GrantPolicyWriters
	policyPlan      *policyPlan
	policyScope     delegationScope
	policyKind      kaname.GrantDelegationMutation
	policyProposed  domain.GrantDelegation
	bindingEpoch    json.RawMessage
	bindingAccounts []string
}

// Legacy pair/row locks могли ждать совместимого писателя. Время native
// проверки обновляется после этих ожиданий и используется всеми её вопросами.
func (w *grantDelegationWriteTx) RefreshGrantDelegationDecision(ctx context.Context) error {
	if w.policy == nil || w.policyPlan == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	actual, err := readDelegationScope(ctx, w.tx, w.policyKind, w.policyProposed)
	if err != nil {
		return delegationPolicyError(err)
	}
	if !sameDelegationScope(actual, w.policyScope) {
		return delegationPolicyError(kaname.ErrAuthorityClassificationChanged)
	}
	if err = grantMutationPreflight(ctx, w.tx, "delegation"); err != nil {
		return delegationPolicyError(err)
	}
	// При >256 refs scope заранее GLOBAL и refs пуст. Сам FK referent при
	// этом не исчезает: Create берёт proposal, Update — уже locked OLD header.
	delegate := string(w.policyProposed.DelegateID)
	if w.policyKind == kaname.GrantDelegationUpdate {
		if err = w.tx.QueryRow(ctx, `SELECT delegate_id FROM kaname.grant_delegations WHERE id=$1`, string(w.policyProposed.ID)).Scan(&delegate); err != nil {
			return delegationPolicyError(err)
		}
	}
	if err = grantPrincipalPrelock(ctx, w.tx, "service_account", delegate); err != nil {
		return delegationPolicyError(err)
	}
	return delegationPolicyError(w.protectDelegationSources(ctx))
}

func (w *grantDelegationWriteTx) Commit(ctx context.Context) error {
	return delegationPolicyError(w.authorityWriteTx.Commit(ctx))
}

func (w *grantDelegationWriteTx) TransactionRelationChecker(_ *authzmodel.Plans) (kaname.RelationChecker, error) {
	if err := w.bundle.Validate(); err != nil {
		return nil, err
	}
	return newLiveAdministrativeChecker(w.authorityWriteTx, w.bundle), nil
}
func (w *grantDelegationWriteTx) RequireInstallationAuthority(ctx context.Context, _ *authzmodel.Plans) error {
	checker, err := w.TransactionRelationChecker(nil)
	if err != nil {
		return err
	}
	return authzguard.RequireClusterAdmin(ctx, checker)
}

var _ kaname.GrantDelegationWriterFactory = (*GrantDelegationParticipant)(nil)

// Даже отменённый worker обязан вернуть pool slot и освободить fences.
func (w *grantDelegationWriteTx) Rollback(ctx context.Context) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return w.authorityWriteTx.Rollback(cleanup)
}

// Обычный Create сохраняет старый pair lock до повторной native проверки;
// повторное получение этого же xact lock внутри Insert безопасно. Никакого
// второго соединения или новой policy здесь нет.
func (w *grantDelegationWriteTx) LockGrantDelegationCreate(ctx context.Context, d domain.GrantDelegation) error {
	writer := &gdWriter{gdReader: gdReader{tx: w.tx}}
	if err := writer.lockPair(ctx, d.AccountID, d.DelegateID); err != nil {
		return err
	}
	return w.RefreshGrantDelegationDecision(ctx)
}
