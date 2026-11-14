// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Конструктор связывает ровно один runtime repo с immutable bundle. Режим
// prepared/strict не кэшируется и не задаётся вызывающим; activation здесь нет.
type InviteDecisions struct {
	policy      *GrantPolicyWriters
	legacyPlans *authzmodel.Plans
}

func NewInviteDecisionRunner(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*InviteDecisions, error) {
	p, err := NewGrantPolicyWriters(ctx, repo, bundle)
	if err != nil {
		return nil, err
	}
	plans, err := authzmodel.New(bundle.ModelSource())
	if err != nil {
		return nil, err
	}
	return &InviteDecisions{policy: p, legacyPlans: plans}, nil
}
func validateInviteIntent(ctx context.Context, in kaname.InviteDecisionIntent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in.Actor.Validate() != nil || (in.Actor.Type != domain.SubjectTypeUser && in.Actor.Type != domain.SubjectTypeServiceAccount) || in.Actor.ID == "*" {
		return iamerr.ErrPermissionDenied
	}
	principal, ok := authzguard.PrincipalSubject(ctx)
	if !ok || principal != string(in.Actor.Type)+":"+string(in.Actor.ID) || string(in.InvitedBy) != authzguard.HumanUserID(ctx) || string(in.GrantedBy) != authzguard.PrincipalUserID(ctx) {
		return iamerr.ErrPermissionDenied
	}
	if in.Email.Validate() != nil || !nativeQuestionToken(string(in.AccountID)) || !nativeQuestionToken(string(in.CandidateUserID)) || !strings.HasPrefix(string(in.CandidateUserID), domain.PrefixUser) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if (in.ProjectID == "") != (in.RoleID == "") || (in.ProjectID == "") != (in.BindingID == "") {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if in.ProjectID != "" && (!nativeQuestionToken(string(in.ProjectID)) || !nativeQuestionToken(string(in.RoleID)) || !nativeQuestionToken(string(in.BindingID))) {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	return nil
}
func (p *InviteDecisions) RunInviteDecision(ctx context.Context, in kaname.InviteDecisionIntent, body func(context.Context, kaname.InviteMutationWriter, kaname.PreparedInvite) error) error {
	if p == nil || p.policy == nil || p.policy.repo == nil || body == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if err := validateInviteIntent(ctx, in); err != nil {
		return err
	}
	return runInviteAttempts(ctx, func() error { return p.once(ctx, in, body) })
}

// Каждая повторная попытка заново получает RR, RC и закрытый prepared результат.
func runInviteAttempts(ctx context.Context, once func() error) error {
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = once()
		if last == nil {
			return nil
		}
		if ctx.Err() != nil {
			var cleanup *inviteCleanupError
			if errors.As(last, &cleanup) {
				return errors.Join(ctx.Err(), last)
			}
			return ctx.Err()
		}
		var cleanup *inviteCleanupError
		if errors.As(last, &cleanup) || (!policyRetry(last) && !errors.Is(last, iamerr.ErrAborted)) {
			return last
		}
	}
	return errors.Join(iamerr.ErrAborted, last)
}
func (p *InviteDecisions) once(ctx context.Context, in kaname.InviteDecisionIntent, body func(context.Context, kaname.InviteMutationWriter, kaname.PreparedInvite) error) (err error) {
	conn, err := p.policy.repo.master.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	// Закрываем RR до RC. Защита дополнительно нужна при любом раннем возврате.
	defer inviteRollback(ctx, snapshot, &err)
	phase, err := readInvitePhase(ctx, snapshot, false)
	if err != nil {
		return err
	}
	if phase.Identity != p.policy.bundle.Identity() {
		return kaname.ErrSemanticIdentityUnavailable
	}
	identity, err := readInviteIdentity(ctx, snapshot, in)
	if err != nil {
		return err
	}
	oldRole, err := inviteRole(ctx, snapshot, in)
	if err != nil {
		return err
	}
	var plan *policyPlan
	if phase.Phase == "active" {
		questions := newNativePolicyQuestions()
		if err = questions.invite(in.Actor, in.AccountID, in.ProjectID, in.RoleID); err != nil {
			return err
		}
		// Считаем logical rows/derived slots, не physical I/O: metadata +
		// person/candidate/issued/membership и итог identity snapshot.
		reads, rows := 2, 6
		req := policyWriteRequest{kind: kaname.AuthorityIdentity, actor: in.Actor, global: true, owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: string(in.AccountID)}}, nativeQuestions: questions}
		if identity.existing {
			req.mutationSubjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(identity.recipient)}}
		}
		if in.ProjectID != "" {
			req.owners = append(req.owners, kaname.AuthorityOwnerRef{Kind: "project", ID: string(in.ProjectID)})
			req.readRoles = []domain.RoleID{in.RoleID}
			reads += 2
			rows += 2
		}
		req.consumedReads = reads
		plan, err = p.policy.discoverPolicyPlanWithRows(ctx, snapshot, req, rows)
		if err != nil {
			return err
		}
	}
	if err = policyRollback(ctx, snapshot); err != nil {
		return &inviteCleanupError{err}
	}
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: p.policy.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	if err = validateAuthorityIntent(intent); err != nil {
		return err
	}
	w, err := enterInviteWriter(ctx, conn.BeginTx, func(ctx context.Context, tx pgx.Tx) (*authorityWriteTx, error) {
		return p.policy.repo.enterAuthority(ctx, tx, intent, []byte("[]"), kaname.AuthorityFenceGlobal, nil, false, "participant")
	})
	if err != nil {
		return err
	}
	defer inviteRollback(ctx, w.tx, &err)
	if plan != nil {
		if err = chargeNativePolicyBudget(plan.nativeBudget, 7, 4); err != nil {
			return err
		}
		if in.ProjectID != "" {
			if err = chargeNativePolicyBudget(plan.nativeBudget, 2, 2); err != nil {
				return err
			}
		}
	}
	held, err := readInvitePhase(ctx, w.tx, true)
	if err != nil {
		return err
	}
	if held != phase {
		return kaname.ErrAuthorityClassificationChanged
	}
	// Все table/row/FK/sequence ожидания предшествуют финальному protect/clock.
	if _, err = w.tx.Exec(ctx, `SELECT kaname.authority_invite_preflight($1)`, in.ProjectID != ""); err != nil {
		return err
	}
	current, err := readInviteIdentity(ctx, w.tx, in)
	if err != nil {
		return err
	}
	if current != identity {
		return kaname.ErrAuthorityClassificationChanged
	}
	role, err := inviteRole(ctx, w.tx, in)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(oldRole, role) {
		return kaname.ErrAuthorityClassificationChanged
	}
	held, err = readInvitePhase(ctx, w.tx, true)
	if err != nil {
		return err
	}
	if held != phase {
		return kaname.ErrAuthorityClassificationChanged
	}
	var checker kaname.RelationChecker
	if plan != nil {
		if err = p.policy.protectPolicyPlan(ctx, w, plan); err != nil {
			return err
		}
		if err = chargeNativePolicyBudget(plan.nativeBudget, 1, 1); err != nil {
			return err
		}
		var eligible bool
		if err = w.tx.QueryRow(ctx, `SELECT CASE $1 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$2 AND invite_status='ACTIVE' AND email_verified_at IS NOT NULL) WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2 AND enabled) ELSE false END`, string(in.Actor.Type), string(in.Actor.ID)).Scan(&eligible); err != nil {
			return err
		}
		if !eligible {
			return iamerr.ErrPermissionDenied
		}
		checker = newInviteAccountChecker(w, p.policy.bundle, in.Actor)
	} else {
		// Prepared сохраняет обычный native cascade, без нового semantic producer.
		var at time.Time
		if err = w.tx.QueryRow(ctx, `SELECT kaname.authority_invite_final_clock()`).Scan(&at); err != nil {
			return err
		}
		w.fence.decisionAt = at.UTC()
		form := relverdict.NewTransactionAsker(w.tx, p.legacyPlans, w.fence.decisionAt)
		checker = authzcascade.WrapAdmitted(form, personmarks.NewTransaction(w.tx))
	}
	allowed := false
	for _, relation := range []string{"editor", "admin", "owner"} {
		ok, e := checker.Check(ctx, string(in.Actor.Type)+":"+string(in.Actor.ID), relation, "account:"+string(in.AccountID))
		if e != nil {
			return e
		}
		allowed = allowed || ok
		if allowed {
			break
		}
	}
	if !allowed {
		return iamerr.ErrPermissionDenied
	}
	binding := inviteBinding(in, identity.recipient)
	semantic := newSemanticAuthorityWriter(w, p.policy.bundle)
	if plan != nil && in.ProjectID != "" {
		// scopeObjects читает project и account вне actor collector.
		if err = chargeNativePolicyBudget(plan.nativeBudget, 2, 2); err != nil {
			return err
		}
		if err = grantpolicy.RequireBinding(ctx, semantic, in.Actor, granteffect.Binding{SourceID: string(binding.ID), Role: role, Scope: domain.ScopeAnchor{Type: "project", ID: string(in.ProjectID)}, Target: binding.Target, Subjects: binding.Subjects, CapabilityVersion: 1}); err != nil {
			return err
		}
	}
	prepared := &preparedInvite{recipient: identity.recipient, binding: binding, at: w.fence.decisionAt}
	facade := &inviteMutationFacade{InviteMutationWriter: w, bindings: &inviteBindingWriter{WriterIface: w.AccessBindingsW(), semantic: semantic, prepared: prepared, active: plan != nil}}
	if err = body(ctx, facade, prepared); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// Embedded порт намеренно узкий: lifecycle owner не становится частью callback.
type inviteMutationFacade struct {
	kaname.InviteMutationWriter
	bindings ab.WriterIface
}

func (w *inviteMutationFacade) AccessBindingsW() ab.WriterIface { return w.bindings }

type inviteBindingWriter struct {
	ab.WriterIface
	semantic *semanticAuthorityWriteTx
	prepared *preparedInvite
	active   bool
}

func (w *inviteBindingWriter) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	if w.prepared.binding.ID == "" || !reflect.DeepEqual(b, w.prepared.Binding()) {
		return domain.AccessBinding{}, kaname.ErrInvalidAuthorityFencePlan
	}
	if w.active {
		return w.semantic.InsertBindingWithCapabilities(ctx, b)
	}
	return w.WriterIface.Insert(ctx, b)
}

var _ kaname.InviteDecisionRunner = (*InviteDecisions)(nil)

// Entry не повторяется отдельно от RR. Неудачный rollback терминален и хранит
// исходную SQL ошибку, отмену и ошибку cleanup в одной цепочке.
func enterInviteWriter(ctx context.Context, begin func(context.Context, pgx.TxOptions) (pgx.Tx, error), enter func(context.Context, pgx.Tx) (*authorityWriteTx, error)) (*authorityWriteTx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	w, err := enter(ctx, tx)
	if err == nil {
		return w, nil
	}
	if cleanup := policyRollback(ctx, tx); cleanup != nil {
		return nil, &inviteCleanupError{errors.Join(err, ctx.Err(), cleanup)}
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ctx.Err(), err)
	}
	return nil, err
}
