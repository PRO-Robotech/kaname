// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (p *GrantPolicyWriters) RunBindingDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding, create bool,
	tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	return p.runBindingDecision(ctx, actor, proposed, create, nil, tuples, apply)
}

// kaname#1034, kaname#986: захваченный ID не меняется даже при serialization retry.
func (p *GrantPolicyWriters) RunDelegatedBindingDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding,
	tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	if actor.Type != domain.SubjectTypeServiceAccount {
		return iamerr.ErrPermissionDenied
	}
	captured := proposed.DelegationID
	return p.runBindingDecision(ctx, actor, proposed, true, &captured, tuples, apply)
}
func (p *GrantPolicyWriters) runBindingDecision(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding, create bool,
	captured *domain.GrantDelegationID, tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	if p == nil || p.repo == nil || apply == nil || proposed.ID == "" || actor.Validate() != nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var last error
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = p.bindingDecisionOnce(ctx, actor, proposed, create, captured, tuples, apply)
		if last == nil {
			return nil
		}
		var pe *pgconn.PgError
		if !errors.Is(last, kaname.ErrAuthorityClassificationChanged) && !errors.Is(last, iamerr.ErrAborted) && status.Code(last) != codes.Aborted && (!errors.As(last, &pe) || (pe.Code != "40001" && pe.Code != "40P01")) {
			return last
		}
	}
	return fmt.Errorf("binding decision retry exhausted: %w", errors.Join(iamerr.ErrAborted, last))
}
func (p *GrantPolicyWriters) bindingDecisionOnce(ctx context.Context, actor domain.Subject, proposed domain.AccessBinding, create bool,
	captured *domain.GrantDelegationID, tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
	apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	conn, err := p.repo.master.Acquire(ctx)
	if err != nil {
		return mapErr(err, "", "")
	}
	defer conn.Release()
	snapshot, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return mapErr(err, "", "")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = snapshot.Rollback(cleanup)
	}()
	reader := &readTx{tx: snapshot}
	b := proposed
	if !create {
		b, err = reader.AccessBindings().Get(ctx, proposed.ID)
		if err != nil {
			return err
		}
		b.Subjects, err = reader.AccessBindings().ListSubjects(ctx, b.ID)
		if err != nil {
			return err
		}
	}
	// Discovery не судит authority: фиксирует ID до fences. Решение повторяется
	// после всех waits. Отсутствие/замена GD не открывает обычный fallback.
	if captured != nil {
		if *captured == "" {
			account := domain.AccountID(b.ResourceID)
			switch b.ResourceType {
			case "account":
			case "project":
				project, e := reader.Projects().Get(ctx, domain.ProjectID(b.ResourceID))
				if e != nil {
					return e
				}
				account = project.AccountID
			default:
				return iamerr.ErrPermissionDenied
			}
			gd, e := reader.AccessBindings().GrantDelegations().ActiveFor(ctx, account, domain.ServiceAccountID(actor.ID))
			if e != nil {
				return e
			}
			*captured = gd.ID
		}
		b.DelegationID = *captured
		gd, e := reader.AccessBindings().GrantDelegations().Get(ctx, *captured)
		if e != nil {
			return e
		}
		if !gd.Active() || !gd.IsDelegate(string(actor.Type), string(actor.ID)) {
			return iamerr.ErrPermissionDenied
		}
	}
	b.Subjects, err = domain.NormalizeSubjects(b.Subjects, b.SubjectType, b.SubjectID)
	if err != nil {
		return err
	}
	// Только отрицательный admission в том же RR до owner/epoch discovery.
	// Положительный результат не заменяет поздний KEY SHARE и final OLD gates.
	var recipientRows, recipientReads int
	if create {
		recipientRows, recipientReads, err = bindingRecipientDiscovery(ctx, snapshot, b.Subjects)
		if err != nil {
			return err
		}
	}
	role, err := reader.Roles().Get(ctx, b.RoleID)
	if err != nil {
		return err
	}
	owners := []kaname.AuthorityOwnerRef{}
	// Metadata меняет binding-AS-OBJECT; explicit target registration rows могут
	// лежать вне scope. До полноценного typed target planner выбираем global
	// перед locks, не присваивая им аккаунт якоря по имени.
	global := captured != nil || !create || len(b.Target.Resources) > 0 || len(b.HeldTargets) > 0
	switch string(b.ResourceType) {
	case "account", "project":
		owners = append(owners, kaname.AuthorityOwnerRef{Kind: string(b.ResourceType), ID: b.ResourceID})
	default:
		global = true
	}
	if !create {
		owners = append(owners, kaname.AuthorityOwnerRef{Kind: "binding", ID: string(b.ID)})
	}
	for _, recipient := range b.Subjects {
		switch recipient.Type {
		case domain.SubjectTypeGroup, domain.SubjectTypeServiceAccount:
			owners = append(owners, kaname.AuthorityOwnerRef{Kind: string(recipient.Type), ID: string(recipient.ID)})
		case domain.SubjectTypeUser:
			if recipient.ID == "*" {
				global = true
			}
		default:
			global = true
		}
	}
	var emitted []ab.RelationTuple
	if tuples != nil {
		emitted = tuples(b, role)
	}
	additionalSet := map[string]bool{}
	for _, tuple := range emitted {
		// Новый parent ещё отсутствует в DB; equality с полным proposed carrier
		// проверяется здесь, а после INSERT тот же emitter проверяет DB backstop.
		if create && tuple.Object == "iam_access_binding:"+string(b.ID) && tuple.Relation == string(b.ResourceType) && tuple.User == string(b.ResourceType)+":"+b.ResourceID {
			continue
		}
		raw, e := json.Marshal(map[string]any{"event_type": "fga.tuple.write", "payload": map[string]string{"user": tuple.User, "relation": tuple.Relation, "object": tuple.Object}})
		if e != nil {
			return e
		}
		var scopes groupMembershipScope
		if e = snapshot.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_row_scopes('fga_outbox',$1::jsonb)`, raw).Scan(&scopes.accounts, &scopes.global); e != nil {
			return e
		}
		global = global || scopes.global
		for _, a := range scopes.accounts {
			additionalSet[a] = true
		}
	}
	additionalIDs := make([]string, 0, len(additionalSet))
	for id := range additionalSet {
		additionalIDs = append(additionalIDs, id)
	}
	slices.Sort(additionalIDs)
	additional := make([]domain.AccountID, len(additionalIDs))
	for i, id := range additionalIDs {
		additional[i] = domain.AccountID(id)
	}
	// D5 требует отдельного полного issuer census; здесь подключён только D1
	// и metadata. Никакой вопрос не выводится из раннего положительного ответа.
	var questions *nativePolicyQuestions
	if captured == nil {
		questions = newNativePolicyQuestions()
		scope := domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}
		if create {
			err = questions.binding(actor, scope, b.RoleID)
		} else {
			err = questions.scopeAdmin(actor, scope)
		}
		if err != nil {
			return err
		}
	}
	plan, err := p.discoverPolicyPlanWithRows(ctx, snapshot, policyWriteRequest{consumedReads: recipientReads, nativeQuestions: questions, actor: actor, kind: kaname.AuthorityBinding, owners: owners, mutationSubjects: b.Subjects, readRoles: []domain.RoleID{b.RoleID}, additionalAccounts: additional, global: global}, recipientRows)
	if err != nil {
		return err
	}
	if err = snapshot.Commit(ctx); err != nil {
		return err
	}
	w, err := p.repo.coordinatedAuthorityWriterWithBegin(ctx, plan.intent(p.bundle), "decision", conn.BeginTx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = p.protectPolicyPlan(ctx, w, plan); err != nil {
		return err
	}
	if b.DelegationID != "" {
		_, active, e := w.AccessBindingsW().GrantDelegationsW().HoldActive(ctx, b.DelegationID)
		if e != nil {
			return e
		}
		if !active {
			return iamerr.ErrFailedPrecondition
		}
	}
	if !create {
		store := &reconcileStore{tx: w.tx}
		if err = store.AcquireBindingLock(ctx, b.ID); err != nil {
			return err
		}
		if _, err = w.AccessBindingsW().GetForDeactivation(ctx, b.ID); err != nil {
			return err
		}
	}
	if types := b.Target.DistinctTypes(); len(types) > 0 {
		if _, err = w.AccessBindingsW().LockLiveTargetTypes(ctx, types); err != nil {
			return err
		}
	}
	if err = holdRegisteredKeys(ctx, w.tx, b.HeldTargets, func(ref domain.ResourceRef) error {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "target resource %s %s was unregistered before the access binding was written", ref.Type, ref.ID)
	}); err != nil {
		return err
	}
	if _, err = w.tx.Exec(ctx, `SELECT id FROM kaname.roles WHERE id=$1 FOR SHARE`, string(b.RoleID)); err != nil {
		return err
	}
	// Только точный уже вычисленный emitter set. Новые locks после решения не
	// прячут ожидание обычной folded row до expiry actor authority.
	for _, tuple := range emitted {
		typ, id, ok := strings.Cut(tuple.Object, ":")
		if !ok {
			return kaname.ErrInvalidAuthorityFencePlan
		}
		subject := tuple.User
		if subject == "user:*" {
			subject = "system_class:authenticated"
			if tuple.Relation == "v_get" {
				subject = "system_class:anonymous"
			}
		}
		if _, err = w.tx.Exec(ctx, `SELECT 1 FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, tuple.Relation, subject); err != nil {
			return err
		}
	}
	if err = bindingDecisionPreflight(ctx, w.tx, b, create); err != nil {
		return err
	}
	if err = p.protectPolicyPlan(ctx, w, plan); err != nil {
		return err
	}
	// Повторный read под защитой возвращает актуальное состояние, а не proposal
	// как основание полномочий. OLD grant fields у metadata Update неизменяемы.
	if !create {
		b, err = w.AccessBindings().Get(ctx, b.ID)
		if err != nil {
			return err
		}
		b.Subjects, err = w.AccessBindings().ListSubjects(ctx, b.ID)
		if err != nil {
			return err
		}
	}
	role, err = w.Roles().Get(ctx, b.RoleID)
	if err != nil {
		return err
	}
	if err = apply(ctx, newSemanticAuthorityWriter(w, p.bundle), b, role); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}

var _ kaname.BindingDecisionRunner = (*GrantPolicyWriters)(nil)
var _ kaname.DelegatedBindingDecisionRunner = (*GrantPolicyWriters)(nil)

func (w *semanticAuthorityWriteTx) InsertBindingWithCapabilities(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	created, err := w.AccessBindingsW().Insert(ctx, b)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	tag, err := w.tx.Exec(ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1 AND grant_capability_version=0`, string(created.ID))
	if err != nil {
		return domain.AccessBinding{}, err
	}
	if tag.RowsAffected() != 1 {
		return domain.AccessBinding{}, kaname.ErrAuthorityClassificationChanged
	}
	return created, nil
}

var _ kaname.BindingCapabilityInserter = (*semanticAuthorityWriteTx)(nil)
