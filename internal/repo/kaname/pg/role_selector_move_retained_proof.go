// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Удержанный writer подтверждает раскладку роли до получения финальных часов.
// Перепись RR и защита её предикатов должны предшествовать этой проверке.
type roleSelectorMoveRetainedProof struct {
	move      *roleSelectorMoveStage
	writer    *authorityWriteTx
	changing  map[domain.AccessBindingID]bool
	confirmed map[domain.RoleID]bool
}

func (s *roleSelectorMoveStage) prepareRetainedTupleProof(ctx context.Context, w *semanticAuthorityWriteTx) (*roleSelectorMoveRetainedProof, error) {
	source := s.grantCapture()
	if source == nil || w == nil || !source.lifetime.beforeDecision(w.authorityWriteTx) || source.lifetime.bundle != w.bundle ||
		source.budget != w.producerBudget || s.facts == nil || s.captured.retainedSources == nil || s.replay.updates == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	p := &roleSelectorMoveRetainedProof{move: s, writer: w.authorityWriteTx,
		changing: make(map[domain.AccessBindingID]bool), confirmed: make(map[domain.RoleID]bool)}
	roles := make(map[domain.RoleID]bool)
	if err := source.budget.Charge(len(s.captured.Carriers)+len(s.captured.Collateral)+len(s.captured.retainedSources), 0); err != nil {
		return nil, err
	}
	for _, scopes := range [][]accessLabelSelectorMoveScope{s.captured.Carriers, s.captured.Collateral} {
		for _, scope := range scopes {
			p.changing[scope.Carrier.Binding.ID] = true
		}
	}
	for _, retained := range s.captured.retainedSources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out := retained.output
		if out == nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := source.budget.Charge(len(out.bindings), 0); err != nil {
			return nil, err
		}
		for _, b := range out.bindings {
			if !p.changing[b.ID] && b.RoleID != "" && b.RoleID != s.replay.role.ID && b.Status == domain.AccessBindingStatusActive &&
				b.RevokedAt == nil && b.GrantedRelation == "" && out.roles[string(b.RoleID)].Lifecycle.State == domain.RoleLifecycleDeclared {
				roles[b.RoleID] = true
			}
		}
	}
	for _, id := range slices.Sorted(maps.Keys(roles)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		role, err := selectorMoveGrantRole(source, id)
		if err != nil {
			return nil, err
		}
		expected, err := w.bundle.Projection(role)
		if err != nil {
			return nil, err
		}
		checkpoint, cost, checkErr := w.RoleProjectionCheckpoint(ctx, id)
		if err = w.ChargeSourceRead(cost); err != nil {
			return nil, err
		}
		if checkErr != nil && !errors.Is(checkErr, kaname.ErrSourceUnconfirmed) {
			return nil, checkErr
		}
		p.confirmed[id] = checkErr == nil && checkpoint == expected.Checkpoint && role.Lifecycle.State == domain.RoleLifecycleDeclared
	}
	return p, ctx.Err()
}

type selectorMoveLedgerHolder struct {
	Binding    domain.AccessBindingID `json:"binding_id"`
	MemberType string                 `json:"member_object_type"`
	MemberID   string                 `json:"member_object_id"`
	User       string                 `json:"fga_user"`
	Relation   string                 `json:"relation"`
	Object     string                 `json:"object"`
}

// Возвращает точного независимого ACTIVE-члена только для доказанного кортежа.
// Отсутствие такого доказательства не удостоверяет отсутствие других владельцев
// и не разрешает DELETE. Ни relation_fact, ни сама запись ledger не дают права.
func (p *roleSelectorMoveRetainedProof) requireTuple(ctx context.Context, w *semanticAuthorityWriteTx, tuple domain.MembershipTuple) (domain.TargetMember, error) {
	var zero domain.TargetMember
	if p == nil || p.move == nil || w == nil || p.writer != w.authorityWriteTx {
		return zero, kaname.ErrSourceUnconfirmed
	}
	source := p.move.grantCapture()
	model, id, ok := resourceFoldCoordinate(tuple.Object)
	if source == nil || !source.lifetime.valid(w.authorityWriteTx, w.bundle) || source.budget != w.producerBudget ||
		!ok || !nativeQuestionToken(tuple.Relation) || tuple.User == "" || tuple.User == "user:*" {
		return zero, kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	held := p.move.captured.retainedSources[domain.ResourceRef{Type: model, ID: id}]
	out := held.output
	if out == nil || out.modelType != model || out.object.ID != id || !held.graph.Present ||
		held.graph.Object.ObjectType != out.object.Type || held.graph.Object.ObjectID != id || !p.liveType(out.object.Type, model) {
		return zero, kaname.ErrSourceUnconfirmed
	}
	rows, captured := source.entries[resourceSourceKey{kind: resourceSourceFactLedgerHolders, typ: model, id: id}]
	if !captured {
		return zero, kaname.ErrSourceUnconfirmed
	}
	if err := source.budget.Charge(len(rows), 0); err != nil {
		return zero, err
	}
	holders, err := resourceDecodeRows[selectorMoveLedgerHolder](rows)
	if err != nil {
		return zero, err
	}
	for _, holder := range holders {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if holder.Object != tuple.Object || holder.User != tuple.User || holder.Relation != tuple.Relation || holder.MemberType == "" || p.changing[holder.Binding] {
			continue
		}
		b, ok := out.bindings[string(holder.Binding)]
		role := out.roles[string(b.RoleID)]
		if !ok || b.ID != holder.Binding || b.RoleID == p.move.replay.role.ID || role.ID != b.RoleID || !p.confirmed[b.RoleID] ||
			role.Lifecycle.State != domain.RoleLifecycleDeclared || b.GrantedRelation != "" || b.CreatedAt.IsZero() || b.CreatedAt.After(w.fence.decisionAt) ||
			b.RevokedByUserID != nil || !(accessLabelSelectorMoveCarrier{Binding: b}).activeAt(w.fence.decisionAt) ||
			b.Scope.ValidateAgainst(string(b.ResourceType), b.ResourceID) != nil || b.Target.Validate() != nil {
			continue
		}
		anchorAccount := ""
		if b.ResourceType == "project" {
			anchorAccount = selectorMoveCapturedProjectAccount(source, b.ResourceID)
			if anchorAccount == "" {
				continue
			}
		}
		if !domain.IsRoleAssignableInAccount(role, string(b.ResourceType), b.ResourceID, anchorAccount) {
			continue
		}
		ref := domain.ResourceRef{Type: holder.MemberType, ID: holder.MemberID}
		graph, ok := held.memberGraphs[ref]
		if !ok || !graph.Present || graph.Object.ObjectType != ref.Type || graph.Object.ObjectID != ref.ID {
			continue
		}
		member, err := p.desiredHolder(ctx, source, graph, b, role, tuple)
		if err != nil {
			return zero, err
		}
		if member.BindingID != "" {
			return member, ctx.Err()
		}
	}
	return zero, kaname.ErrSourceUnconfirmed
}

func (p *roleSelectorMoveRetainedProof) liveType(dotted, model string) bool {
	compiled, known := p.move.facts.FGAObjectType(dotted)
	catalogs := p.move.replay.parents.catalogs
	row, found := catalogs[model].selected()
	if !found && (dotted == domain.ScopeTypeAccountDotted || dotted == domain.ScopeTypeProjectDotted) {
		// Граф нативного проекта удерживает каталог по точечному имени.
		row, found = catalogs[dotted].selected()
	}
	return known && compiled == model && found && row.live && row.identity.ObjectType == model && row.identity.Dotted == dotted
}

func selectorMoveCapturedProjectAccount(source *resourceSourceCapture, id string) string {
	rows := source.entries[resourceSourceKey{kind: resourceSourceProject, typ: "project", id: id}]
	var project struct {
		ID      string `json:"id"`
		Account string `json:"account_id"`
	}
	if len(rows) != 1 || json.Unmarshal(rows[0].value, &project) != nil || project.ID != id || !nativeQuestionToken(project.Account) {
		return ""
	}
	return project.Account
}

func (p *roleSelectorMoveRetainedProof) desiredHolder(
	ctx context.Context, source *resourceSourceCapture, graph accessLabelMoveGraph, b domain.AccessBinding, role domain.Role, tuple domain.MembershipTuple,
) (domain.TargetMember, error) {
	var zero domain.TargetMember
	subjectRows, subjectsKnown := source.entries[resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: string(b.ID)}]
	memberRows, membersKnown := source.entries[resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: string(b.ID)}]
	if !subjectsKnown || !membersKnown {
		return zero, kaname.ErrSourceUnconfirmed
	}
	ancestors := graph.ancestors()
	var nested *domain.MirrorObject
	if graph.Object.ObjectType == domain.ScopeTypeProjectDotted {
		if graph.Project == nil {
			return zero, kaname.ErrSourceUnconfirmed
		}
		// Прямые правила используют строку проекта, вложенные — собственную
		// область зеркального ребёнка и предков из сохранённых рёбер.
		nested = graph.Project.Object
	}
	objectCount := 1 + len(ancestors)
	if nested != nil {
		objectCount++
	}
	if err := source.budget.Charge(objectCount+len(subjectRows)+len(memberRows), 0); err != nil {
		return zero, err
	}
	objects := make([]domain.MirrorObject, 0, objectCount)
	objects = append(objects, ancestors...)
	objects = append(objects, graph.Object)
	if nested != nil {
		objects = append(objects, *nested)
	}
	// Для этого свидетельства все источники выбора должны переживать перенос
	// без изменения. Копируемый объект или предок требует отдельного NEW-вывода.
	for _, object := range objects {
		ref := domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}
		model, known := p.move.facts.FGAObjectType(ref.Type)
		if _, changed := p.move.replay.updates[ref]; changed || !known || !p.liveType(ref.Type, model) {
			return zero, nil
		}
		if object.ParentProjectID != "" {
			account := selectorMoveCapturedProjectAccount(source, object.ParentProjectID)
			if account == "" || len(object.ParentAccountIDs) != 1 || object.ParentAccountIDs[0] != account {
				return zero, nil
			}
		}
	}
	subjects, err := accessLabelSelectorMoveSubjects(b, subjectRows)
	if err != nil || !slices.Equal(subjects, b.Subjects) {
		return zero, kaname.ErrSourceUnconfirmed
	}
	members, err := accessLabelSelectorMoveMembers(b, memberRows)
	if err != nil {
		return zero, err
	}
	active := make(map[string]domain.TargetMember)
	for _, member := range members {
		if member.ObjectType == graph.Object.ObjectType && member.ObjectID == graph.Object.ObjectID && member.VerificationStatus == domain.VerificationActive {
			active[member.RuleFP] = member
		}
	}
	if len(active) == 0 {
		return zero, nil
	}
	scope := bindingScopeFrom(p.move.facts, b, role)
	desired, err := graph.compileDesired(p.move.facts, resourceEffectBinding(scope), nil)
	if err != nil {
		return zero, err
	}
	if err = source.budget.Charge(len(desired), 0); err != nil {
		return zero, err
	}
	for _, member := range desired {
		if err = ctx.Err(); err != nil {
			return zero, err
		}
		if err = source.budget.Charge(len(member.Tuples), 0); err != nil {
			return zero, err
		}
		holder, ok := active[member.RuleFP]
		if ok && member.Status == domain.VerificationActive && holder.ObjectType == member.ObjectType && holder.ObjectID == member.ObjectID &&
			slices.Contains(member.Tuples, tuple) {
			return holder, nil
		}
	}
	return zero, nil
}
