// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ObjectBinding содержит факты выдачи из одного закрытого снимка. Active
// переносится как факт: eligibility и выбор маршрута проверяет владелец TX.
type ObjectBinding struct {
	BindingID      domain.AccessBindingID
	Scope          domain.ScopeAnchor
	Subjects       []domain.Subject
	RoleID         string
	Policy         domain.RulePolicy
	Selectors      []domain.RuleSelector
	ScopeSelfVerbs []string
	Target         domain.AccessTarget
	Active         bool
}

// ObjectDesiredMember сохраняет ключ правила, отказ по включению и точные
// кортежи общего materializer. Сам по себе он не разрешает запись в БД.
type ObjectDesiredMember struct {
	RuleFP     string
	ObjectType string
	ObjectID   string
	Status     domain.VerificationStatus
	Tuples     []domain.MembershipTuple
}

type grantee struct {
	subject string
	verbs   []string
}

const scopeSelfRuleFP = "scope_self"

// CompileObjectDesired выводит желаемый состав для одного объекта из уже
// проверенного снимка. Порядок, fingerprints, REJECTED и вывод кортежей совпадают
// с прежним общим materializer. Полнота, живость, часы и авторизация остаются у TX.
func CompileObjectDesired(facts *catalog.Facts, binding ObjectBinding, object domain.MirrorObject, ancestors []domain.MirrorObject) ([]ObjectDesiredMember, error) {
	if facts == nil || binding.Scope.Type == "" || binding.Scope.ID == "" || object.ObjectType == "" || object.ObjectID == "" {
		return nil, fmt.Errorf("%w: incomplete object compiler input", ErrInvalidSnapshot)
	}
	if _, err := domain.NormalizeSubjects(binding.Subjects, "", ""); err != nil {
		return nil, fmt.Errorf("%w: object subjects: %v", ErrInvalidSnapshot, err)
	}
	for _, selector := range binding.Selectors {
		if selector.RuleFP == "" || (selector.Container != nil && selector.Container.Type == "") {
			return nil, fmt.Errorf("%w: incomplete object selector", ErrInvalidSnapshot)
		}
	}
	for _, ancestor := range ancestors {
		if ancestor.ObjectType == "" || ancestor.ObjectID == "" {
			return nil, fmt.Errorf("%w: incomplete object ancestor", ErrInvalidSnapshot)
		}
	}
	return desiredMembersForObject(facts, binding, object, ancestors), nil
}

// Следующие чистые решения перенесены из прежнего materializer без изменения
// алгоритмов. Владелец Resource подключает к этому compiler все три маршрута.
func desiredMembersForObject(cat *catalog.Facts, bs ObjectBinding, o domain.MirrorObject,
	ancestors []domain.MirrorObject) []ObjectDesiredMember {
	perObject := len(bs.Target.Resources) > 0

	var out []ObjectDesiredMember
	if len(bs.ScopeSelfVerbs) > 0 && !perObject &&
		o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		if sm, ok := scopeSelfMember(cat, grantees(bs, bs.ScopeSelfVerbs, false), bs.Scope.Type, bs.Scope.ID); ok {
			out = append(out, sm)
		}
	}
	// Контейнерные действия правил (kaname#1003, creator.go) — члены на объекте
	// ОБЛАСТИ: путь по объекту обязан их выводить, иначе событие аккаунта сняло бы
	// их как устаревшие.
	if o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		out = append(out, containerMembers(cat, bs)...)
	}
	// Минимальные привилегии пообъектной цели (F8, IAM-1-21): правило даёт объект лишь тогда,
	// когда цель выдачи тоже его называет. Едино для всех ветвей, ровно как
	// matchSelectorObjects пересекает совпавший набор. Вложенное правило (kaname#874)
	// судит цель по КОНТЕЙНЕРУ среди предков объекта, а не по самому объекту.
	inTarget := !perObject || bs.Target.Contains(o.ObjectType, o.ObjectID)
	for _, sel := range bs.Selectors {
		gs := selectorGrantees(bs, sel)
		if len(gs) == 0 {
			continue
		}
		if sel.Container != nil {
			if !nestedCoversObject(sel, bs, o, ancestors) {
				continue
			}
		} else if !inTarget || !selectorMatchesObject(sel, o) {
			continue
		}
		dm, ok := desiredMemberForObject(cat, bs.Policy, gs, sel, o, bs.Scope)
		if !ok {
			// У типа нет объекта FGA в модели → нет кортежа → пропускаем объект
			// (отказ по умолчанию: опечатка в типе ничего не выдаёт).
			continue
		}
		out = append(out, dm)
	}
	// Публичное чтение детям (kaname#856): тот же вывод, что у полного прохода
	// (desiredRuleMembers), — иначе два пути разошлись бы в составе.
	return withPublicReaders(cat, bs, out)
}

func desiredMemberForObject(cat *catalog.Facts, policy domain.RulePolicy, gs []grantee, sel domain.RuleSelector, o domain.MirrorObject, scope domain.ScopeAnchor) (ObjectDesiredMember, bool) {
	// Селектор создателя (kaname#1003, creator.go): объект входит в охват правила
	// только для субъекта, который его создал. Никому — объект правилом не
	// выбран вовсе (ни члена, ни отвергнутого члена: охвата нет, а не вне области).
	gs = creatorGrantees(sel, gs, o)
	if len(gs) == 0 {
		return ObjectDesiredMember{}, false
	}
	if !o.IsContainedIn(scope) {
		return ObjectDesiredMember{
			RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
			Status: domain.VerificationRejected,
		}, true
	}
	// Кортежи — объединение по субъектам `gs`, каждому со своими глаголами
	// (subjects.go, kaname#880). Отказ «у типа нет объекта модели» от субъекта
	// не зависит: первый же отказ — отказ всего члена.
	var tuples []domain.MembershipTuple
	for _, g := range gs {
		// Контейнерные действия кортежей на объекте не пишут (kaname#1003): их
		// отношение лежит на родителе (containerMembers). Правило, у которого на
		// типе объекта кроме них ничего нет, объекту не даёт ничего — даже яруса.
		verbs := objectVerbsOf(cat, o.ObjectType, g.verbs)
		if len(verbs) == 0 {
			continue
		}
		t, ok := ruleObjectTuples(cat, policy, g.subject, verbs, o.ObjectType, o.ObjectID)
		if !ok {
			return ObjectDesiredMember{}, false
		}
		if sel.CreatedBySubject {
			t = verbTuplesOnly(t)
		}
		tuples = append(tuples, t...)
	}
	if len(tuples) == 0 {
		return ObjectDesiredMember{}, false
	}
	return ObjectDesiredMember{
		RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
		Status: domain.VerificationActive, Tuples: tuples,
	}, true
}

func selectorMatchesObject(sel domain.RuleSelector, o domain.MirrorObject) bool {
	if !containsStringForward(sel.ObjectTypes, o.ObjectType) {
		return false
	}
	switch sel.Arm {
	case domain.ArmNames:
		return containsStringForward(sel.ResourceNames, o.ObjectID)
	case domain.ArmLabels:
		return o.MatchesLabels(sel.MatchLabels)
	default: // ArmAnchor
		return true
	}
}

func containsStringForward(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func grantees(bs ObjectBinding, verbs []string, nested bool) []grantee {
	recipients := domain.GrantRecipients(bs.Subjects, verbs, nested)
	out := make([]grantee, 0, len(recipients))
	for _, recipient := range recipients {
		out = append(out, grantee{
			subject: domain.FGASubjectRef(string(recipient.Subject.Type), string(recipient.Subject.ID)),
			verbs:   recipient.Verbs,
		})
	}
	return out
}

func selectorGrantees(bs ObjectBinding, sel domain.RuleSelector) []grantee {
	return grantees(bs, sel.Verbs, sel.Container != nil)
}

func hasNonClassSubject(bs ObjectBinding) bool {
	return domain.HasNonClassSubject(bs.Subjects)
}

func ruleObjectTuples(cat *catalog.Facts, policy domain.RulePolicy, subject string, verbs []string, objectType, objectID string) ([]domain.MembershipTuple, bool) {
	fgaType, ok := cat.FGAObjectType(objectType)
	if !ok {
		return nil, false
	}
	return ruleObjectTuplesWithTypeVerbs(cat, policy, subject, verbs, fgaType, objectID, typeVerbsOf(cat, fgaType))
}

func typeVerbsOf(cat *catalog.Facts, fgaType string) []string {
	if set := cat.VerbsOfType(fgaType); len(set) > 0 {
		return set
	}
	return cat.CommonVerbVocabulary()
}

func ruleObjectTuplesWithTypeVerbs(cat *catalog.Facts, policy domain.RulePolicy, subject string, verbs []string, fgaType, objectID string,
	typeVerbs []string) ([]domain.MembershipTuple, bool) {
	object := fmt.Sprintf("%s:%s", fgaType, objectID)
	var out []domain.MembershipTuple
	for _, relation := range cat.ObjectRelations(fgaType, verbs, typeVerbs, policy) {
		out = append(out, domain.MembershipTuple{User: subject, Relation: relation, Object: object})
	}
	return out, true
}

func scopeSelfMember(cat *catalog.Facts, gs []grantee, scopeType, scopeID string) (ObjectDesiredMember, bool) {
	dotted := "iam." + scopeType // iam.account / iam.project (cluster has no mapping)
	if _, ok := cat.FGAObjectType(dotted); !ok {
		return ObjectDesiredMember{}, false
	}
	var tuples []domain.MembershipTuple
	for _, g := range gs {
		t, ok := scopeSelfTuples(cat, g.subject, scopeType, scopeID, g.verbs)
		if !ok {
			return ObjectDesiredMember{}, false
		}
		tuples = append(tuples, t...)
	}
	if len(tuples) == 0 {
		return ObjectDesiredMember{}, false
	}
	return ObjectDesiredMember{
		RuleFP:     scopeSelfRuleFP,
		ObjectType: dotted,
		ObjectID:   scopeID,
		Status:     domain.VerificationActive,
		Tuples:     tuples,
	}, true
}

func scopeSelfTuples(cat *catalog.Facts, subject, scopeType, scopeID string, verbs []string) ([]domain.MembershipTuple, bool) {
	if scopeID == "" || len(verbs) == 0 {
		return nil, false
	}
	switch scopeType {
	case "account", "project":
		// per-object verb-bearing hierarchy scopes — materialized below.
	default:
		// cluster (D-9 short-circuit owns it) + any non-hierarchy scope → no member.
		return nil, false
	}
	return scopeSelfTuplesWithTypeVerbs(cat, subject, scopeType, scopeID, verbs, typeVerbsOf(cat, scopeType))
}

func scopeSelfTuplesWithTypeVerbs(cat *catalog.Facts, subject, scopeType, scopeID string,
	verbs, typeVerbs []string) ([]domain.MembershipTuple, bool) {
	object := scopeType + ":" + scopeID
	var out []domain.MembershipTuple
	for _, relation := range cat.ScopeSelfRelations(scopeType, verbs, typeVerbs) {
		out = append(out, domain.MembershipTuple{User: subject, Relation: relation, Object: object})
	}
	return out, true
}

func creatorGrantees(sel domain.RuleSelector, gs []grantee, o domain.MirrorObject) []grantee {
	if !sel.CreatedBySubject {
		return gs
	}
	if o.CreatedBy == "" {
		return nil
	}
	var out []grantee
	for _, g := range gs {
		if g.subject == o.CreatedBy {
			out = append(out, g)
		}
	}
	return out
}

func objectVerbsOf(cat *catalog.Facts, objectType string, verbs []string) []string {
	return cat.ObjectVerbs(objectType, verbs)
}

func verbTuplesOnly(tuples []domain.MembershipTuple) []domain.MembershipTuple {
	out := tuples[:0:0]
	for _, t := range tuples {
		if strings.HasPrefix(t.Relation, "v_") {
			out = append(out, t)
		}
	}
	return out
}

func creatorSubjectIDs(bs ObjectBinding) []string {
	var out []string
	for _, s := range bs.Subjects {
		if s.Type == domain.SubjectTypeServiceAccount {
			out = append(out, string(s.ID))
		}
	}
	return out
}

func containerMembers(cat *catalog.Facts, bs ObjectBinding) []ObjectDesiredMember {
	if len(bs.Target.Resources) > 0 || bs.Scope.ID == "" {
		return nil
	}
	var subjects []string
	for _, id := range creatorSubjectIDs(bs) {
		subjects = append(subjects, domain.FGASubjectRef(string(domain.SubjectTypeServiceAccount), id))
	}
	if len(subjects) == 0 {
		return nil
	}
	var out []ObjectDesiredMember
	for _, sel := range bs.Selectors {
		if sel.Container != nil {
			continue
		}
		seen := map[domain.MembershipTuple]bool{}
		var tuples []domain.MembershipTuple
		for _, typ := range sel.ObjectTypes {
			for _, v := range sel.Verbs {
				g, ok := cat.ContainerVerb(typ, v)
				if !ok || g.ParentType != bs.Scope.Type {
					continue
				}
				for _, subj := range subjects {
					t := domain.MembershipTuple{User: subj, Relation: g.Relation, Object: g.ParentType + ":" + bs.Scope.ID}
					if seen[t] {
						continue
					}
					seen[t] = true
					tuples = append(tuples, t)
				}
			}
		}
		if len(tuples) == 0 {
			continue
		}
		out = append(out, ObjectDesiredMember{
			RuleFP:     sel.RuleFP,
			ObjectType: "iam." + bs.Scope.Type,
			ObjectID:   bs.Scope.ID,
			Status:     domain.VerificationActive,
			Tuples:     tuples,
		})
	}
	return out
}

func ownerSelectorOf(sel domain.RuleSelector) domain.RuleSelector {
	c := sel.Container
	return domain.RuleSelector{
		RuleFP:        c.OwnerFP,
		Arm:           c.Arm,
		ObjectTypes:   []string{c.Type},
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

func containerSelected(sel domain.RuleSelector, bs ObjectBinding, a domain.MirrorObject) bool {
	if a.ObjectType != sel.Container.Type || !selectorMatchesObject(ownerSelectorOf(sel), a) {
		return false
	}
	if len(bs.Target.Resources) > 0 && !bs.Target.Contains(a.ObjectType, a.ObjectID) {
		return false
	}
	return a.IsContainedIn(bs.Scope)
}

func nestedCoversObject(sel domain.RuleSelector, bs ObjectBinding, o domain.MirrorObject, ancestors []domain.MirrorObject) bool {
	if !hasNonClassSubject(bs) || !selectorMatchesObject(sel, o) {
		return false
	}
	for _, a := range ancestors {
		if containerSelected(sel, bs, a) {
			return true
		}
	}
	return false
}

func publicReaderMember(cat *catalog.Facts, bs ObjectBinding, objectType, objectID string,
	ownerFPs map[string]bool) (ObjectDesiredMember, bool) {
	effect, ok := cat.PublicReaderEffect(bs.Selectors, bs.Subjects, objectType, ownerFPs)
	if !ok {
		return ObjectDesiredMember{}, false
	}
	return ObjectDesiredMember{
		RuleFP:     effect.RuleFP,
		ObjectType: objectType,
		ObjectID:   objectID,
		Status:     domain.VerificationActive,
		Tuples:     effect.Tuples(objectID),
	}, true
}

func withPublicReaders(cat *catalog.Facts, bs ObjectBinding, members []ObjectDesiredMember) []ObjectDesiredMember {
	classes := domain.SystemClassSubjects(bs.Subjects)
	if len(classes) == 0 {
		return members
	}
	classRead := domain.PublicReaderOwnerRuleFPs(bs.Selectors)
	type object struct{ typ, id string }
	owners := map[object]map[string]bool{}
	var order []object
	for _, m := range members {
		if m.Status != domain.VerificationActive || !classRead[m.RuleFP] {
			continue
		}
		key := object{m.ObjectType, m.ObjectID}
		if owners[key] == nil {
			owners[key] = map[string]bool{}
			order = append(order, key)
		}
		owners[key][m.RuleFP] = true
	}
	out := members
	for _, key := range order {
		if pm, ok := publicReaderMember(cat, bs, key.typ, key.id, owners[key]); ok {
			out = append(out, pm)
		}
	}
	return out
}
