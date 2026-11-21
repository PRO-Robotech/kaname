// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

const publicReaderModel = `model
  schema 1.1
type user
type service_account
type system_class
type group
  relations
    define member: [user, service_account]
type odd_box
  relations
    define public_reader: [system_class]
    define viewer: [user, service_account, group#member, system_class]
    define editor: [user, service_account, group#member]
    define v_get: [user, service_account, group#member, system_class] or viewer
    define v_list: [user, service_account, group#member, system_class]
    define v_update: [user, service_account, group#member]
type odd_item
  relations
    define parent: [odd_box]
    define viewer: [user, service_account, group#member] or public_reader from parent
    define v_get: [user, service_account, group#member] or viewer
    define v_list: [user, service_account, group#member] or viewer
type odd_sibling
  relations
    define parent: [odd_box]
    define viewer: [user, service_account, group#member] or public_reader from parent
    define v_get: [user, service_account, group#member] or viewer
    define v_list: [user, service_account, group#member] or viewer
`

func publicReaderRows(declared bool) catalog.Halves {
	h := catalog.Halves{Live: catalog.Rows{Modules: []string{"probe"}, Resources: []catalog.ResourceRow{
		{Module: "probe", Resource: "boxes", ObjectType: "odd_box", PublicReadToChildren: declared},
		{Module: "probe", Resource: "items", ObjectType: "odd_item", ParentTypes: []string{"odd_box"}, ParentNames: []string{"parent"}},
		{Module: "probe", Resource: "siblings", ObjectType: "odd_sibling", ParentTypes: []string{"odd_box"}, ParentNames: []string{"parent"}},
	}}}
	for _, r := range h.Live.Resources {
		for _, verb := range []string{"get", "list", "update"} {
			h.Live.Verbs = append(h.Live.Verbs, catalog.VerbRow{Module: r.Module, Resource: r.Resource, Verb: verb, PerObject: true})
		}
	}
	return h
}

func publicReaderCompiler(t *testing.T, declared bool) *Compiler {
	t.Helper()
	c, err := New(publicReaderModel, publicReaderRows(declared))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func publicReaderBinding() Binding {
	b := binding(domain.Rule{Module: "probe", Resources: []string{"boxes"}, ResourceNames: []string{"box-a"}, Verbs: []string{"get", "list"},
		Children: domain.Rules{{Resources: []string{"items"}, Verbs: []string{"get", "list"}}}})
	b.Subjects = []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: "anonymous"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated},
		{Type: domain.SubjectTypeGroup, ID: "anonymous"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous},
		{Type: domain.SubjectTypeServiceAccount, ID: "anonymous"},
	}
	b.Recipient = b.Subjects[3]
	return b
}

func publicReaderEffects(s Set) []Effect {
	var out []Effect
	for _, e := range s.Effects() {
		if e.Provenance.Primitive == "public_reader" {
			out = append(out, e)
		}
	}
	return out
}

func hasObligation(s Set, code string) bool {
	for _, o := range s.Obligations() {
		if o.Code == code {
			return true
		}
	}
	return false
}

func TestPublicReaderWholeRelationIncludesUnmentionedFutureChildren(t *testing.T) {
	c := publicReaderCompiler(t, true)
	b := publicReaderBinding()
	proposed := complete(t, c.Compile(b))
	selectors := c.facts.GrantSelectors(b.Role.Rules.MaterializingSelectorsInScope(domain.DeriveFromResourceType(b.Scope.Type)), domain.PolicyOfRole(false, ""))
	grant, ok := c.facts.PublicReaderEffect(selectors, b.Subjects, "probe.boxes", domain.PublicReaderOwnerRuleFPs(selectors))
	if !ok {
		t.Fatal("фикстура не запустила реальный producer")
	}
	foundSibling := false
	for _, e := range publicReaderEffects(proposed) {
		if e.Provenance.ProjectedRuleFP != grant.RuleFP {
			t.Fatalf("ключ не взят из общего producer: %+v", e.Provenance)
		}
		if e.Type == "odd_sibling" && e.Action == (grantcoverage.Action{Kind: grantcoverage.Verb, Name: "get"}) {
			foundSibling = true
			if len(e.Constraints) != 1 || e.Constraints[0].Type != "odd_box" || len(e.Constraints[0].Path) != 1 || !contains(e.Constraints[0].Region.Objects.IDs, "box-a") {
				t.Fatalf("будущие дети сужены запускающим ребёнком: %+v", e)
			}
		}
	}
	if !foundSibling {
		t.Fatal("неупомянутый ребёнок модели потерян")
	}
	owner := b
	owner.Role.Rules = append(domain.Rules(nil), b.Role.Rules...)
	owner.Role.Rules[0].Children = nil
	ownerSet := complete(t, c.Compile(owner))
	proves(t, ownerSet, proposed, false)
	publicFact := complete(t, c.CompileDirect(Direct{SourceID: "existing-public-reader", ObjectType: "odd_box", ObjectID: "box-a", Relation: "public_reader", Recipient: b.Recipient}))
	proves(t, Union(ownerSet, publicFact), proposed, true)
	wrongFact := complete(t, c.CompileDirect(Direct{SourceID: "other-container", ObjectType: "odd_box", ObjectID: "box-b", Relation: "public_reader", Recipient: b.Recipient}))
	proves(t, Union(ownerSet, wrongFact), proposed, false)
}

func TestPublicReaderTypedClassesFullFingerprintAndOrdinaryNeighbors(t *testing.T) {
	c := publicReaderCompiler(t, true)
	b := publicReaderBinding()
	var fp string
	for _, subject := range b.Subjects {
		b.Recipient = subject
		s := complete(t, c.Compile(b))
		public := publicReaderEffects(s)
		if subject.IsSystemClass() {
			if len(public) == 0 || !strings.Contains(public[0].Provenance.ProjectedRuleFP, "system_class:anonymous,system_class:authenticated") {
				t.Fatal("полный набор классов потерян")
			}
			if fp != "" && fp != public[0].Provenance.ProjectedRuleFP {
				t.Fatal("fingerprint пересчитан на одного получателя")
			}
			fp = public[0].Provenance.ProjectedRuleFP
			for _, e := range s.Effects() {
				if e.Type == "odd_item" && e.Provenance.Primitive == "object_rule" {
					t.Fatal("класс получил обычную вложенную ветвь")
				}
			}
		} else {
			if len(public) != 0 {
				t.Fatal("одноимённый обычный субъект стал классом")
			}
			found := false
			for _, e := range s.Effects() {
				found = found || e.Type == "odd_item" && e.Provenance.Primitive == "object_rule"
			}
			if !found {
				t.Fatalf("обычная вложенная ветвь потеряна для %s", subject.Type)
			}
		}
	}
	b.Recipient = b.Subjects[3]
	b.Subjects = []domain.Subject{b.Recipient}
	one := publicReaderEffects(complete(t, c.Compile(b)))
	if len(one) == 0 || one[0].Provenance.ProjectedRuleFP == fp {
		t.Fatal("удаление класса не изменило общий ключ")
	}
}

func TestPublicReaderNegativeProducerTwins(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{
		{"get-only-child", func(b *Binding) { b.Role.Rules[0].Children[0].Verbs = []string{"get"} }},
		{"named-child", func(b *Binding) { b.Role.Rules[0].Children[0].ResourceNames = []string{"today"} }},
		{"write-only-owner", func(b *Binding) { b.Role.Rules[0].Verbs = []string{"update"} }},
		{"wildcard-owner", func(b *Binding) { b.Role.Rules[0].ResourceNames = nil; b.Role.Rules[0].Verbs = []string{"*"} }},
		{"target-outside-owner", func(b *Binding) {
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "box-b"}}}
		}},
		{"target-child-is-not-owner", func(b *Binding) {
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.items", ID: "today"}}}
		}},
		{"wrong-owner-fingerprint", func(b *Binding) {
			other := b.Role.Rules[0]
			other.ResourceNames = []string{"box-b"}
			b.Role.Rules[0].Children = nil
			b.Role.Rules = append(b.Role.Rules, other)
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "box-a"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := publicReaderBinding()
			tc.change(&b)
			s := complete(t, publicReaderCompiler(t, true).Compile(b))
			if len(publicReaderEffects(s)) != 0 {
				t.Fatal("невыбранный producer произвёл public_reader")
			}
		})
	}
	if len(publicReaderEffects(complete(t, publicReaderCompiler(t, false).Compile(publicReaderBinding())))) != 0 {
		t.Fatal("необъявленный контейнер дал public_reader")
	}
}

func TestPublicReaderIncompleteInputsAndUnsupportedDeclaration(t *testing.T) {
	c := publicReaderCompiler(t, true)
	for _, tc := range []struct {
		name   string
		change func(*Binding)
	}{
		{"missing-subjects", func(b *Binding) { b.Subjects = nil }},
		{"recipient-absent", func(b *Binding) { b.Subjects = b.Subjects[:1] }},
		{"duplicate", func(b *Binding) { b.Subjects = append(b.Subjects, b.Subjects[0]) }},
		{"unknown-class", func(b *Binding) { b.Subjects[1].ID = "everybody" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := publicReaderBinding()
			tc.change(&b)
			s := c.Compile(b)
			if !hasObligation(s, "recipient_input") || s.Complete() || len(s.Effects()) != 0 {
				t.Fatalf("неполный перечень принят: %+v", s.Obligations())
			}
		})
	}
	b := publicReaderBinding()
	b.Role.Rules[0].Resources = []string{"unknown"}
	if c.Compile(b).Complete() {
		t.Fatal("unknown catalog скрыт как пустой producer")
	}
	bad, err := New(strings.Replace(publicReaderModel, "define public_reader: [system_class]", "define public_reader: [user]", 1), publicReaderRows(true))
	if err != nil {
		t.Fatal(err)
	}
	s := bad.Compile(publicReaderBinding())
	if s.Complete() || !hasObligation(s, "recipient_declaration") || Prove(s, s).Reason != grantcoverage.ReasonIncomplete {
		t.Fatalf("модель не принимает класс, но доказательство завершено: %+v", s.Obligations())
	}
	if _, err := New(publicReaderModel, catalog.Halves{}); err == nil {
		t.Fatal("отсутствующий снимок принят")
	}
}

func TestPublicReaderOwnerRegionsAggregateOrRemainIncomplete(t *testing.T) {
	c := publicReaderCompiler(t, true)
	b := publicReaderBinding()
	second := b.Role.Rules[0]
	second.Children = domain.Rules{{Resources: []string{"siblings"}, Verbs: []string{"get", "list"}}}
	b.Role.Rules = append(b.Role.Rules, second)
	s := complete(t, c.Compile(b))
	selectors := c.facts.GrantSelectors(b.Role.Rules.MaterializingSelectorsInScope(domain.DeriveFromResourceType(b.Scope.Type)), domain.PolicyOfRole(false, ""))
	grant, ok := c.facts.PublicReaderEffect(selectors, b.Subjects, "probe.boxes", domain.PublicReaderOwnerRuleFPs(selectors))
	if !ok || len(grant.ChildRuleFPs) != 2 {
		t.Fatal("фикстура не содержит двух оснований")
	}
	for _, e := range publicReaderEffects(s) {
		if e.Provenance.ProjectedRuleFP != grant.RuleFP {
			t.Fatal("ключ нескольких owner не агрегирован")
		}
	}
	b.Role.Rules[1].ResourceNames = []string{"box-a", "box-b"}
	s = c.Compile(b)
	if s.Complete() || !hasObligation(s, "public_reader_owners") || Prove(s, s).Reason != grantcoverage.ReasonIncomplete {
		t.Fatalf("неразбитые owner-регионы приняты: %+v", s.Obligations())
	}
}

func TestClassDoesNotMintMetaLegacyOrWriteEffects(t *testing.T) {
	c := publicReaderCompiler(t, true)
	b := publicReaderBinding()
	b.Role.Rules[0].Verbs = []string{"get", "list", "update"}
	for _, e := range complete(t, c.Compile(b)).Effects() {
		if e.Kind != Use || e.Action.Name == "update" || e.Action.Name == "editor" {
			t.Fatalf("класс получил полномочие записи: %+v", e)
		}
	}
	legacy := publicReaderBinding()
	legacy.Role.Rules = nil
	legacy.Role.Permissions = domain.Permissions{"iam.account.*.*"}
	if s := c.Compile(legacy); s.Complete() || !hasObligation(s, "recipient_legacy") || len(s.Effects()) != 0 {
		t.Fatal("неподтверждённый legacy класса принят")
	}
	meta := binding(domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}})
	meta.Recipient = b.Recipient
	meta.Subjects = b.Subjects
	if s := compiler(t).Compile(meta); s.Complete() || !hasObligation(s, "recipient_meta") || len(s.Effects()) != 0 {
		t.Fatal("класс получил explicit meta")
	}
}

func TestClassScopeWildcardKeepsOnlyReadAndContainerActionStaysSuppressed(t *testing.T) {
	// Реальный scope-self producer сначала разворачивает *, затем фильтрует
	// глаголы получателя; объектный producer фильтрует авторский * раньше.
	model := strings.Replace(modelFixture, "type user", "type system_class\ntype user", 1)
	model = strings.ReplaceAll(model, "[user, service_account, group#member]", "[user, service_account, group#member, system_class]")
	c, err := New(model, rows())
	if err != nil {
		t.Fatal(err)
	}
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}})
	b.Recipient = domain.Subject{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}
	b.Subjects = []domain.Subject{b.Recipient}
	foundRead := false
	for _, e := range complete(t, c.Compile(b)).Effects() {
		if e.Kind != Use || e.Action.Kind == grantcoverage.AllVerbs || e.Action.Name == "admin" || e.Action.Name == "editor" || e.Action.Name == "update" || e.Action.Name == "delete" {
			t.Fatalf("класс получил scope полномочие записи: %+v", e)
		}
		foundRead = foundRead || e.Provenance.Primitive == "scope_self" && e.Action.Name == "get"
	}
	if !foundRead {
		t.Fatal("чтение scope-self потеряно после фильтрации раскрытого wildcard")
	}
	b.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"create"}}}
	s := complete(t, c.Compile(b))
	if len(s.Effects()) != 0 || Prove(s, s).Status == grantcoverage.Proved {
		t.Fatalf("класс получил SA container полномочие: %+v", s.Effects())
	}
}
