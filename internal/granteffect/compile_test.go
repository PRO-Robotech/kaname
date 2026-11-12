// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

const modelFixture = `model
  schema 1.1
type user
type service_account
type group
  relations
    define member: [user, service_account]
type cluster
  relations
    define system_admin: [user, service_account, group#member]
    define system_viewer: [user, service_account, group#member]
    define admin: system_admin
    define viewer: system_viewer or admin
type account
  relations
    define cluster: [cluster]
    define admin: [user, service_account, group#member] or system_admin from cluster
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define service_account_creator: [service_account] or editor
    define v_get: [user, service_account, group#member]
    define v_update: [user, service_account, group#member]
    define v_delete: [user, service_account, group#member]
type project
  relations
    define account: [account]
    define admin: [user, service_account, group#member] or admin from account
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
type strange_box
  relations
    define account: [account]
    define admin: [user, service_account, group#member] or admin from account
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or viewer
    define v_update: [user, service_account, group#member]
    define v_delete: [user, service_account, group#member]
    define inspect: v_get
    define console: [user with fresh] or admin
type strange_item
  relations
    define parent: [strange_box]
    define admin: [user, service_account, group#member] or admin from parent
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or viewer
type strange_tag
  relations
    define parent: [strange_item]
    define admin: [user, service_account, group#member] or admin from parent
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or viewer
type iam_role
  relations
    define viewer: [user, service_account, group#member]
    define v_get: [user, service_account, group#member] or viewer
type iam_service_account
  relations
    define admin: [user, service_account, group#member]
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or viewer
    define v_update: [user, service_account, group#member]
    define v_delete: [user, service_account, group#member]
type iam_access_binding
  relations
    define admin: [user, service_account, group#member]
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
type iam_grant_scope
  relations
    define create_binding: [user, service_account, group#member]
type iam_grant_role
  relations
    define bind: [user, service_account, group#member]
condition fresh(at: timestamp) {
  true
}
`

func rows() catalog.Halves {
	resources := []catalog.ResourceRow{
		{Module: "probemod", Resource: "boxes", ObjectType: "strange_box", ParentTypes: []string{"account"}, ParentNames: []string{"account"}},
		{Module: "probemod", Resource: "items", ObjectType: "strange_item", ParentTypes: []string{"strange_box"}, ParentNames: []string{"parent"}},
		{Module: "probemod", Resource: "tags", ObjectType: "strange_tag", ParentTypes: []string{"strange_item"}, ParentNames: []string{"parent"}},
		{Module: "iam", Resource: "account", ObjectType: "account"},
		{Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"},
		{Module: "iam", Resource: "role", ObjectType: "iam_role"},
		{Module: "iam", Resource: "serviceAccount", ObjectType: "iam_service_account"},
	}
	var verbs []catalog.VerbRow
	for _, r := range resources {
		for _, v := range []string{"get", "update", "delete"} {
			verbs = append(verbs, catalog.VerbRow{Module: r.Module, Resource: r.Resource, Verb: v, PerObject: true})
		}
	}
	verbs = append(verbs, catalog.VerbRow{Module: "iam", Resource: "accessBinding", Verb: "create"}, catalog.VerbRow{Module: "iam", Resource: "role", Verb: "bind"})
	verbs = append(verbs, catalog.VerbRow{Module: "iam", Resource: "serviceAccount", Verb: "create", ContainerParent: "account", ContainerRelation: "service_account_creator"})
	return catalog.Halves{Live: catalog.Rows{Modules: []string{"iam", "probemod"}, Resources: resources, Verbs: verbs}}
}
func compiler(t *testing.T) *Compiler {
	t.Helper()
	c, e := New(modelFixture, rows())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func binding(rules ...domain.Rule) Binding {
	return Binding{SourceID: "binding-source", Role: domain.Role{ID: "role-a", Rules: rules}, Scope: domain.ScopeAnchor{Type: "account", ID: "acc-a"}, Target: domain.AccessTarget{AllInScope: true}, Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "user-a"}, CapabilityVersion: 1}
}
func box(verbs ...string) domain.Rule {
	return domain.Rule{Module: "probemod", Resources: []string{"boxes"}, Verbs: verbs}
}
func complete(t *testing.T, s Set) Set {
	t.Helper()
	if !s.Complete() {
		t.Fatalf("обязательства: %+v", s.Obligations())
	}
	return s
}
func proves(t *testing.T, a, w Set, want bool) {
	t.Helper()
	r := Prove(a, w)
	if (r.Status == grantcoverage.Proved) != want {
		t.Fatalf("coverage=%+v, wanted proof=%v; obligations a=%+v w=%+v", r, want, a.Obligations(), w.Obligations())
	}
}

func TestActualCatalogTypeAndComputedRelation(t *testing.T) {
	c := compiler(t)
	s := complete(t, c.Compile(binding(box("get"))))
	found := false
	for _, e := range s.Effects() {
		if e.Type == "strange_box" && e.Action.Name == "inspect" {
			found = true
			if e.Provenance.ModelOrigin == "" || e.Provenance.AuthoredRuleFP == "" {
				t.Fatal("нет lineage")
			}
		}
	}
	if !found {
		t.Fatal("custom computed relation потеряно")
	}
	copy := s.Effects()
	copy[0].Constraints[0].Region.Objects.IDs = []string{"mutation"}
	if len(s.Effects()[0].Constraints[0].Region.Objects.IDs) != 0 {
		t.Fatal("Effects вернул mutable внутренний срез")
	}
	proves(t, s, s, true)
}
func TestTreskaOsetrUnionAndFutureObjects(t *testing.T) {
	c := compiler(t)
	one := box("get")
	one.ResourceNames = []string{"x"}
	two := one
	two.ResourceNames = []string{"y"}
	a := binding(one)
	a.Role.ID = "treska"
	b := binding(two)
	b.Role.ID = "another"
	wanted := box("get")
	wanted.ResourceNames = []string{"x", "y"}
	w := binding(wanted)
	w.Role.ID = "osetr"
	actor := Union(complete(t, c.Compile(a)), complete(t, c.Compile(b)))
	proves(t, actor, complete(t, c.Compile(w)), true)
	proves(t, actor, complete(t, c.Compile(binding(box("get")))), false)
}
func TestTargetIntersectsNamesAndNoInventory(t *testing.T) {
	c := compiler(t)
	r := box("get")
	r.ResourceNames = []string{"x", "y"}
	b := binding(r)
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probemod.boxes", ID: "x"}}}
	x := box("get")
	x.ResourceNames = []string{"x"}
	proves(t, complete(t, c.Compile(binding(x))), complete(t, c.Compile(b)), true)
}
func TestWildcardFiniteCannotCoverFuture(t *testing.T) {
	c := compiler(t)
	star := complete(t, c.Compile(binding(box("*"))))
	finite := complete(t, c.Compile(binding(box("get", "update", "delete"))))
	proves(t, finite, star, false)
	proves(t, star, finite, true)
}
func TestLabelImplicationAndNotTodaysMatches(t *testing.T) {
	c := compiler(t)
	r := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}}
	narrow := r
	narrow.MatchLabels = map[string]string{"env": "prod", "team": "blue"}
	a := complete(t, c.Compile(binding(r)))
	w := complete(t, c.Compile(binding(narrow)))
	proves(t, a, w, true)
	proves(t, w, a, false)
}
func TestNestedParentSelectionAndTwoHopPath(t *testing.T) {
	c := compiler(t)
	r := box("get")
	r.ResourceNames = []string{"parent-x"}
	r.Children = domain.Rules{{Resources: []string{"tags"}, Verbs: []string{"get"}}}
	a := complete(t, c.Compile(binding(r)))
	found := false
	for _, e := range a.Effects() {
		for _, q := range e.Constraints {
			if len(q.Path) == 2 && q.Type == "strange_box" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("путь tags -> items -> boxes отсутствует")
	}
	proves(t, a, a, true)
	other := r
	other.ResourceNames = []string{"parent-y"}
	proves(t, a, complete(t, c.Compile(binding(other))), false)
	broad := r
	broad.ResourceNames = nil
	proves(t, complete(t, c.Compile(binding(broad))), a, true)
}
func TestCreatorServiceAccountIdentity(t *testing.T) {
	c := compiler(t)
	r := domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get", "update", "delete"}, CreatedBySubject: true}
	a := binding(r)
	a.Recipient = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
	b := a
	b.Recipient.ID = "sa-b"
	aa := complete(t, c.Compile(a))
	bb := complete(t, c.Compile(b))
	proves(t, aa, aa, true)
	proves(t, aa, bb, false)
	admin := r
	admin.CreatedBySubject = false
	admin.Verbs = []string{"*"}
	a.Role.Rules = domain.Rules{admin}
	proves(t, complete(t, c.Compile(a)), bb, true)
}
func TestExactMetaAnchorsAndScopeAdmin(t *testing.T) {
	c := compiler(t)
	meta := binding(domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"role-x"}})
	meta.Role.IsSystem = true
	meta.Role.ClusterID = "cluster_root"
	m := complete(t, c.Compile(meta))
	if len(m.Effects()) != 1 || m.Effects()[0].Anchor != meta.Scope {
		t.Fatal("home anchor заменил scope")
	}
	other := meta
	other.Scope.ID = "acc-b"
	proves(t, m, complete(t, c.Compile(other)), false)
	other = meta
	other.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"role-y"}}}
	proves(t, m, complete(t, c.Compile(other)), false)
	admin := c.CompileDirect(Direct{SourceID: "admin", ObjectType: "account", ObjectID: "acc-a", Relation: "admin", Recipient: meta.Recipient})
	complete(t, admin)
	found := false
	for _, e := range admin.Effects() {
		found = found || e.Kind == ScopeAdmin
	}
	if !found {
		t.Fatal("ScopeAdmin не выведен")
	}
	proves(t, m, admin, false)
	proves(t, admin, admin, true)
}
func TestConditionEqualityAndUnconditionalCustomBranch(t *testing.T) {
	c := compiler(t)
	d := Direct{SourceID: "fact", ObjectType: "strange_box", ObjectID: "x", Relation: "console", Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "user-a"}, Condition: Condition{Name: "fresh", Parameters: `{"at":"2026-11-12T00:00:00Z"}`}}
	a := complete(t, c.CompileDirect(d))
	proves(t, a, a, true)
	d.Condition.Parameters = `{"at":"2026-11-13T00:00:00Z"}`
	proves(t, a, complete(t, c.CompileDirect(d)), false)
	d.Relation = "admin"
	d.Condition = Condition{}
	admin := complete(t, c.CompileDirect(d))
	proves(t, admin, a, true)
}
func TestModelIdentityUnsupportedAndLimit(t *testing.T) {
	c := compiler(t)
	s := complete(t, c.Compile(binding(box("get"))))
	changed, err := New(modelFixture+"\n# changed source\n", rows())
	if err != nil {
		t.Fatal(err)
	}
	if Prove(s, changed.Compile(binding(box("get")))).Reason != grantcoverage.ReasonIdentity {
		t.Fatal("identity mismatch пропущен")
	}
	b := binding(box("get"))
	b.Role.Rules[0].Resources = []string{"unknown"}
	if c.Compile(b).Complete() {
		t.Fatal("неизвестный тип потерян")
	}
	b = binding(box("get"))
	b.SourceID = strings.Repeat("x", MaxInputBytes+1)
	if c.Compile(b).Complete() {
		t.Fatal("лимит пропущен")
	}
}
func TestCanonicalSourceParsesForCompiler(t *testing.T) {
	raw, err := os.ReadFile("../../proto/kaname/cloud/iam/v1/fga_model.fga")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(string(raw), rows())
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentityForTest() != digest(raw) {
		t.Fatal("использована не каноническая модель")
	}
}
func (c *Compiler) IdentityForTest() string { return c.identity.ModelID }

func TestScopeSelfAndContainerUseActualProducer(t *testing.T) {
	c := compiler(t)
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}})
	s := complete(t, c.Compile(b))
	found := false
	for _, e := range s.Effects() {
		if e.Kind == ScopeAdmin && e.Provenance.Primitive == "scope_self" {
			found = true
		}
	}
	if !found {
		t.Fatal("scope-self admin effect потерян")
	}
	creator := binding(domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"create"}})
	creator.Recipient = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
	s = complete(t, c.Compile(creator))
	found = false
	for _, e := range s.Effects() {
		if e.Type == "account" && e.Action.Name == "service_account_creator" && e.Provenance.Primitive == "container" {
			found = true
		}
	}
	if !found {
		t.Fatal("контейнерное право потеряно")
	}
}
func TestCarrierZeroDoesNotBecomeMetaAndFiniteMetaDoesNotBecomeAdmin(t *testing.T) {
	c := compiler(t)
	b := binding(domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}})
	newSet := complete(t, c.Compile(b))
	b.CapabilityVersion = 0
	oldSet := complete(t, c.Compile(b))
	for _, e := range oldSet.Effects() {
		if e.Kind == CreateBinding {
			t.Fatal("version0 приобрёл meta")
		}
	}
	proves(t, oldSet, newSet, false)
	b.CapabilityVersion = 1
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.accessBinding", ID: "ab-x"}}}
	if c.Compile(b).Complete() {
		t.Fatal("finite meta carrier принят")
	}
	admin := complete(t, c.CompileDirect(Direct{SourceID: "admin", ObjectType: "account", ObjectID: "acc-a", Relation: "admin", Recipient: b.Recipient}))
	onlyAdmin := Set{identity: admin.identity}
	for _, e := range admin.effects {
		if e.Kind == ScopeAdmin {
			onlyAdmin.effects = append(onlyAdmin.effects, e)
		}
	}
	proves(t, newSet, onlyAdmin, false)
}
func TestLegacyAndUnknownProducerRemainExplicit(t *testing.T) {
	c := compiler(t)
	b := binding()
	b.Role.Permissions = domain.Permissions{"iam.account.*.*"}
	s := complete(t, c.Compile(b))
	found := false
	for _, e := range s.Effects() {
		found = found || e.Kind == ScopeAdmin
	}
	if !found {
		t.Fatal("legacy scope admin потерян")
	}
	b = binding(box("get"))
	b.CapabilityVersion = 99
	if c.Compile(b).Complete() {
		t.Fatal("неизвестная версия")
	}
}
func TestConditionParametersDoNotRoundLargeIntegers(t *testing.T) {
	c := compiler(t)
	d := Direct{SourceID: "fact", ObjectType: "strange_box", ObjectID: "x", Relation: "console", Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "user-a"}, Condition: Condition{Name: "fresh", Parameters: `{"n":9007199254740992}`}}
	a := complete(t, c.CompileDirect(d))
	d.Condition.Parameters = `{"n":9007199254740993}`
	b := complete(t, c.CompileDirect(d))
	if Prove(a, b).Reason != grantcoverage.ReasonUnsupported {
		t.Fatal("условия были отождествлены либо скрыто выданы за обычный отказ")
	}
}

func TestUnsupportedPlanAndCrossAnchorNeedProof(t *testing.T) {
	bad := strings.Replace(modelFixture, "define v_update: [user, service_account, group#member]", "define v_update: [user with fresh]", 1)
	c, err := New(bad, rows())
	if err != nil {
		t.Fatal(err)
	}
	if c.Compile(binding(box("get"))).Complete() {
		t.Fatal("невыразимый Plan потерян")
	}
	c = compiler(t)
	a := binding(box("get"))
	w := a
	w.Scope = domain.ScopeAnchor{Type: "project", ID: "prj-a"}
	r := Prove(complete(t, c.Compile(a)), complete(t, c.Compile(w)))
	if r.Status == grantcoverage.Proved || r.Reason != grantcoverage.ReasonUnsupported {
		t.Fatalf("не доказанная account/project связь: %+v", r)
	}
}

func TestLegacySharedProducerCapsAccountAndPreservesFiniteAnchor(t *testing.T) {
	c := compiler(t)
	legacy := func(scope domain.ScopeAnchor, permissions ...domain.Permission) Set {
		b := binding()
		b.Scope = scope
		b.Role.Permissions = permissions
		b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probemod.boxes", ID: "x"}}}
		return complete(t, c.Compile(b))
	}
	account := domain.ScopeAnchor{Type: "account", ID: "acc-a"}
	narrow := legacy(account, "vpc.network.*.*")
	for _, e := range narrow.Effects() {
		if e.Kind == ScopeAdmin {
			t.Fatal("leaf legacy permission стал scope admin")
		}
		if e.Type == "account" && len(e.Constraints) > 0 && len(e.Constraints[0].Path) == 0 && !contains(e.Constraints[0].Region.Objects.IDs, "acc-a") {
			t.Fatal("legacy scope подменён finite target")
		}
	}
	mixed := legacy(account, "iam.account.*.get", "vpc.network.*.*")
	for _, e := range mixed.Effects() {
		if e.Kind == ScopeAdmin || e.Type == "account" && e.Action.Name == "editor" {
			t.Fatal("account read получил чужой tier")
		}
	}
	wide := legacy(account, "iam.account.*.*")
	proves(t, narrow, wide, false)
	proves(t, wide, narrow, true)
	cluster := legacy(domain.ScopeAnchor{Type: "cluster", ID: "cluster_root"}, "vpc.network.*.update")
	found := false
	for _, e := range cluster.Effects() {
		if e.Kind == ScopeAdmin && e.Type == "cluster" {
			found = true
		}
	}
	if !found {
		t.Fatal("cluster editor не прошёл общий direct mapping")
	}
}

func TestChildrenKeepStructuralParentsWithoutTTUCascade(t *testing.T) {
	flat := strings.ReplaceAll(modelFixture, " or admin from parent", "")
	c, err := New(flat, rows())
	if err != nil {
		t.Fatal(err)
	}
	r := box("get")
	r.ResourceNames = []string{"parent-x"}
	r.Children = domain.Rules{{Resources: []string{"tags"}, Verbs: []string{"get"}}}
	s := complete(t, c.Compile(binding(r)))
	found := false
	for _, e := range s.Effects() {
		if e.Type == "strange_tag" {
			for _, constraint := range e.Constraints {
				if len(constraint.Path) == 2 && constraint.Type == "strange_box" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("structural parent исчез без TTU")
	}
	proves(t, s, s, true)
}

// structuralPathCompiler задаёт асимметричный мир: обычное чтение box даёт
// чтение child только через direct; children выбирает также структурных предков,
// которые ни одним TTU модели не читаются.
func structuralPathCompiler(t *testing.T, variant string, reverse bool) *Compiler {
	t.Helper()
	dsl := `model
  schema 1.1
type user
type box
  relations
    define viewer: [user]
    define v_get: [user] or viewer
type child
  relations
    define direct: [box]
    define viewer: [user] or viewer from direct
    define v_get: [user] or viewer
`
	cat := catalog.Halves{Live: catalog.Rows{Modules: []string{"probemod"}, Resources: []catalog.ResourceRow{
		{Module: "probemod", Resource: "boxes", ObjectType: "box"},
		{Module: "probemod", Resource: "children", ObjectType: "child", ParentTypes: []string{"box"}, ParentNames: []string{"direct"}},
	}, Verbs: []catalog.VerbRow{
		{Module: "probemod", Resource: "boxes", Verb: "get", PerObject: true},
		{Module: "probemod", Resource: "children", Verb: "get", PerObject: true},
	}}}
	add := func(typ, rel, target string) {
		dsl += "type " + typ + "\n  relations\n    define " + rel + ": [" + target + "]\n"
		cat.Live.Resources = append(cat.Live.Resources, catalog.ResourceRow{Module: "probemod", Resource: typ, ObjectType: typ, ParentTypes: []string{target}, ParentNames: []string{rel}})
	}
	switch variant {
	case "short":
	case "short_with_tail":
		dsl = strings.Replace(dsl, "type box\n  relations", "type box\n  relations\n    define exit: [a]", 1)
		cat.Live.Resources[0].ParentTypes = []string{"a"}
		cat.Live.Resources[0].ParentNames = []string{"exit"}
		add("a", "next", "b")
		add("b", "next", "c")
		add("c", "next", "d")
		add("d", "next", "e")
		dsl += "type e\n"
		cat.Live.Resources = append(cat.Live.Resources, catalog.ResourceRow{Module: "probemod", Resource: "e", ObjectType: "e"})
	case "long", "cycle":
		dsl = strings.Replace(dsl, "    define direct: [box]", "    define direct: [box]\n    define tail: [a]", 1)
		cat.Live.Resources[1].ParentTypes = append(cat.Live.Resources[1].ParentTypes, "a")
		cat.Live.Resources[1].ParentNames = append(cat.Live.Resources[1].ParentNames, "tail")
		add("a", "next", "b")
		if variant == "long" {
			add("b", "next", "c")
			add("c", "next", "d")
			add("d", "next", "box")
		} else {
			add("b", "loop", "a")
			dsl += "    define finish: [box]\n"
			last := &cat.Live.Resources[len(cat.Live.Resources)-1]
			last.ParentTypes = append(last.ParentTypes, "box")
			last.ParentNames = append(last.ParentNames, "finish")
		}
	case "cycle_after_container":
		dsl = strings.Replace(dsl, "type box\n  relations", "type box\n  relations\n    define back: [child]", 1)
		cat.Live.Resources[0].ParentTypes = []string{"child"}
		cat.Live.Resources[0].ParentNames = []string{"back"}
	default:
		t.Fatalf("неизвестный вариант %s", variant)
	}
	if reverse && len(cat.Live.Resources[1].ParentTypes) == 2 {
		r := &cat.Live.Resources[1]
		r.ParentTypes[0], r.ParentTypes[1] = r.ParentTypes[1], r.ParentTypes[0]
		r.ParentNames[0], r.ParentNames[1] = r.ParentNames[1], r.ParentNames[0]
	}
	c, err := New(dsl, cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.modelObligations) != 0 {
		t.Fatalf("модель фикстуры не принята: %+v", c.modelObligations)
	}
	return c
}

func structuralPathProposal() (Binding, Binding) {
	actorRule := box("get")
	actorRule.ResourceNames = []string{"x"}
	proposedRule := actorRule
	proposedRule.Children = domain.Rules{{Resources: []string{"children"}, Verbs: []string{"get"}}}
	return binding(actorRule), binding(proposedRule)
}

func TestMixedShortLongChildrenNeverProveDroppedBranch(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		c := structuralPathCompiler(t, "long", reverse)
		ab, pb := structuralPathProposal()
		actor := complete(t, c.Compile(ab))
		proposed := c.Compile(pb)
		if proposed.Complete() {
			t.Fatalf("пятишаговая ветвь потеряна при reverse=%v", reverse)
		}
		found := false
		for _, o := range proposed.Obligations() {
			if o.Code == "selector" && strings.Contains(o.Detail, "structural_limit: parent path") {
				found = true
			}
		}
		if !found {
			t.Fatalf("нет явного обязательства глубины: %+v", proposed.Obligations())
		}
		// Actor уже даёт весь короткий эффект proposed через прямой TTU. Именно
		// поэтому сравнение с самим собой не обнаружило бы потерю длинной ветви.
		result := Prove(actor, proposed)
		if result.Status == grantcoverage.Proved || result.Reason != grantcoverage.ReasonIncomplete {
			t.Fatalf("частичный proposed доказан: %+v", result)
		}
	}
}

func TestShortOnlyChildrenStillProvedByParentRelation(t *testing.T) {
	for _, variant := range []string{"short", "short_with_tail"} {
		c := structuralPathCompiler(t, variant, false)
		ab, pb := structuralPathProposal()
		actor := complete(t, c.Compile(ab))
		proposed := complete(t, c.Compile(pb))
		proves(t, actor, proposed, true)
	}
}

func TestStructuralCycleKeepsExplicitIncompleteObligation(t *testing.T) {
	for _, variant := range []string{"cycle", "cycle_after_container"} {
		c := structuralPathCompiler(t, variant, false)
		ab, pb := structuralPathProposal()
		actor := complete(t, c.Compile(ab))
		proposed := c.Compile(pb)
		if proposed.Complete() {
			t.Fatalf("цикл %s молча усечён", variant)
		}
		found := false
		for _, o := range proposed.Obligations() {
			if o.Code == "selector" && strings.Contains(o.Detail, "unsupported_parent_cycle") {
				found = true
			}
		}
		if !found {
			t.Fatalf("цикл %s не назван: %+v", variant, proposed.Obligations())
		}
		result := Prove(actor, proposed)
		if result.Status == grantcoverage.Proved || result.Reason != grantcoverage.ReasonIncomplete {
			t.Fatalf("цикл %s: %+v", variant, result)
		}
	}
}

// Проекции чтения роли не меняют effect и не вызываются компилятором.
func TestRoleReadProjectionCallbackIsNotCompilerInput(t *testing.T) {
	c := compiler(t)
	b := binding(box("get"))
	plain := complete(t, c.Compile(b))
	b.Role.TypeVerbs = func(string, string) ([]string, bool) { panic("read projection callback reached compiler") }
	withProjection := complete(t, c.Compile(b))
	if !EqualEffects(plain, withProjection) {
		t.Fatal("проекция чтения изменила выдаваемый эффект")
	}
}

// Положительный мир содержит допустимую цепь из четырёх указателей. Возврат
// лишнего project сохраняет прежний отказ: глубина модели не ослаблена ради проб.
func TestUnsupportedModelPointerDepthRemainsIncomplete(t *testing.T) {
	deep := strings.Replace(modelFixture,
		"type strange_box\n  relations\n    define account: [account]\n    define admin: [user, service_account, group#member] or admin from account",
		"type strange_box\n  relations\n    define project: [project]\n    define admin: [user, service_account, group#member] or admin from project", 1)
	h := rows()
	h.Live.Resources[0].ParentTypes = []string{"project"}
	h.Live.Resources[0].ParentNames = []string{"project"}
	c, err := New(deep, h)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Compile(binding(box("get")))
	found := false
	for _, o := range s.Obligations() {
		found = found || o.Code == "model_plan" && strings.Contains(o.Detail, "глубже 4")
	}
	if s.Complete() || !found || Prove(s, s).Reason != grantcoverage.ReasonIncomplete {
		t.Fatalf("недопустимая глубина модели потеряна: %+v", s.Obligations())
	}
}
