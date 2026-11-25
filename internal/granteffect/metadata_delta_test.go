// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

func metadataCompiler(t *testing.T) *Compiler {
	t.Helper()
	model := strings.Replace(modelFixture, "type strange_box\n", `    define v_get: [user, service_account, group#member] or viewer
    define v_update: [user, service_account, group#member]
    define v_delete: [user, service_account, group#member]
type strange_box
`, 1)
	model = strings.Replace(model, "condition fresh", `type metadata_leaf
  relations
    define parent: [project]
    define admin: [user, service_account, group#member] or admin from parent
    define editor: [user, service_account, group#member] or admin
    define viewer: [user, service_account, group#member] or editor
    define v_get: [user, service_account, group#member] or viewer
    define v_update: [user, service_account, group#member]
    define v_delete: [user, service_account, group#member]
condition fresh`, 1)
	h := rows()
	// iam.group проходит настоящий feed gate; модель задаёт двухшаговый путь
	// до account, чтобы проверить символические ограничения будущих потомков.
	h.Live.Resources = append(h.Live.Resources,
		catalog.ResourceRow{Module: "iam", Resource: "project", ObjectType: "project", ParentTypes: []string{"account"}, ParentNames: []string{"account"}},
		catalog.ResourceRow{Module: "iam", Resource: "group", ObjectType: "metadata_leaf", ParentTypes: []string{"project"}, ParentNames: []string{"parent"}})
	for _, resource := range []string{"project", "group"} {
		for _, verb := range []string{"get", "update", "delete"} {
			h.Live.Verbs = append(h.Live.Verbs, catalog.VerbRow{Module: "iam", Resource: resource, Verb: verb, PerObject: true})
		}
	}
	c, err := New(model, h)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func metadataPair(typ, id string) (MetadataObject, MetadataObject) {
	return MetadataObject{Type: typ, ID: id, Labels: domain.Labels{"env": "old"}},
		MetadataObject{Type: typ, ID: id, Labels: domain.Labels{"env": "new"}}
}

func completeMetadata(t *testing.T, d MetadataDelta) MetadataDelta {
	t.Helper()
	complete(t, d.Before)
	complete(t, d.After)
	return d
}

func TestMetadataDeltaDirectLabelsUseExactOldAndNewObject(t *testing.T) {
	c := metadataCompiler(t)
	for _, typ := range []string{"account", "project"} {
		t.Run(typ, func(t *testing.T) {
			old, next := metadataPair(typ, map[string]string{"account": "acc-a", "project": "prj-focus"}[typ])
			rule := domain.Rule{Module: "iam", Resources: []string{typ}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "new"}}
			b := binding(rule)
			ordinary := c.Compile(b)
			delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
			if len(delta.Before.Effects()) != 0 || len(delta.After.Effects()) == 0 {
				t.Fatalf("new label match lost: before=%+v after=%+v", delta.Before.Effects(), delta.After.Effects())
			}
			if delta.Before.Identity() != ordinary.Identity() || delta.After.Identity() != ordinary.Identity() {
				t.Fatal("specialization changed artifact identity")
			}
			for _, effect := range delta.After.Effects() {
				if effect.Provenance.SourceID != b.SourceID || effect.Provenance.RoleID != b.Role.ID ||
					effect.Provenance.AuthoredRuleFP != rule.Fingerprint() || effect.Provenance.ProjectedRuleFP == "" || effect.Provenance.ModelOrigin == "" {
					t.Fatalf("source lineage lost: %+v", effect)
				}
				for _, constraint := range effect.Constraints {
					if constraint.Type != typ || constraint.Region.Objects.Kind != grantcoverage.ObjectIDs ||
						!reflect.DeepEqual(constraint.Region.Objects.IDs, []string{next.ID}) || len(constraint.Region.Labels) != 0 ||
						constraint.Within == nil || *constraint.Within != b.Scope {
						t.Fatalf("focal region lost: %+v", constraint)
					}
				}
			}
			proves(t, delta.Before, delta.After, false)
			if !reflect.DeepEqual(ordinary, c.Compile(b)) {
				t.Fatal("metadata compilation mutated ordinary compiler")
			}
			removed := completeMetadata(t, c.compileMetadataDelta(b, next, old))
			if len(removed.Before.Effects()) == 0 || len(removed.After.Effects()) != 0 {
				t.Fatal("old-only match is not a withdrawal")
			}
		})
	}
}

func TestMetadataDeltaProtectedDirectAndNestedUseHeldImages(t *testing.T) {
	c := metadataCompiler(t)
	old := MetadataObject{Type: "account", ID: "acc-a", Labels: domain.Labels{"team": "blue"},
		AccessLabels: domain.Labels{"team": "red"}}
	next := old
	next.AccessLabels = domain.Labels{"team": "blue"}
	base := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		MatchAccessLabels: map[string]string{"team": "blue"}}
	nested := base
	nested.Children = []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}}}
	for name, rule := range map[string]domain.Rule{"direct": base, "nested": nested} {
		t.Run(name, func(t *testing.T) {
			b := binding(rule)
			added := completeMetadata(t, c.compileMetadataDelta(b, old, next))
			removed := completeMetadata(t, c.compileMetadataDelta(b, next, old))
			if len(added.Before.Effects()) != 0 || len(added.After.Effects()) == 0 ||
				len(removed.Before.Effects()) == 0 || len(removed.After.Effects()) != 0 {
				t.Fatal("protected change must add and remove effects independently of ordinary labels")
			}
			for _, effect := range added.After.Effects() {
				for _, constraint := range effect.Constraints {
					if constraint.Type == "account" && (constraint.Region.Objects.Kind != grantcoverage.ObjectIDs ||
						!reflect.DeepEqual(constraint.Region.Objects.IDs, []string{old.ID}) || len(constraint.Region.AccessLabels) != 0) {
						t.Fatalf("exact held account coordinate lost: %+v", constraint)
					}
				}
			}
		})
	}
}

func TestMetadataDeltaExternalCoordinatePreservesDirectAndNestedEffects(t *testing.T) {
	// Селектор меток проходит настоящий feed gate. Нестандартные FGA-типы
	// сохраняем, а каталожные имена берём у подтверждённого внешнего feed.
	h := rows()
	h.Live.Modules = append(h.Live.Modules, "registry")
	resourceNames := map[string]string{"boxes": "registries", "items": "repositories"}
	for i := range h.Live.Resources {
		r := &h.Live.Resources[i]
		if name, ok := resourceNames[r.Resource]; ok && r.Module == "probemod" {
			r.Module, r.Resource = "registry", name
		}
	}
	for i := range h.Live.Verbs {
		v := &h.Live.Verbs[i]
		if name, ok := resourceNames[v.Resource]; ok && v.Module == "probemod" {
			v.Module, v.Resource = "registry", name
		}
	}
	c, err := New(modelFixture, h)
	if err != nil {
		t.Fatal(err)
	}
	old := MetadataObject{
		Type: "strange_box", CatalogType: "registry.registries", ID: "registry/demo:tag",
		Labels: domain.Labels{"team": "new"}, AccessLabels: domain.Labels{"team": "old"},
	}
	next := old
	next.AccessLabels = domain.Labels{"team": "new"}
	direct := domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}}
	direct.MatchAccessLabels = map[string]string{"team": "new"}
	nested := direct
	nested.Children = []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}}

	for _, rule := range []domain.Rule{direct, nested} {
		b := binding(rule)
		added := completeMetadata(t, c.compileMetadataDelta(b, old, next))
		removed := completeMetadata(t, c.compileMetadataDelta(b, next, old))
		if len(added.Before.Effects()) != 0 || len(added.After.Effects()) == 0 ||
			len(removed.Before.Effects()) == 0 || len(removed.After.Effects()) != 0 {
			t.Fatal("изменение защищённой метки должно добавить и отозвать соответствующий эффект")
		}
		proves(t, added.Before, added.After, false)
		proves(t, added.After, added.After, true)
		childFound := false
		for _, effect := range added.After.Effects() {
			focal := false
			for _, constraint := range effect.Constraints {
				if constraint.Type == old.Type && constraint.Region.Objects.Kind == grantcoverage.ObjectIDs &&
					reflect.DeepEqual(constraint.Region.Objects.IDs, []string{old.ID}) {
					focal = true
				}
			}
			if !focal {
				t.Fatalf("в эффекте потеряна координата изменяемого внешнего объекта: %+v", effect)
			}
			if len(effect.Constraints) > 1 && effect.Constraints[0].Type == "strange_item" &&
				effect.Constraints[0].Region.Objects.Kind == grantcoverage.AllObjects {
				parent := effect.Constraints[1]
				if parent.Type == old.Type && len(parent.Path) == 1 && parent.Path[0].To == old.Type &&
					reflect.DeepEqual(parent.Region.Objects.IDs, []string{old.ID}) {
					childFound = true
				}
			}
		}
		if len(rule.Children) != 0 && !childFound {
			t.Fatal("эффект для вложенного типа должен удерживать путь к точному родителю")
		}
		b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: old.CatalogType, ID: "registry/other"}}}
		outside := completeMetadata(t, c.compileMetadataDelta(b, old, next))
		if len(outside.After.Effects()) != 0 {
			t.Fatal("правка текущего объекта не должна менять выдачу, закреплённую за другим объектом")
		}
	}

	b := binding(direct)
	for _, broken := range []MetadataObject{
		{Type: old.Type, ID: old.ID},
		{Type: old.Type, CatalogType: "registry.repositories", ID: old.ID},
		{Type: old.Type, CatalogType: "unknown.boxes", ID: old.ID},
		{Type: old.Type, CatalogType: old.CatalogType, ID: "*"},
		{Type: old.Type, CatalogType: old.CatalogType, ID: old.ID, CreatorKnown: true},
	} {
		delta := c.compileMetadataDelta(b, broken, broken)
		if delta.Before.Complete() || delta.After.Complete() {
			t.Fatalf("неподтверждённая внешняя координата принята: %+v", broken)
		}
	}
	changedType := next
	changedType.CatalogType = "registry.repositories"
	delta := c.compileMetadataDelta(b, old, changedType)
	if delta.Before.Complete() || delta.After.Complete() {
		t.Fatal("тип объекта сменился между OLD и NEW")
	}
}

func TestMetadataDeltaNestedContainerKeepsFutureChildrenAndSubpaths(t *testing.T) {
	c := metadataCompiler(t)
	old, next := metadataPair("account", "acc-a")
	for _, tc := range []struct{ name, child string }{{"project", "project"}, {"leaf", "group"}} {
		t.Run(tc.name, func(t *testing.T) {
			child := tc.child
			rule := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "new"},
				Children: []domain.Rule{{Resources: []string{child}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "blue"}}}}
			b := binding(rule)
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: next.ID}}}
			delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
			if len(delta.Before.Effects()) != 0 {
				t.Fatal("OLD container did not match")
			}
			found := false
			for _, effect := range delta.After.Effects() {
				if len(effect.Constraints) != 2 {
					continue
				}
				self, container := effect.Constraints[0], effect.Constraints[1]
				if self.Region.Objects.Kind != grantcoverage.AllObjects || self.Region.Labels["team"] != "blue" ||
					self.Within == nil || *self.Within != b.Scope || container.Within == nil || *container.Within != b.Scope ||
					container.Type != "account" || !reflect.DeepEqual(container.Region.Objects.IDs, []string{next.ID}) || len(container.Region.Labels) != 0 {
					t.Fatalf("child became finite or container target moved: %+v", effect)
				}
				depth := 1
				if child == "group" {
					depth = 2
				}
				if len(container.Path) < depth || container.Path[len(container.Path)-1].To != "account" {
					t.Fatalf("parent subpath lost: %+v", container.Path)
				}
				found = true
			}
			if !found {
				t.Fatal("symbolic nested effect absent; no inventory is supplied by this test")
			}
			// A finite target names the container, never the future child.
			b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam." + child, ID: "child-a"}}}
			wrong := completeMetadata(t, c.compileMetadataDelta(b, old, next))
			if len(wrong.Before.Effects()) != 0 || len(wrong.After.Effects()) != 0 {
				t.Fatal("child target incorrectly selected its container")
			}
		})
	}
}

func TestMetadataDeltaDirectChildKeepsUnchangedContainerPredicate(t *testing.T) {
	c := metadataCompiler(t)
	old, next := metadataPair("project", "prj-focus")
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"owner": "retained"},
		Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "new"}}}})
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: "acc-a"}}}
	delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
	if len(delta.Before.Effects()) != 0 || len(delta.After.Effects()) == 0 {
		t.Fatal("direct nested child label transition was lost")
	}
	for _, effect := range delta.After.Effects() {
		if len(effect.Constraints) != 2 || effect.Constraints[0].Type != "project" ||
			!reflect.DeepEqual(effect.Constraints[0].Region.Objects.IDs, []string{next.ID}) ||
			effect.Constraints[1].Region.Labels["owner"] != "retained" ||
			!reflect.DeepEqual(effect.Constraints[1].Region.Objects.IDs, []string{"acc-a"}) {
			t.Fatalf("direct/container predicates confused: %+v", effect)
		}
	}
}

func TestMetadataDeltaDirectTargetAndUnchangedLabels(t *testing.T) {
	c := metadataCompiler(t)
	old, next := metadataPair("account", "acc-a")
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, ResourceNames: []string{old.ID}})
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: old.ID}}}
	delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
	if len(delta.Before.Effects()) == 0 || !reflect.DeepEqual(delta.Before, delta.After) {
		t.Fatal("name/anchor selector should be invariant under labels")
	}
	b.Target.Resources[0].ID = "other-a"
	delta = completeMetadata(t, c.compileMetadataDelta(b, old, next))
	if len(delta.Before.Effects()) != 0 || len(delta.After.Effects()) != 0 {
		t.Fatal("foreign direct target selected focal object")
	}
}

func TestMetadataDeltaOmitsInvariantLegacyMetaAndScopeProducers(t *testing.T) {
	c := metadataCompiler(t)
	old, next := metadataPair("account", "acc-a")
	legacy := binding()
	legacy.Role.Permissions = domain.Permissions{"iam.account.*.get"}
	meta := binding(domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"role-x"}})
	meta.Role.IsSystem = true
	meta.Role.ClusterID = "cluster_root"
	creator := binding(domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"create"}})
	creator.Recipient = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
	for _, b := range []Binding{legacy, meta, creator} {
		delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
		if len(delta.Before.Effects()) != 0 || len(delta.After.Effects()) != 0 {
			t.Fatalf("invariant producer became a metadata grant: %+v", delta)
		}
		if len(complete(t, c.Compile(b)).Effects()) == 0 {
			t.Fatal("ordinary producer was changed or test did not exercise it")
		}
	}
}

func TestMetadataDeltaRejectsUnprovenInputsAndPreservesEmptyIdentity(t *testing.T) {
	c := metadataCompiler(t)
	old, next := metadataPair("account", "acc-a")
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
	for _, bad := range []MetadataObject{{Type: "project", ID: next.ID}, {Type: "account", ID: ""}, {Type: "account", ID: "other-a"}, {Type: "strange_box", ID: next.ID}} {
		delta := c.compileMetadataDelta(b, old, bad)
		if delta.Before.Complete() || delta.After.Complete() || len(delta.Before.Obligations()) == 0 || len(delta.After.Obligations()) == 0 {
			t.Fatal("unknown coordinate became complete empty delta")
		}
	}
	b.Role.IsSystem = true
	b.Role.Rules[0].Resources = []string{"*"}
	wildcard := c.compileMetadataDelta(b, old, next)
	if wildcard.Before.Complete() || wildcard.After.Complete() {
		t.Fatal("unproved wildcard type producer accepted")
	}
	b = binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}})
	b.Subjects = []domain.Subject{{Type: domain.SubjectTypeUser, ID: "different-user"}}
	if d := c.compileMetadataDelta(b, old, next); d.Before.Complete() || d.After.Complete() {
		t.Fatal("recipient missing from full binding subjects accepted")
	}
	for _, bundle := range []*Bundle{nil, {}} {
		if d := bundle.CompileMetadataDelta(b, old, next); d.Before.Complete() || d.After.Complete() {
			t.Fatal("invalid bundle accepted")
		}
	}
	valid := bundleCanon(t)
	b.Subjects = nil
	delta := completeMetadata(t, valid.CompileMetadataDelta(b, old, next))
	if delta.Before.Identity() != valid.Identity() || delta.After.Identity() != valid.Identity() {
		t.Fatal("public Bundle port lost pinned identity")
	}
}

func TestMetadataDeltaRejectsUnwitnessedCreatorAndAmbiguousFocalRole(t *testing.T) {
	c := metadataCompiler(t)
	focal, _ := metadataPair("project", "prj-focus")
	b := binding()
	b.Recipient = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
	for _, selector := range []domain.RuleSelector{
		{RuleFP: "creator", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.project"}, CreatedBySubject: true},
		{RuleFP: "both", Arm: domain.ArmAnchor, ObjectTypes: []string{"iam.project"}, Container: &domain.ContainerSelector{Type: "iam.project", Arm: domain.ArmAnchor}},
	} {
		if _, err := c.bindingSelectorRegions(selector, "iam.project", "project", b, &focal); err == nil {
			t.Fatal("unsupported focal witness was guessed")
		}
	}
}

func TestMetadataDeltaRequiresUnconditionedTypedProducerDeclaration(t *testing.T) {
	old, next := metadataPair("account", "acc-a")
	model := strings.Replace(modelFixture, "define v_get: [user, service_account, group#member]", "define v_get: [user with fresh, service_account, group#member]", 1)
	c, err := New(model, rows())
	if err != nil {
		t.Fatal(err)
	}
	b := binding(domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "new"}})
	delta := c.compileMetadataDelta(b, old, next)
	if delta.After.Complete() || !hasObligation(delta.After, "metadata_declaration") {
		t.Fatal("condition-only user declaration became an unconditioned metadata grant")
	}
	b.Recipient = domain.Subject{Type: domain.SubjectTypeGroup, ID: "group-a"}
	// Условный прямой глагол делает план всей модели неполным: допустимый
	// group#member не вправе скрыть это обязательство другого типа субъекта.
	delta = c.compileMetadataDelta(b, old, next)
	if delta.Before.Complete() || delta.After.Complete() ||
		!hasObligation(delta.Before, "model_plan") || !hasObligation(delta.After, "model_plan") ||
		hasObligation(delta.After, "metadata_declaration") {
		t.Fatal("group declaration must retain the globally incomplete model plan")
	}
	// Положительный контроль использует полную модель без условного глагола.
	delta = completeMetadata(t, compiler(t).compileMetadataDelta(b, old, next))
	if len(delta.After.Effects()) == 0 {
		t.Fatal("declared group#member source lost; membership must remain a userset")
	}
}

func TestMetadataDeltaPublicReaderKeepsUnmentionedFutureChildren(t *testing.T) {
	model := strings.NewReplacer("odd_box", "account", "odd_item", "project", "odd_sibling", "metadata_sibling").Replace(publicReaderModel)
	h := publicReaderRows(true)
	h.Live.Modules = []string{"iam"}
	names := map[string]string{"boxes": "account", "items": "project", "siblings": "sibling"}
	types := map[string]string{"odd_box": "account", "odd_item": "project", "odd_sibling": "metadata_sibling"}
	for i := range h.Live.Resources {
		r := &h.Live.Resources[i]
		r.Module, r.Resource, r.ObjectType = "iam", names[r.Resource], types[r.ObjectType]
		for j, typ := range r.ParentTypes {
			r.ParentTypes[j] = types[typ]
		}
	}
	for i := range h.Live.Verbs {
		v := &h.Live.Verbs[i]
		v.Module, v.Resource = "iam", names[v.Resource]
	}
	c, err := New(model, h)
	if err != nil {
		t.Fatal(err)
	}
	b := publicReaderBinding()
	b.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list"}, MatchLabels: map[string]string{"env": "new"},
		Children: domain.Rules{{Resources: []string{"project"}, Verbs: []string{"get", "list"}}}}}
	old, next := metadataPair("account", "acc-a")
	delta := completeMetadata(t, c.compileMetadataDelta(b, old, next))
	if len(delta.Before.Effects()) != 0 {
		t.Fatal("unselected OLD public-reader container contributed rights")
	}
	found := false
	for _, effect := range publicReaderEffects(delta.After) {
		if effect.Type == "metadata_sibling" && effect.Action == (grantcoverage.Action{Kind: grantcoverage.Verb, Name: "get"}) {
			found = true
			if len(effect.Constraints) != 1 || effect.Constraints[0].Type != "account" ||
				len(effect.Constraints[0].Path) != 1 || !reflect.DeepEqual(effect.Constraints[0].Region.Objects.IDs, []string{next.ID}) ||
				effect.Provenance.ProjectedRuleFP == "" || effect.Provenance.AuthoredRuleFP != b.Role.Rules[0].Fingerprint() {
				t.Fatalf("public-reader container or fingerprint lost: %+v", effect)
			}
		}
	}
	if !found {
		t.Fatal("public-reader delta was restricted to the named child instead of future siblings")
	}
}
