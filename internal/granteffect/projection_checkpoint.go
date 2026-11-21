// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ProjectionCheckpoint описывает вычисление проекции, а не её присутствие в БД.
// RelevantCatalogID не зависит от постороннего модуля. Нулевое значение не proof.
type ProjectionCheckpoint struct{ AuthoredID, RelevantCatalogID, ProjectionID, ModelID, ProjectorVersion string }
type RoleProjection struct {
	Checkpoint   ProjectionCheckpoint
	Modules      []string
	Catalog      catalog.Halves
	Selectors    []domain.RuleSelector
	Verbs        []domain.RoleVerb
	Capabilities []domain.GrantCapabilityRule
}

// Projection использует тот же Facts и scope-agnostic primitive, что producer
// role_rule_selectors. Возвращаемые карты/срезы принадлежат этому вызову.
func (b *Bundle) Projection(role domain.Role) (RoleProjection, error) {
	if err := b.Validate(); err != nil {
		return RoleProjection{}, err
	}
	// Только authored semantics: TypeVerbs — read-only callback, не вход
	// checkpoint. DTO одновременно ограничивает и глубоко копирует правила.
	type authoredRole struct {
		Rules       domain.Rules
		Permissions domain.Permissions
		IsSystem    bool
		OwnerModule string
	}
	raw, err := json.Marshal(authoredRole{role.Rules, role.Permissions, role.IsSystem, role.OwnerModule})
	if err != nil || len(raw) > MaxInputBytes {
		return RoleProjection{}, fmt.Errorf("projection input limit")
	}
	var r authoredRole
	if err = json.Unmarshal(raw, &r); err != nil {
		return RoleProjection{}, err
	}
	policy := domain.PolicyOfRole(r.IsSystem, r.OwnerModule)
	if err = r.Rules.Validate(policy, b.compiler.facts); err != nil {
		return RoleProjection{}, err
	}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(r.Rules)
	if err != nil {
		return RoleProjection{}, err
	}
	for _, cap := range caps {
		dotted, verb := "iam.accessBinding", "create"
		if cap.Kind == domain.GrantCapabilityBindRole {
			dotted, verb = "iam.role", "bind"
		}
		if !b.compiler.facts.GrantVerb(dotted, verb) {
			return RoleProjection{}, fmt.Errorf("grant catalog axis unavailable")
		}
	}
	selectors := b.compiler.facts.GrantSelectors(ordinary.MaterializingSelectors(), policy)
	verbs := b.compiler.facts.RoleVerbsFromSelectors(ordinary.MaterializingSelectors(), policy)
	var halves catalog.Halves
	if err = json.Unmarshal(b.canonicalCatalog, &halves); err != nil {
		return RoleProjection{}, err
	}
	modules := map[string]bool{}
	for _, rule := range r.Rules {
		if rule.Module == "*" {
			for _, m := range halves.Live.Modules {
				modules[m] = true
			}
		} else {
			modules[rule.Module] = true
		}
	}
	// Релевантны также declared parents/container verbs: изменение их владельца
	// или формы не теряется при неизменных собственных глаголах роли.
	resources := append(append([]catalog.ResourceRow(nil), halves.Live.Resources...), halves.Retired.Resources...)
	byType := map[string]string{}
	for _, row := range resources {
		byType[row.ObjectType] = row.Module
	}
	changed := true
	for changed {
		changed = false
		add := func(typ string) {
			if m := byType[typ]; m != "" && !modules[m] {
				modules[m] = true
				changed = true
			}
		}
		for _, row := range resources {
			if modules[row.Module] {
				for _, parent := range row.ParentTypes {
					add(parent)
				}
			}
		}
		for _, v := range halves.Live.Verbs {
			if modules[v.Module] {
				add(v.ContainerParent)
			}
		}
	}
	subset := func(in catalog.Rows) catalog.Rows {
		out := catalog.Rows{}
		for _, m := range in.Modules {
			if modules[m] {
				out.Modules = append(out.Modules, m)
			}
		}
		for _, r := range in.Resources {
			if modules[r.Module] {
				out.Resources = append(out.Resources, r)
			}
		}
		for _, v := range in.Verbs {
			if modules[v.Module] {
				out.Verbs = append(out.Verbs, v)
			}
		}
		return out
	}
	relevant := catalog.Halves{Live: subset(halves.Live), Retired: subset(halves.Retired)}
	canonical, err := catalog.CanonicalJSON(relevant)
	if err != nil {
		return RoleProjection{}, err
	}
	authored, err := json.Marshal(struct {
		Rules       domain.Rules
		Permissions domain.Permissions
		System      bool
		Owner       string
	}{r.Rules, append(domain.Permissions{}, r.Permissions...), r.IsSystem, r.OwnerModule})
	if err != nil {
		return RoleProjection{}, err
	}
	projection, err := ProjectionJSON(selectors, verbs, caps)
	if err != nil {
		return RoleProjection{}, err
	}
	names := []string{}
	for m := range modules {
		names = append(names, m)
	}
	sort.Strings(names)
	return RoleProjection{Checkpoint: ProjectionCheckpoint{AuthoredID: digest(authored), RelevantCatalogID: digest(canonical), ProjectionID: digest(projection), ModelID: b.Identity().ModelID, ProjectorVersion: ProjectorVersion}, Modules: names, Catalog: relevant, Selectors: selectors, Verbs: verbs, Capabilities: caps}, nil
}

// ProjectionJSON канонизирует именно сохраняемые producer поля. Verbs в
// RuleSelector — вход вычисления, а не колонка; Grants — сохраняемый результат.
func ProjectionJSON(selectors []domain.RuleSelector, verbs []domain.RoleVerb, capabilities ...[]domain.GrantCapabilityRule) ([]byte, error) {
	type row struct {
		FP, Arm      string
		Types, Names []string
		Labels       map[string]string
		Container    *domain.ContainerSelector
		Creator      bool
		Grants       map[string][]string
	}
	rows := []row{}
	for _, s := range selectors {
		if len(s.ObjectTypes) == 0 {
			continue
		}
		arm := "anchor"
		if s.Arm == domain.ArmNames {
			arm = "names"
		}
		if s.Arm == domain.ArmLabels {
			arm = "labels"
		}
		types := append([]string{}, s.ObjectTypes...)
		names := append([]string{}, s.ResourceNames...)
		sort.Strings(types)
		sort.Strings(names)
		labels := s.MatchLabels
		if labels == nil {
			labels = map[string]string{}
		}
		grants := map[string][]string{}
		for k, v := range s.Grants {
			grants[k] = append([]string{}, v...)
			sort.Strings(grants[k])
		}
		var container *domain.ContainerSelector
		if s.Container != nil {
			copy := *s.Container
			copy.OwnerFP = ""
			copy.ResourceNames = append([]string{}, copy.ResourceNames...)
			sort.Strings(copy.ResourceNames)
			if copy.MatchLabels == nil {
				copy.MatchLabels = map[string]string{}
			}
			container = &copy
		}
		rows = append(rows, row{s.RuleFP, arm, types, names, labels, container, s.CreatedBySubject, grants})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].FP < rows[j].FP })
	vv := append([]domain.RoleVerb{}, verbs...)
	sort.Slice(vv, func(i, j int) bool {
		a, _ := json.Marshal(vv[i])
		z, _ := json.Marshal(vv[j])
		return string(a) < string(z)
	})
	caps := []domain.GrantCapabilityRule{}
	for _, batch := range capabilities {
		caps = append(caps, batch...)
	}
	sort.Slice(caps, func(i, j int) bool {
		a, _ := json.Marshal(caps[i])
		z, _ := json.Marshal(caps[j])
		return string(a) < string(z)
	})
	return json.Marshal(struct {
		Capabilities []domain.GrantCapabilityRule
		Selectors    []row
		Verbs        []domain.RoleVerb
	}{caps, rows, vv})
}
