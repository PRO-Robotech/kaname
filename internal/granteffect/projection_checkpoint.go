// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
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
		switch cap.Kind {
		case domain.GrantCapabilityCreateBinding, domain.GrantCapabilityBindRole:
		case domain.GrantCapabilityApplyAccessLabel:
			// Строка каталога сама по себе не доказывает точный native-план.
			if err := b.GrantCapabilityPlan(grantcapability.AccessLabelObjectType, grantcapability.ApplyAccessLabelRelation); err != nil {
				return RoleProjection{}, err
			}
		default:
			return RoleProjection{}, fmt.Errorf("grant catalog axis unavailable")
		}
		ref, _ := cap.Kind.RuleRef()
		if !b.compiler.facts.GrantVerb(ref.Module+"."+ref.Resource, ref.Verb) {
			return RoleProjection{}, fmt.Errorf("grant catalog axis unavailable")
		}
	}
	selectors := b.compiler.facts.GrantSelectors(b.compiler.facts.MaterializingSelectors(ordinary), policy)
	verbs := b.compiler.facts.RoleVerbsFromSelectors(selectors, policy)
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
		AccessLabels map[string]string `json:",omitempty"`
	}
	rows := []row{}
	for _, s := range selectors {
		if len(s.ObjectTypes) == 0 {
			continue
		}
		var arm string
		switch s.Arm {
		case domain.ArmAnchor:
			arm = "anchor"
		case domain.ArmNames:
			arm = "names"
		case domain.ArmLabels:
			arm = "labels"
		case domain.ArmAccessLabels:
			arm = "access_labels"
		default:
			return nil, fmt.Errorf("неподдерживаемая ветвь проекции роли: %d", s.Arm)
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
			switch s.Container.Arm {
			case domain.ArmAnchor, domain.ArmNames, domain.ArmLabels, domain.ArmAccessLabels:
			default:
				return nil, fmt.Errorf("неподдерживаемая ветвь проекции контейнера: %d", s.Container.Arm)
			}
			copy := *s.Container
			copy.OwnerFP = ""
			copy.ResourceNames = append([]string{}, copy.ResourceNames...)
			sort.Strings(copy.ResourceNames)
			if copy.MatchLabels == nil {
				copy.MatchLabels = map[string]string{}
			}
			container = &copy
		}
		// Only the protected arm introduces the optional field. A malformed ordinary
		// selector must not erase a protected predicate from its checkpoint.
		if err := validateProjectionAccessLabels(s.Arm, s.MatchAccessLabels, s.MatchLabels, s.ResourceNames, s.CreatedBySubject); err != nil {
			return nil, err
		}
		if s.Container != nil {
			if err := validateProjectionAccessLabels(s.Container.Arm, s.Container.MatchAccessLabels, s.Container.MatchLabels, s.Container.ResourceNames, false); err != nil {
				return nil, err
			}
		}
		rows = append(rows, row{s.RuleFP, arm, types, names, labels, container, s.CreatedBySubject, grants, s.MatchAccessLabels})
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
	// Проекция роли не содержит scope: он принадлежит носителю. Идентификаторы
	// разных управляющих осей не должны подменять друг друга в сохранённой строке.
	for _, cap := range caps {
		switch cap.Kind {
		case domain.GrantCapabilityCreateBinding:
			if cap.BoundRoleID != "" || cap.DefinitionID != "" {
				return nil, fmt.Errorf("invalid create binding projection payload")
			}
		case domain.GrantCapabilityBindRole:
			if cap.BoundRoleID == "" || cap.BoundRoleID == "*" || cap.DefinitionID != "" {
				return nil, fmt.Errorf("invalid bind role projection payload")
			}
		case domain.GrantCapabilityApplyAccessLabel:
			if cap.BoundRoleID != "" || cap.DefinitionID.Validate() != nil {
				return nil, fmt.Errorf("invalid access label projection payload")
			}
		default:
			return nil, fmt.Errorf("unsupported grant projection kind")
		}
	}
	// DefinitionID уже входит в JSON и порядок сравнения. omitempty сохраняет
	// байты прежних create/bind и потому их контрольные суммы без изменений.
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

// Optional JSON keeps the previous field order and bytes for every old selector.
// Protected restrictions must never be dropped while building a checkpoint.
func validateProjectionAccessLabels(arm domain.Arm, protected, ordinary map[string]string, names []string, creator bool) error {
	if arm != domain.ArmAccessLabels {
		if len(protected) != 0 {
			return fmt.Errorf("access labels on a different selector arm")
		}
		return nil
	}
	if len(protected) == 0 || len(protected) > 16 || len(ordinary) != 0 || len(names) != 0 || creator {
		return fmt.Errorf("invalid access label projection shape")
	}
	for key, value := range protected {
		if err := domain.LabelKey(key).Validate(); err != nil {
			return err
		}
		if err := domain.LabelVal(value).Validate(); err != nil {
			return err
		}
	}
	return nil
}
