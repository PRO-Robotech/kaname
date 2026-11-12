// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// Compiler закрепляет полные байты модели и обе половины каталога. New не
// устанавливает глобальную модель и не изменяет ни одного внешнего объекта.
type Compiler struct {
	plans            *authzmodel.Plans
	facts            *catalog.Facts
	identity         grantcoverage.Identity
	derivations      []authzmodel.EffectDerivation
	authored         map[string]map[string]bool
	parents          map[string][]authzmodel.EffectHop
	modelObligations []Obligation
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func New(modelSource string, halves catalog.Halves) (*Compiler, error) {
	raw, err := json.Marshal(halves)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxInputBytes || len(modelSource) > MaxInputBytes {
		return nil, fmt.Errorf("structural_limit: model/catalog")
	}
	// Копия разрывает общие с вызывающим карты и срезы строк каталога.
	var copy catalog.Halves
	if err = json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(copy)
	if err != nil {
		return nil, err
	}
	plans, err := authzmodel.New(modelSource)
	if err != nil {
		return nil, err
	}
	c := &Compiler{plans: plans, facts: facts, identity: grantcoverage.Identity{ModelID: digest([]byte(modelSource)), CatalogID: digest(raw)}}
	c.parents = map[string][]authzmodel.EffectHop{}
	for _, r := range copy.Live.Resources {
		if len(r.ParentTypes) != len(r.ParentNames) {
			c.modelObligations = append(c.modelObligations, Obligation{Code: "catalog_parent", Detail: r.ObjectType + ": unpaired names/types"})
			continue
		}
		for i, to := range r.ParentTypes {
			name := r.ParentNames[i]
			if !plans.EffectDirectAccepts(r.ObjectType, name, to, "", "") {
				c.modelObligations = append(c.modelObligations, Obligation{Code: "catalog_parent", Detail: r.ObjectType + "." + name + " -> " + to})
				continue
			}
			c.parents[r.ObjectType] = append(c.parents[r.ObjectType], authzmodel.EffectHop{From: r.ObjectType, Pointer: name, To: to})
		}
	}
	c.authored = map[string]map[string]bool{}
	for _, v := range copy.Live.Verbs {
		key := v.Module + "." + v.Resource
		if c.authored[key] == nil {
			c.authored[key] = map[string]bool{}
		}
		c.authored[key][domain.NormalizeVerb(v.Verb)] = true
	}
	declarations := 0
	for _, typ := range plans.EffectTypes() {
		names, _ := plans.RelationNames(typ)
		for _, rel := range names {
			declarations++
			if declarations > MaxEffects {
				return nil, fmt.Errorf("structural_limit: model declarations")
			}
			ds, err := plans.EffectDerivations(typ, rel)
			if err != nil {
				c.modelObligations = append(c.modelObligations, Obligation{Code: "model_plan", Detail: typ + "." + rel + ": " + err.Error()})
				continue
			}
			if len(ds) > MaxSteps-len(c.derivations) {
				return nil, fmt.Errorf("structural_limit: model derivations")
			}
			c.derivations = append(c.derivations, ds...)
		}
	}
	return c, nil
}

func (c *Compiler) Compile(b Binding) Set {
	s := Set{identity: c.identity, obligations: append([]Obligation(nil), c.modelObligations...)}
	p := Provenance{SourceID: b.SourceID, RoleID: b.Role.ID}
	fail := func(code, detail string) { s.obligations = append(s.obligations, Obligation{code, detail, p}) }
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxInputBytes {
		fail("structural_limit", "binding input")
		return s
	}
	if b.SourceID == "" || !domain.IsScopeAnchorKind(b.Scope.Type) || domain.DeriveFromResourceType(b.Scope.Type).ValidateAgainst(b.Scope.Type, b.Scope.ID) != nil {
		fail("input", "source/scope")
		return s
	}
	if b.CapabilityVersion != 0 && b.CapabilityVersion != 1 {
		fail("capability_version", "unknown version")
		return s
	}
	if err := b.Target.Validate(); err != nil {
		fail("input", err.Error())
		return s
	}
	if b.Recipient.Validate() != nil {
		fail("input", "invalid recipient")
		return s
	}
	switch b.Recipient.Type {
	case domain.SubjectTypeUser, domain.SubjectTypeServiceAccount, domain.SubjectTypeGroup:
	default:
		fail("recipient_producer", "system-class public_reader requires shared subject emitter")
		return s
	}
	if len(b.Role.Rules) == 0 {
		if len(b.Role.Permissions) > 0 {
			permissions := make([]string, len(b.Role.Permissions))
			for i, v := range b.Role.Permissions {
				permissions[i] = string(v)
			}
			// Прежняя ветвь пишет на scope, в том числе при конечном target. Нельзя
			// подменить её пообъектным смыслом rules либо новым meta split.
			ep := p
			ep.Primitive = "legacy_scope"
			ep.AuthoredRuleFP = digest(raw)
			relations := authzmap.LegacyScopeTierRelations(b.Scope.Type, permissions)
			for _, rel := range authzmap.ScopeDirectRelations(b.Scope.Type, relations) {
				c.derive(&s, b.Scope.Type, string(rel), exact(b.Scope.Type, b.Scope.ID), Condition{}, ep)
			}
		}
		return s
	}
	policy := domain.PolicyOfRole(b.Role.IsSystem, b.Role.OwnerModule)
	rules := b.Role.Rules
	if err := rules.Validate(policy, c.facts); err != nil {
		fail("input", err.Error())
		return s
	}
	if b.CapabilityVersion == 1 {
		ordinary, caps, err := domain.SplitGrantCapabilityRules(rules)
		if err != nil {
			fail("input", err.Error())
			return s
		}
		if len(caps) > 0 && len(b.Target.Resources) > 0 {
			fail("input", "meta carrier requires allInScope")
			return s
		}
		rules = ordinary
		for _, cap := range caps {
			ep := p
			ep.AuthoredRuleFP = cap.RuleFP
			ep.ProjectedRuleFP = cap.RuleFP
			ep.Primitive = "explicit_meta"
			k := CreateBinding
			modelType, modelRelation := grantcapability.ScopeObjectType, grantcapability.CreateRelation
			dotted, verb := "iam.accessBinding", "create"
			if cap.Kind == domain.GrantCapabilityBindRole {
				k = BindRole
				modelType, modelRelation = grantcapability.RoleObjectType, grantcapability.BindRelation
				dotted, verb = "iam.role", "bind"
			}
			if err := c.plans.GrantCapabilityPlan(modelType, modelRelation); err != nil {
				s.obligations = append(s.obligations, Obligation{"meta_model", modelType + "." + modelRelation, ep})
				continue
			}
			if !c.authored[dotted][verb] {
				s.obligations = append(s.obligations, Obligation{"catalog_meta", dotted + "." + verb, ep})
				continue
			}
			c.append(&s, Effect{Kind: k, Anchor: b.Scope, RoleID: cap.BoundRoleID, Provenance: ep})
		}
	}
	// Каждая авторская строка проходит split отдельно: provenance остатка не
	// угадывает совпадение остаточного отпечатка с исходной строкой.
	origins := map[string]string{}
	for _, r := range b.Role.Rules {
		rr := domain.Rules{r}
		if b.CapabilityVersion == 1 {
			rr, _, _ = domain.SplitGrantCapabilityRules(rr)
		}
		for _, sel := range rr.MaterializingSelectorsInScope(domain.DeriveFromResourceType(b.Scope.Type)) {
			origins[sel.RuleFP] = r.Fingerprint()
		}
	}
	for _, r := range rules {
		if r.Module == "*" || contains(r.Resources, "*") {
			fail("wildcard_type_producer", "shared live-catalog wildcard expansion and cluster short-circuit required")
		}
	}
	selectors := c.facts.GrantSelectors(rules.MaterializingSelectorsInScope(domain.DeriveFromResourceType(b.Scope.Type)), policy)
	roleVerbs := map[domain.RoleVerb]bool{}
	for _, v := range c.facts.RoleVerbsFromSelectors(selectors, policy) {
		roleVerbs[v] = true
	}
	for _, sel := range selectors {
		ep := p
		ep.AuthoredRuleFP = origins[sel.RuleFP]
		ep.ProjectedRuleFP = sel.RuleFP
		ep.Primitive = "object_rule"
		for _, dotted := range sel.ObjectTypes {
			typ, ok := c.facts.FGAObjectType(dotted)
			if !ok {
				s.obligations = append(s.obligations, Obligation{"catalog_type", dotted, ep})
				continue
			}
			for _, v := range sel.Verbs {
				if v != "*" && !c.authored[dotted][domain.NormalizeVerb(v)] {
					s.obligations = append(s.obligations, Obligation{"catalog_verb", dotted + "." + v, ep})
				}
			}
			for _, v := range sel.Grants[dotted] {
				if !roleVerbs[domain.RoleVerb{ObjectType: dotted, Verb: v}] {
					s.obligations = append(s.obligations, Obligation{"projection_mismatch", dotted + "." + v, ep})
				}
			}
			regions, err := c.selectorRegions(sel, dotted, typ, b)
			if err != nil {
				s.obligations = append(s.obligations, Obligation{"selector", err.Error(), ep})
				continue
			}
			verbs := c.facts.ObjectVerbs(dotted, sel.Verbs)
			if len(verbs) > 0 {
				relations := c.facts.ObjectRelations(typ, verbs, c.typeVerbs(typ), policy)
				for _, region := range regions {
					for _, rel := range relations {
						if sel.CreatedBySubject && !strings.HasPrefix(rel, "v_") {
							continue
						}
						c.derive(&s, typ, rel, region, Condition{}, ep)
					}
					if contains(verbs, "*") {
						// Отдельный символ сохраняет будущие глаголы, но не выдаёт meta-bind.
						c.append(&s, Effect{Kind: Use, Type: typ, Action: grantcoverage.Action{Kind: grantcoverage.AllVerbs}, Constraints: region, Provenance: ep})
					}
				}
			}
			// Контейнерный producer адресует собственный scope только для SA и без
			// конечной цели; селектор объектов не подменяет эту семантику.
			if sel.Container == nil && len(b.Target.Resources) == 0 && b.Recipient.Type == domain.SubjectTypeServiceAccount {
				for _, v := range sel.Verbs {
					if g, ok := c.facts.ContainerVerb(dotted, v); ok && g.ParentType == b.Scope.Type {
						cp := ep
						cp.Primitive = "container"
						c.derive(&s, g.ParentType, g.Relation, exact(g.ParentType, b.Scope.ID), Condition{}, cp)
					}
				}
			}
		}
	}
	if len(b.Target.Resources) == 0 && b.Scope.Type != "cluster" {
		verbs := rules.ScopeSelfVerbs(b.Scope.Type, c.typeVerbs(b.Scope.Type))
		if len(verbs) > 0 {
			ep := p
			ep.Primitive = "scope_self"
			ep.ProjectedRuleFP = "scope_self"
			ep.AuthoredRuleFP = digest(raw)
			for _, rel := range c.facts.ScopeSelfRelations(b.Scope.Type, verbs, c.typeVerbs(b.Scope.Type)) {
				c.derive(&s, b.Scope.Type, rel, exact(b.Scope.Type, b.Scope.ID), Condition{}, ep)
			}
		}
	}
	return s
}

func (c *Compiler) typeVerbs(typ string) []string {
	if v := c.facts.VerbsOfType(typ); len(v) > 0 {
		return v
	}
	return c.facts.CommonVerbVocabulary()
}
func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
func universe() grantcoverage.Region {
	return grantcoverage.Region{Objects: grantcoverage.Objects{Kind: grantcoverage.AllObjects}, Creator: grantcoverage.Creator{Kind: grantcoverage.AnyCreator}}
}
func exact(typ, id string) []Constraint {
	r := universe()
	r.Objects = grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{id}}
	return []Constraint{{Type: typ, Region: r}}
}
func (c *Compiler) append(s *Set, e Effect) {
	if s.limited {
		return
	}
	raw, _ := json.Marshal(e)
	if len(raw) > MaxInputBytes-s.outputBytes {
		s.limited = true
		s.obligations = append(s.obligations, Obligation{Code: "structural_limit", Detail: "effect bytes"})
		return
	}
	s.outputBytes += len(raw)
	if len(s.effects) >= MaxEffects {
		s.limited = true
		if len(s.obligations) == 0 || s.obligations[len(s.obligations)-1].Code != "structural_limit" {
			s.obligations = append(s.obligations, Obligation{Code: "structural_limit", Detail: "effect output"})
		}
		return
	}
	e.Constraints = cloneConstraints(e.Constraints)
	s.effects = append(s.effects, e)
}

// CompileDirect сохраняет условие факта; declared with не заменяет condition
// фактической строки. Объявление безусловного admin не запрещается из-за того,
// что соседняя ветвь конечного отношения допускает mfa_fresh.
func (c *Compiler) CompileDirect(d Direct) Set {
	s := Set{identity: c.identity, obligations: append([]Obligation(nil), c.modelObligations...)}
	p := Provenance{SourceID: d.SourceID, Primitive: "direct_fact"}
	raw, _ := json.Marshal(d)
	if len(raw) > MaxInputBytes || d.SourceID == "" || d.ObjectID == "" || d.Recipient.Validate() != nil {
		s.obligations = append(s.obligations, Obligation{"input", "direct source", p})
		return s
	}
	typ := string(d.Recipient.Type)
	userset := ""
	if d.Recipient.Type == domain.SubjectTypeGroup {
		userset = "member"
	}
	if !c.plans.EffectDirectAccepts(d.ObjectType, d.Relation, typ, userset, d.Condition.Name) {
		s.obligations = append(s.obligations, Obligation{"direct_declaration", d.ObjectType + "." + d.Relation, p})
		return s
	}
	if d.Condition.Name == "" && d.Condition.Parameters != "" {
		s.obligations = append(s.obligations, Obligation{"condition", "parameters without name", p})
		return s
	}
	if d.Condition.Name != "" {
		var params bytes.Buffer
		if json.Compact(&params, []byte(d.Condition.Parameters)) != nil {
			s.obligations = append(s.obligations, Obligation{"condition", "invalid JSON parameters", p})
			return s
		}
		d.Condition.Parameters = params.String()
	}
	c.derive(&s, d.ObjectType, d.Relation, exact(d.ObjectType, d.ObjectID), d.Condition, p)
	return s
}
