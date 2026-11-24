// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

func (c *Compiler) derive(s *Set, typ, rel string, region []Constraint, condition Condition, p Provenance) {
	if s.limited {
		return
	}
	found := false
	for _, d := range c.derivations {
		s.steps++
		if s.steps > MaxSteps {
			s.limited = true
			s.obligations = append(s.obligations, Obligation{"work_limit", "reverse derivation", p})
			return
		}
		if d.SourceType != typ || d.SourceRelation != rel {
			continue
		}
		found = true
		constraints := cloneConstraints(region)
		for i := range constraints {
			constraints[i].Path = append(append([]authzmodel.EffectHop(nil), d.Path...), constraints[i].Path...)
		}
		ep := p
		ep.ModelOrigin = d.Origin
		a := grantcoverage.Action{Kind: grantcoverage.Relation, Name: d.Relation}
		if strings.HasPrefix(d.Relation, "v_") {
			a = grantcoverage.Action{Kind: grantcoverage.Verb, Name: strings.TrimPrefix(d.Relation, "v_")}
		}
		c.append(s, Effect{Kind: Use, Type: d.ObjectType, Action: a, Constraints: constraints, Condition: condition, Provenance: ep})
		// Это не список нынешних ролей. Само отношение admin на настоящем виде
		// scope открывает сохранённый D3 ceiling; каскад читает тот же Plan.
		if domain.IsScopeAnchorKind(d.ObjectType) && d.Relation == "admin" {
			c.append(s, Effect{Kind: ScopeAdmin, Type: d.ObjectType, Constraints: constraints, Condition: condition, Provenance: ep})
		}
	}
	if !found {
		s.obligations = append(s.obligations, Obligation{"emitted_relation", typ + "." + rel, p})
	}
}

func selectorRegion(arm domain.Arm, ids []string, labels map[string]string) (grantcoverage.Region, error) {
	r := universe()
	switch arm {
	case domain.ArmAnchor:
	case domain.ArmNames:
		if len(ids) == 0 {
			return r, fmt.Errorf("empty names selector")
		}
		r.Objects = grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: append([]string(nil), ids...)}
	case domain.ArmLabels:
		if len(labels) == 0 {
			return r, fmt.Errorf("empty label selector")
		}
		r.Labels = map[string]string{}
		for k, v := range labels {
			r.Labels[k] = v
		}
	default:
		return r, fmt.Errorf("unknown selector arm")
	}
	return r, nil
}

func intersectTarget(r grantcoverage.Region, dotted string, t domain.AccessTarget) (grantcoverage.Region, bool) {
	if len(t.Resources) == 0 {
		return r, true
	}
	var ids []string
	for _, ref := range t.Resources {
		if ref.Type == dotted && (r.Objects.Kind == grantcoverage.AllObjects || contains(r.Objects.IDs, ref.ID)) {
			ids = append(ids, ref.ID)
		}
	}
	if len(ids) == 0 {
		return r, false
	}
	r.Objects = grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: ids}
	return r, true
}

func (c *Compiler) selectorRegions(sel domain.RuleSelector, dotted, typ string, b Binding) ([][]Constraint, error) {
	r, err := selectorRegion(sel.Arm, sel.ResourceNames, sel.MatchLabels)
	if err != nil {
		return nil, err
	}
	if sel.CreatedBySubject {
		// Production creator относится к типизированной SA, а не совпавшему ID
		// человека или группы. Личность получателя остаётся в нормальной форме.
		if b.Recipient.Type != domain.SubjectTypeServiceAccount {
			return nil, fmt.Errorf("creator selector requires service_account recipient")
		}
		r.Creator = grantcoverage.Creator{Kind: grantcoverage.ExactCreator, Subject: b.Recipient}
	}
	scope := b.Scope
	self := Constraint{Type: typ, Region: r, Within: &scope}
	if sel.Container == nil {
		var nonempty bool
		self.Region, nonempty = intersectTarget(r, dotted, b.Target)
		if !nonempty {
			return nil, nil
		}
		return [][]Constraint{{self}}, nil
	}
	container, ok := c.facts.FGAObjectType(sel.Container.Type)
	if !ok {
		return nil, fmt.Errorf("unknown parent type %s", sel.Container.Type)
	}
	cr, err := selectorRegion(sel.Container.Arm, sel.Container.ResourceNames, sel.Container.MatchLabels)
	if err != nil {
		return nil, err
	}
	cr, nonempty := intersectTarget(cr, sel.Container.Type, b.Target)
	if !nonempty {
		return nil, nil
	}
	paths, err := c.parentPaths(typ, container)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no admitted parent path %s -> %s", typ, container)
	}
	var out [][]Constraint
	for _, path := range paths {
		out = append(out, []Constraint{self, {Path: path, Type: container, Region: cr, Within: &scope}})
	}
	return out, nil
}

// Union объединяет только целиком скомпилированные источники одного снимка.
// Незавершённый источник не исчезает рядом с полностью покрывающим соседом.
func Union(sets ...Set) Set {
	var out Set
	for i, s := range sets {
		if i == 0 {
			out.identity = s.identity
		}
		if s.identity != out.identity || s.identity.ModelID == "" {
			out.obligations = append(out.obligations, Obligation{Code: "identity", Detail: "mixed or absent snapshot"})
		}
		out.obligations = append(out.obligations, s.obligations...)
		if s.outputBytes > MaxInputBytes-out.outputBytes {
			out.obligations = append(out.obligations, Obligation{Code: "structural_limit", Detail: "union bytes"})
			continue
		}
		out.outputBytes += s.outputBytes
		if len(s.effects) > MaxEffects-len(out.effects) {
			out.obligations = append(out.obligations, Obligation{Code: "structural_limit", Detail: "union output"})
			continue
		}
		out.effects = append(out.effects, cloneEffects(s.effects)...)
	}
	return out
}

// parentPaths читает declared catalog parents и проверенные моделью указатели.
// Родитель children не обязан участвовать в TTU какого-либо права: structural
// ребро само по себе достаточно, и его нельзя потерять из-за плоских ACL.
func (c *Compiler) parentPaths(from, to string) ([][]authzmodel.EffectHop, error) {
	out, err := c.plans.EffectParentPaths(from, to)
	if err != nil {
		return nil, err
	}
	seenPaths := map[string]bool{}
	for _, path := range out {
		seenPaths[authzmodel.EffectPathKey(path)] = true
	}
	// Замыкание обратного графа удостоверяет только отсутствие пути к типу
	// контейнера. Оно позволяет завершить не относящийся к нему хвост области,
	// но не объявляет найденный короткий путь полным при другой достижимой ветви.
	reverse := map[string][]string{}
	closureSteps := 0
	for typ, hops := range c.parents {
		for _, hop := range hops {
			closureSteps++
			if closureSteps > MaxSteps {
				return nil, fmt.Errorf("structural_limit: parent reachability")
			}
			reverse[hop.To] = append(reverse[hop.To], typ)
		}
	}
	reachesTarget := map[string]bool{to: true}
	queue := []string{to}
	for i := 0; i < len(queue); i++ {
		for _, typ := range reverse[queue[i]] {
			closureSteps++
			if closureSteps > MaxSteps {
				return nil, fmt.Errorf("structural_limit: parent reachability")
			}
			if !reachesTarget[typ] {
				reachesTarget[typ] = true
				queue = append(queue, typ)
			}
		}
	}
	steps := 0
	var walk func(string, []authzmodel.EffectHop, map[string]bool) error
	walk = func(current string, path []authzmodel.EffectHop, seen map[string]bool) error {
		steps++
		if steps > MaxEffects {
			return fmt.Errorf("structural_limit: parent paths")
		}
		if !reachesTarget[current] {
			return nil
		}
		if seen[current] {
			return fmt.Errorf("unsupported_parent_cycle: %s -> %s revisits %s", from, to, current)
		}
		if current == to {
			key := authzmodel.EffectPathKey(path)
			if !seenPaths[key] {
				seenPaths[key] = true
				out = append(out, append([]authzmodel.EffectHop(nil), path...))
			}
			// Совпавший тип не доказывает конец цепи: выше может находиться
			// другой контейнер того же типа, выбранный именем либо метками.
		}
		continues := false
		for _, hop := range c.parents[current] {
			continues = continues || reachesTarget[hop.To]
		}
		if !continues {
			// Лист либо доказанно не ведущий обратно к контейнеру хвост.
			return nil
		}
		if len(path) >= authzplan.MaxPointerDepth {
			return fmt.Errorf("structural_limit: parent path %s -> %s continues beyond depth %d at %s", from, to, authzplan.MaxPointerDepth, current)
		}
		next := map[string]bool{}
		for k, v := range seen {
			next[k] = v
		}
		next[current] = true
		for _, hop := range c.parents[current] {
			if !reachesTarget[hop.To] {
				continue
			}
			if err := walk(hop.To, append(append([]authzmodel.EffectHop(nil), path...), hop), next); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(from, nil, map[string]bool{}); err != nil {
		return nil, err
	}
	return out, nil
}
