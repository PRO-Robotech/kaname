// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
)

// EffectHop сохраняет настоящий указатель модели, а не догадку по имени типа.
type EffectHop struct{ From, Pointer, To string }

// EffectDerivation — один прямой источник принятого плана с полным путём.
// Ограничение строки факта передаёт её производитель отдельно; условие
// объявления не навязывается соседнему безусловному источнику.
type EffectDerivation struct {
	ObjectType, Relation       string
	SourceType, SourceRelation string
	Kind                       authzplan.AtomKind
	Path                       []EffectHop
	Origin                     string
}

// EffectTypes возвращает копию полного перечня объявленных типов.
func (p *Plans) EffectTypes() []string {
	out := p.model.TypeNames()
	sort.Strings(out)
	return out
}

// EffectDerivations восстанавливает путь каждого источника уже принятого Plan.
// Самостоятельного допуска языка здесь нет: неполный Plan останавливает обход.
func (p *Plans) EffectDerivations(typ, relation string) ([]EffectDerivation, error) {
	plan, err := p.Plan(typ, relation)
	if err != nil {
		return nil, err
	}
	var out []EffectDerivation
	steps := 0
	var walk func(string, string, []EffectHop, map[string]bool) error
	walk = func(current, rel string, path []EffectHop, stack map[string]bool) error {
		steps++
		if steps > 65536 || len(path) > authzplan.MaxPointerDepth {
			return fmt.Errorf("предел обхода источников %s.%s", typ, relation)
		}
		key := current + "." + rel
		if stack[key] {
			return nil
		}
		next := make(map[string]bool, len(stack)+1)
		for k, v := range stack {
			next[k] = v
		}
		next[key] = true
		mt := p.model.Type(current)
		if mt == nil || mt.Rel(rel) == nil {
			return fmt.Errorf("источник %s не объявлен", key)
		}
		for _, term := range mt.Rel(rel).Terms {
			switch term.Kind {
			case authzplan.TermComputed:
				if err := walk(current, term.Computed, path, next); err != nil {
					return err
				}
			case authzplan.TermTTU:
				ptr := mt.Rel(term.TTUPointer)
				if ptr == nil {
					return fmt.Errorf("указатель %s.%s отсутствует", current, term.TTUPointer)
				}
				for _, target := range p.model.PointerTargets(ptr) {
					pp := append(append([]EffectHop(nil), path...), EffectHop{current, term.TTUPointer, target})
					if err := walk(target, term.TTURelation, pp, next); err != nil {
						return err
					}
				}
			case authzplan.TermDirect:
				parent := ""
				if len(path) > 0 {
					parent = current
				}
				for _, a := range plan.Atoms {
					if a.Relation == rel && a.ParentType == parent && (a.Kind != authzplan.AtomBinding || len(path) == 0) {
						out = append(out, EffectDerivation{typ, relation, current, rel, a.Kind, append([]EffectHop(nil), path...), a.Origin})
					}
				}
			default:
				return fmt.Errorf("неподдержанный терм %s", key)
			}
		}
		return nil
	}
	if err := walk(typ, relation, nil, map[string]bool{}); err != nil {
		return nil, err
	}
	return out, nil
}

// EffectParentPaths перечисляет только структурные пути, объявленные моделью.
// Они нужны селектору children, чей контейнер может быть дальним предком.
func (p *Plans) EffectParentPaths(from, to string) ([][]EffectHop, error) {
	var out [][]EffectHop
	steps := 0
	var walk func(string, []EffectHop, map[string]bool) error
	walk = func(current string, path []EffectHop, seen map[string]bool) error {
		steps++
		if steps > 65536 {
			return fmt.Errorf("предел обхода путей")
		}
		if current == to {
			out = append(out, append([]EffectHop(nil), path...))
			return nil
		}
		if len(path) >= authzplan.MaxPointerDepth {
			return nil
		}
		if seen[current] {
			return nil
		}
		next := map[string]bool{}
		for k, v := range seen {
			next[k] = v
		}
		next[current] = true
		mt := p.model.Type(current)
		if mt == nil {
			return fmt.Errorf("тип %s не объявлен", current)
		}
		var names []string
		for name := range p.model.Pointers[current] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, target := range p.model.PointerTargets(mt.Rel(name)) {
				pp := append(append([]EffectHop(nil), path...), EffectHop{current, name, target})
				if err := walk(target, pp, next); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if p.model.Type(to) == nil {
		return nil, fmt.Errorf("тип %s не объявлен", to)
	}
	if err := walk(from, nil, map[string]bool{}); err != nil {
		return nil, err
	}
	// Порядок не зависит от обхода карт модели.
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out, nil
}

// EffectDirectAccepts проверяет форму прямого факта, включая имя условия.
func (p *Plans) EffectDirectAccepts(typ, rel, subjectType, userset, condition string) bool {
	mt := p.model.Type(typ)
	if mt == nil || mt.Rel(rel) == nil {
		return false
	}
	for _, term := range mt.Rel(rel).Terms {
		if term.Kind != authzplan.TermDirect {
			continue
		}
		for _, s := range term.Direct {
			if !s.Wildcard && s.Object == "" && s.Type == subjectType && s.Userset == userset && s.Condition == condition {
				return true
			}
		}
	}
	return false
}

// EffectPathKey — однозначная координата пути для канонизации ограничений.
func EffectPathKey(path []EffectHop) string {
	var b strings.Builder
	for _, h := range path {
		for _, s := range []string{h.From, h.Pointer, h.To} {
			fmt.Fprintf(&b, "%d:%s", len(s), s)
		}
	}
	return b.String()
}
