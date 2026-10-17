// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// rolechildren.go — судья формы вложенного правила роли (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, Р1, ND-04 (а)–(е)).
//
// Правило над типом-контейнером несёт `children` — правила над типами, лежащими
// под ним по объявленным `parents` ресурсов ЭТОГО манифеста, на любой глубине.
// Загрузчик принимает ключ, только если:
//
//  1. правило-владелец называет РОВНО ОДИН ресурс, и это не `*`;
//  2. ресурс владельца — не ярус иерархии: под ярусом выбирает ОБЛАСТЬ выдачи;
//  3. тип каждого вложенного правила — потомок типа владельца по `parents`;
//     сам себе тип потомком не является;
//  4. у вложенного правила нет `module` (оно берёт модуль владельца) и своих
//     `children` — глубину выражает тип, а не структура роли;
//  5. `children` либо отсутствует, либо непуст.
//
// # Почему пункт 4 судится по СЫРОМУ узлу
//
// Вложенное правило — свой тип [ChildRule] без полей `module` и `children`:
// рекурсивный тип сделал бы бесконечным обход полей структур, на котором стоит
// согласие схемы и структур (MOD-MF-21), а схема у вложенного правила этих
// ключей не объявляет. Строгий разбор (`KnownFields`) отверг бы такой ключ
// общим «неизвестное поле», не назвав, ЧТО не так с вложенностью. Поэтому оба
// ключа ищутся в узле документа ДО типизированного разбора, и находка несёт
// координату и причину.

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ErrRoleRuleNestingMalformed — вложенность правила роли не той формы.
var ErrRoleRuleNestingMalformed = errors.New("manifest: role rule nesting is malformed")

// tierObjectTypes — типы модели, являющиеся ярусами иерархии: под ними выбирает
// область выдачи, а не вложенное правило.
var tierObjectTypes = map[string]bool{"cluster": true, "account": true, "project": true}

// ChildRule — вложенное правило роли манифеста (kaname#874). Те же ключи права,
// что у [Rule], без `module` (берётся у владельца) и без `children` (глубину
// выражает тип).
type ChildRule struct {
	Resources     []string          `yaml:"resources"`
	Classes       []string          `yaml:"classes"`
	Verbs         []string          `yaml:"verbs"`
	ResourceNames []string          `yaml:"resourceNames"`
	MatchLabels   map[string]string `yaml:"matchLabels"`
}

// Right — запись права вложенного правила и её форма (см. [Rule.Right]).
func (c ChildRule) Right() (values []string, named bool) {
	if len(c.Verbs) > 0 {
		return c.Verbs, true
	}
	return c.Classes, false
}

// DomainRule — вложенное правило в форме домена: модуль пуст, `classes` — глаголы
// (как у [Rule.DomainRule]).
func (c ChildRule) DomainRule() domain.Rule {
	return domain.Rule{
		Resources:     c.Resources,
		Verbs:         c.Classes,
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

// formRule — вложенное правило с записью права любой из двух форм (для судьи
// домена).
func (c ChildRule) formRule() domain.Rule {
	values, _ := c.Right()
	return domain.Rule{
		Resources:     c.Resources,
		Verbs:         values,
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

// domainChildren — вложенные правила в форме домена; nil — ключа нет.
func domainChildren(children []ChildRule, form bool) []domain.Rule {
	if children == nil {
		return nil
	}
	out := make([]domain.Rule, 0, len(children))
	for _, c := range children {
		if form {
			out = append(out, c.formRule())
		} else {
			out = append(out, c.DomainRule())
		}
	}
	return out
}

// refuseNestedChildKeys — пункт 4: `module` и `children` у вложенного правила,
// по сырому узлу документа (почему не по разобранному — шапка файла).
func refuseNestedChildKeys(doc *yaml.Node) error {
	var faults []error
	roles := mapValue(doc, "roles")
	if roles == nil || roles.Kind != yaml.SequenceNode {
		return nil
	}
	for i, role := range roles.Content {
		rules := mapValue(role, "rules")
		if rules == nil || rules.Kind != yaml.SequenceNode {
			continue
		}
		for j, rule := range rules.Content {
			children := mapValue(rule, "children")
			if children == nil || children.Kind != yaml.SequenceNode {
				continue
			}
			for k, child := range children.Content {
				if mapValue(child, "module") != nil {
					faults = append(faults, linkFault{
						kind:  ErrRoleRuleNestingMalformed,
						coord: locate(doc, "roles", i, "rules", j, "children", k, "module"),
						detail: fmt.Sprintf("roles[%d].rules[%d].children[%d].module: "+
							"вложенное правило берёт модуль правила-владельца", i, j, k),
					})
				}
				if mapValue(child, "children") != nil {
					faults = append(faults, linkFault{
						kind:  ErrRoleRuleNestingMalformed,
						coord: locate(doc, "roles", i, "rules", j, "children", k, "children"),
						detail: fmt.Sprintf("roles[%d].rules[%d].children[%d].children: "+
							"у вложенного правила своих children нет; более глубокий тип "+
							"называется прямо под правилом-владельцем", i, j, k),
					})
				}
			}
		}
	}
	if len(faults) > 0 {
		return errors.Join(faults...)
	}
	return nil
}

// validateRuleChildren — пункты 1, 2, 3 и 5 по разобранному правилу.
func validateRuleChildren(m *Manifest, rule Rule, doc *yaml.Node, i, j int) []error {
	if rule.Children == nil {
		return nil
	}
	fault := func(detail string, steps ...any) linkFault {
		return linkFault{
			kind:   ErrRoleRuleNestingMalformed,
			coord:  locate(doc, append([]any{"roles", i, "rules", j}, steps...)...),
			detail: detail,
		}
	}
	if len(rule.Children) == 0 {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].children: пустой перечень; "+
			"правило без вложенных пишется без ключа", i, j), "children")}
	}
	if len(rule.Resources) != 1 {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: правило с children "+
			"называет ровно один ресурс, получено %d", i, j, len(rule.Resources)), "resources")}
	}
	owner := rule.Resources[0]
	if owner == "*" {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: правило с children "+
			"называет ресурс, а не «*»", i, j), "resources")}
	}
	byName := resourcesByName(m)
	if r, ok := byName[owner]; ok && tierObjectTypes[r.ObjectType] {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: %q — ярус иерархии; "+
			"под ярусом выбирает область выдачи, children у него нет", i, j, owner), "resources")}
	}

	var faults []error
	for k, child := range rule.Children {
		if formFaults := validateChildRightForm(child, doc, i, j, k); len(formFaults) > 0 {
			faults = append(faults, formFaults...)
			continue
		}
		for _, res := range child.Resources {
			if res == "*" || !descendsFrom(byName, res, owner) {
				faults = append(faults, fault(fmt.Sprintf("roles[%d].rules[%d].children[%d].resources: "+
					"тип %q не лежит под %q ни по одному объявленному указателю parents; "+
					"вложенное правило действует только на потомков типа правила-владельца",
					i, j, k, rule.Module+"."+res, rule.Module+"."+owner), "children", k, "resources"))
			}
		}
	}
	return faults
}

// validateChildRightForm — две записи права у вложенного правила рядом не
// стоят (то же, что [validateRuleRightForm] у правила верхнего уровня).
func validateChildRightForm(child ChildRule, doc *yaml.Node, i, j, k int) []error {
	if len(child.Classes) == 0 || len(child.Verbs) == 0 {
		return nil
	}
	return []error{linkFault{
		kind:  ErrRoleRuleRightFormsCollide,
		coord: locate(doc, "roles", i, "rules", j, "children", k),
		detail: fmt.Sprintf("roles[%d].rules[%d].children[%d]: право записано ОБЕИМИ формами "+
			"сразу — и `classes`, и `verbs`. Формы взаимоисключающи: оставьте ОДНУ", i, j, k),
	}}
}

// resourcesByName — ресурсы манифеста по имени.
func resourcesByName(m *Manifest) map[string]Resource {
	out := make(map[string]Resource, len(m.Resources))
	for _, r := range m.Resources {
		out[r.Name] = r
	}
	return out
}

// descendsFrom — ресурс `child` лежит под ресурсом `owner` по объявленным
// `parents` этого манифеста на любой глубине. Сам себе ресурс потомком не
// является. Обход — по типам модели, на которые указывают указатели; цикл
// указателей (его судит раздел `resources`) обход не зацикливает.
func descendsFrom(byName map[string]Resource, child, owner string) bool {
	o, ok := byName[owner]
	if !ok || child == owner {
		return false
	}
	byType := make(map[string]Resource, len(byName))
	for _, r := range byName {
		byType[r.ObjectType] = r
	}
	start, ok := byName[child]
	if !ok {
		return false
	}
	seen := map[string]bool{start.ObjectType: true}
	queue := []Resource{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, p := range cur.Parents {
			if p.Type == o.ObjectType {
				return true
			}
			if seen[p.Type] {
				continue
			}
			seen[p.Type] = true
			if next, ok := byType[p.Type]; ok {
				queue = append(queue, next)
			}
		}
	}
	return false
}
