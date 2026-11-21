// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// GrantCapabilityKind отличает управление выдачами от использования ресурса.
// Эти действия не становятся правами управления из-за расширения обычного '*'.
type GrantCapabilityKind string

const (
	GrantCapabilityCreateBinding GrantCapabilityKind = "create_binding"
	GrantCapabilityBindRole      GrantCapabilityKind = "bind_role"
)

// GrantCapabilityRule — проекция одного авторского правила управляющей роли.
// Область и получатели поступают из действующей выдачи этой роли, а не из её
// definitionTier. RuleFP не содержит позиции правила: порядок и дубликаты
// одинаковых правил не меняют множество полномочий.
type GrantCapabilityRule struct {
	RuleFP      string
	Kind        GrantCapabilityKind
	BoundRoleID RoleID
}

// SplitGrantCapabilityRules отделяет явные управляющие пары от обычных прав.
// Остаток сохраняет декартово произведение resources × verbs, кроме извлечённых
// пар. Символический '*' остаётся символическим; потребитель обычных правил
// обязан разворачивать только leaf-глаголы, а не добавлять управляющие действия.
// Общая проверка формы/каталога Rules.Validate остаётся обязанностью вызывающего.
// Функция дополнительно проверяет ограничения нового управляющего синтаксиса.
func SplitGrantCapabilityRules(rules Rules) (Rules, []GrantCapabilityRule, error) {
	var ordinary Rules
	var capabilities []GrantCapabilityRule
	seen := make(map[GrantCapabilityRule]struct{})
	for i, r := range rules {
		create, bind := grantCapabilityPairs(r)
		if err := validateGrantCapabilityRule(r, i, create, bind); err != nil {
			return nil, nil, err
		}
		if !create && !bind {
			ordinary = append(ordinary, cloneGrantRule(r))
			continue
		}
		projected, err := projectGrantCapabilityRule(r, create, bind)
		if err != nil {
			return nil, nil, err
		}
		for _, capability := range projected {
			if _, exists := seen[capability]; !exists {
				seen[capability] = struct{}{}
				capabilities = append(capabilities, capability)
			}
		}
		ordinary = append(ordinary, ordinaryGrantRuleResidual(r, create, bind)...)
	}
	return ordinary, capabilities, nil
}

func grantCapabilityPairs(r Rule) (create, bind bool) {
	if r.Module != "iam" {
		return false, false
	}
	return slices.Contains(r.Resources, "accessBinding") && hasAuthoredVerb(r.Verbs, "create"),
		slices.Contains(r.Resources, "role") && hasAuthoredVerb(r.Verbs, "bind")
}

func validateGrantCapabilityRule(r Rule, index int, create, bind bool) error {
	if nestedGrantCapability(r, r.Module) {
		return fmt.Errorf("Illegal argument rules[%d].children (grant capabilities must be top-level rules)", index)
	}
	if !create && !bind {
		return nil
	}
	if len(r.Children) != 0 || r.CreatedBySubject || len(r.MatchLabels) != 0 {
		return fmt.Errorf("Illegal argument rules[%d] (grant capabilities do not accept children, matchLabels or createdBySubject)", index)
	}
	if create && len(r.ResourceNames) != 0 {
		return fmt.Errorf("Illegal argument rules[%d].resourceNames (accessBinding create requires the whole scope)", index)
	}
	if bind {
		if len(r.ResourceNames) == 0 {
			return fmt.Errorf("Illegal argument rules[%d].resourceNames (role bind requires explicit role IDs)", index)
		}
		for _, id := range r.ResourceNames {
			if id == "" || id == "*" {
				return fmt.Errorf("Illegal argument rules[%d].resourceNames (role bind requires explicit role IDs)", index)
			}
		}
	}
	return nil
}

func projectGrantCapabilityRule(r Rule, create, bind bool) ([]GrantCapabilityRule, error) {
	fp, err := grantRuleFingerprint(r)
	if err != nil {
		return nil, err
	}
	var result []GrantCapabilityRule
	if create {
		result = append(result, GrantCapabilityRule{RuleFP: fp, Kind: GrantCapabilityCreateBinding})
	}
	if bind {
		for _, id := range r.ResourceNames {
			// Идентификатор — ссылка на роль. resource_mirror не удостоверяет её.
			result = append(result, GrantCapabilityRule{RuleFP: fp, Kind: GrantCapabilityBindRole, BoundRoleID: RoleID(id)})
		}
	}
	return result, nil
}

// Группировка сохраняет исходные селекторы у каждого остатка. Нельзя удалить
// глагол целиком: create другого ресурса остаётся обычным правом.
func ordinaryGrantRuleResidual(r Rule, create, bind bool) Rules {
	groups := make(map[string]int)
	var residual Rules
	for _, resource := range r.Resources {
		verbs := ordinaryGrantVerbs(r.Verbs, resource, create, bind)
		if len(verbs) == 0 {
			continue
		}
		key := strings.Join(verbs, "\x00")
		if index, exists := groups[key]; exists {
			residual[index].Resources = append(residual[index].Resources, resource)
		} else {
			groups[key] = len(residual)
			copy := cloneGrantRule(r)
			copy.Resources, copy.Verbs = []string{resource}, verbs
			residual = append(residual, copy)
		}
	}
	return residual
}

func ordinaryGrantVerbs(authored []string, resource string, create, bind bool) []string {
	var verbs []string
	for _, verb := range authored {
		v := NormalizeVerb(verb)
		if (create && resource == "accessBinding" && v == "create") || (bind && resource == "role" && v == "bind") {
			continue
		}
		verbs = append(verbs, verb)
	}
	return verbs
}

// ValidateGrantCapabilityTarget проверяет носитель целиком: управляющая роль
// не становится обычной объектной выдачей от добавления ещё одного leaf-правила.
func ValidateGrantCapabilityTarget(rules Rules, target AccessTarget) error {
	_, capabilities, err := SplitGrantCapabilityRules(rules)
	if err != nil {
		return err
	}
	if len(capabilities) != 0 && (!target.AllInScope || len(target.Resources) != 0) {
		return fmt.Errorf("Illegal argument target (grant capability roles require allInScope)")
	}
	return nil
}

func hasAuthoredVerb(verbs []string, want string) bool {
	for _, v := range verbs {
		if NormalizeVerb(v) == want {
			return true
		}
	}
	return false
}

func nestedGrantCapability(r Rule, inheritedModule string) bool {
	for _, child := range r.Children {
		module := child.Module
		if module == "" {
			module = inheritedModule
		}
		if module == "iam" && (slices.Contains(child.Resources, "accessBinding") && hasAuthoredVerb(child.Verbs, "create") ||
			slices.Contains(child.Resources, "role") && hasAuthoredVerb(child.Verbs, "bind")) || nestedGrantCapability(child, module) {
			return true
		}
	}
	return false
}

func cloneGrantRule(r Rule) Rule {
	r.Resources = slices.Clone(r.Resources)
	r.Verbs = slices.Clone(r.Verbs)
	r.ResourceNames = slices.Clone(r.ResourceNames)
	if r.MatchLabels != nil {
		labels := make(map[string]string, len(r.MatchLabels))
		for k, v := range r.MatchLabels {
			labels[k] = v
		}
		r.MatchLabels = labels
	}
	if r.Children != nil {
		children := make([]Rule, len(r.Children))
		for i, child := range r.Children {
			children[i] = cloneGrantRule(child)
		}
		r.Children = children
	}
	return r
}

func grantRuleFingerprint(r Rule) (string, error) {
	r = cloneGrantRule(r)
	r.Resources = canonicalGrantSet(r.Resources, false)
	r.Verbs = canonicalGrantSet(r.Verbs, true)
	r.ResourceNames = canonicalGrantSet(r.ResourceNames, false)
	if len(r.MatchLabels) == 0 {
		r.MatchLabels = nil
	}
	if len(r.Children) == 0 {
		r.Children = nil
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("grant capability rule fingerprint: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalGrantSet(values []string, normalizeVerb bool) []string {
	if len(values) == 0 {
		return nil
	}
	result := slices.Clone(values)
	if normalizeVerb {
		for i, value := range result {
			result[i] = NormalizeVerb(value)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}
