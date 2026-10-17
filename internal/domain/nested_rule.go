// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// nested_rule.go — вложенное правило роли (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2).
//
// # Что это
//
// Правило над типом-контейнером несёт перечень `Children` — правила над типами,
// лежащими под ним. Вложенное правило действует на объекты СВОЕГО типа, у
// которых среди предков (цепь регистрации, любая глубина) есть контейнер,
// ВЫБРАННЫЙ выдачей: контейнер проходит отбор правила-владельца (якорь, имена,
// метки) и входит в цель выдачи — назван элементом цели либо цель «вся
// область». Правило верхнего уровня сравнивает точно, как прежде.
//
// # Форма плоская: один уровень
//
// Правило-владелец называет РОВНО ОДИН ресурс и не `*`: вложенное правило
// адресует потомков ОДНОГО типа-контейнера, и «потомки любого из двух» было бы
// вторым смыслом. У вложенного правила модуль пуст — он берётся у
// правила-владельца, — и своих `Children` нет: глубину выражает ТИП (он лежит
// под контейнером на любой глубине по объявленным `parents`), а не структура
// роли. Родство по `parents` судит загрузчик манифеста — у домена каталога нет;
// здесь — форма, которая от каталога не зависит.
//
// # Чем это НЕ является
//
// Вложенное правило не компилируется в права (`CompileRules`): строка
// `registry.repositories.*.get` обещала бы чтение всех репозиториев области
// (Р4). И оно не покрывает цель (`CoversType` читает верхний уровень, ND-12):
// оно действует на потомков названного контейнера, а не на названный объект
// своего типа.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"go.uber.org/multierr"
)

// maxChildren — вложенных правил у одного правила-владельца. Та же граница, что у
// перечней ресурсов и глаголов правила: вложенное правило называет тип, и типов
// под одним контейнером не бывает больше, чем ресурсов у правила.
const maxChildren = maxRuleElems

// Тексты отказа ворот класса (Р5, ND-05) — контракт тона, дословно приёмочные.
//
// NestedRuleNotWholeText — вложенное правило не читает тип-ребёнок целиком: даёт
// не ровно `get` и `list` либо сужено именами или метками.
func NestedRuleNotWholeText(role RoleID, childType string) string {
	return fmt.Sprintf("Role %s nests a rule over %s that does not read it whole "+
		"(get and list, without resourceNames or matchLabels); a system class reads children only whole",
		role, childType)
}

// NestedRuleBeyondDirectChildText — вложенное правило называет не ПРЯМОГО ребёнка
// контейнера: `public_reader from <указатель>` до внука не доходит.
func NestedRuleBeyondDirectChildText(containerType string, role RoleID, nestedType string) string {
	return fmt.Sprintf("Type %s passes public read to its direct children only; role %s nests a rule over %s",
		containerType, role, nestedType)
}

// OwnerType — точечный тип правила-владельца (`<модуль>.<ресурс>`); пусто у
// правила, которое владельцем быть не может (не ровно один ресурс либо `*`).
func (r Rule) OwnerType() string {
	if r.Module == "" || r.Module == wildcard || len(r.Resources) != 1 || r.Resources[0] == wildcard {
		return ""
	}
	return r.Module + "." + r.Resources[0]
}

// EffectiveChildren — вложенные правила с модулем правила-владельца, как их
// читают проекции (селекторы, сегменты, «только чтение»). Хранимая и
// контрактная форма модуля у вложенного правила не несёт.
func (r Rule) EffectiveChildren() []Rule {
	if len(r.Children) == 0 {
		return nil
	}
	out := make([]Rule, 0, len(r.Children))
	for _, c := range r.Children {
		eff := c
		eff.Module = r.Module
		eff.Children = nil
		out = append(out, eff)
	}
	return out
}

// HasChildren — у роли есть хотя бы одно вложенное правило.
func (rs Rules) HasChildren() bool {
	for _, r := range rs {
		if len(r.Children) > 0 {
			return true
		}
	}
	return false
}

// nestedFingerprint — ключ селектора вложенного правила: отпечаток владельца и
// отпечаток вложенного вместе. Один отпечаток вложенного не годится — одно и то
// же вложенное правило под двумя владельцами дало бы два селектора с одним
// ключом, а ключ — первичный ключ селекторов роли и координата члена
// материализации.
func nestedFingerprint(owner, child Rule) string {
	h := sha256.New()
	_, _ = h.Write([]byte("nested\x00"))
	_, _ = h.Write([]byte(owner.Fingerprint()))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(child.Fingerprint()))
	return hex.EncodeToString(h.Sum(nil))
}

// writeChildren — секция вложенных правил в отпечатке владельца. У правила без
// вложенных секции НЕТ вовсе: на прежнем отпечатке стоят хранимые селекторы и
// члены материализации, и он обязан не сдвинуться (ND-07 (а)).
func writeChildren(h interface{ Write([]byte) (int, error) }, children []Rule) {
	if len(children) == 0 {
		return
	}
	fps := make([]string, 0, len(children))
	for _, c := range children {
		fps = append(fps, c.Fingerprint())
	}
	sort.Strings(fps)
	writeSortedList(h, "c", fps)
}

// containerOf — отбор правила-владельца в форме контейнера вложенного селектора.
func containerOf(owner Rule) *ContainerSelector {
	c := &ContainerSelector{Type: owner.OwnerType(), OwnerFP: owner.Fingerprint(), Arm: owner.Arm()}
	switch c.Arm {
	case ArmNames:
		c.ResourceNames = append([]string(nil), owner.ResourceNames...)
	case ArmLabels:
		c.MatchLabels = make(map[string]string, len(owner.MatchLabels))
		for k, v := range owner.MatchLabels {
			c.MatchLabels[k] = v
		}
	}
	return c
}

// nestedSelectors — селекторы вложенных правил одного владельца.
func nestedSelectors(owner Rule) []RuleSelector {
	if len(owner.Children) == 0 || owner.OwnerType() == "" {
		return nil
	}
	out := make([]RuleSelector, 0, len(owner.Children))
	for i, child := range owner.EffectiveChildren() {
		sel := RuleSelector{
			RuleFP:      nestedFingerprint(owner, owner.Children[i]),
			Arm:         child.Arm(),
			ObjectTypes: dottedTypes(child, false),
			Verbs:       append([]string(nil), child.Verbs...),
			Container:   containerOf(owner),
		}
		switch child.Arm() {
		case ArmNames:
			sel.ResourceNames = append([]string(nil), child.ResourceNames...)
		case ArmLabels:
			sel.MatchLabels = make(map[string]string, len(child.MatchLabels))
			for k, v := range child.MatchLabels {
				sel.MatchLabels[k] = v
			}
		}
		out = append(out, sel)
	}
	return out
}

// validateChildren — форма вложенности (Р1). Ничего не делает у правила без
// ключа: `Children == nil` — «вложенных нет».
func (r Rule) validateChildren(policy RulePolicy, modules ModuleSet) error {
	if r.Children == nil {
		return nil
	}
	if len(r.Children) == 0 {
		return fmt.Errorf("Illegal argument children (must be non-empty when set)")
	}
	var errs error
	if len(r.Children) > maxChildren {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument children (cardinality must be <=%d)", maxChildren))
	}
	if r.OwnerType() == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"Illegal argument children (an owner rule names exactly one resource, not a wildcard)"))
	}
	for _, c := range r.Children {
		if c.Module != "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument children (a nested rule takes the module of its owner)"))
		}
		if c.Children != nil {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument children (a nested rule has no children of its own)"))
		}
		for _, res := range c.Resources {
			if res == wildcard {
				errs = multierr.Append(errs, fmt.Errorf(
					"Illegal argument children (a nested rule names a type, not a wildcard)"))
			}
			if len(r.Resources) == 1 && res == r.Resources[0] {
				errs = multierr.Append(errs, fmt.Errorf(
					"Illegal argument children (a type is not its own descendant)"))
			}
		}
		eff := c
		eff.Module = r.Module
		eff.Children = nil
		errs = multierr.Append(errs, eff.Validate(policy, modules))
	}
	return errs
}

// readsExactly — вложенное правило читает тип целиком и только читает: якорь,
// глаголы — РОВНО `get` и `list` (Р5 п. 2–3). Строже [readsWhole]: тот
// допускает лишние глаголы, а здесь лишний глагол — второе право сверх
// `public_reader`, которого роль классу не называет.
func readsExactly(arm Arm, verbs []string) bool {
	if !readsWhole(arm, verbs) {
		return false
	}
	for _, v := range verbs {
		if !IsClassReadVerb(v) {
			return false
		}
	}
	return true
}

// PublicReadsChildOf — селектор вложенного правила под контейнером
// `containerType`, читающий ЦЕЛИКОМ одного из его прямых детей `children`. Им
// судит разворачивание выдачи классу, писать ли `public_reader` (ND-03).
// Правило верхнего уровня (прежняя форма) `public_reader` не пишет (ND-07 (б)).
func (s RuleSelector) PublicReadsChildOf(containerType string, children []string) bool {
	if s.Container == nil || s.Container.Type != containerType || !readsExactly(s.Arm, s.Verbs) {
		return false
	}
	for _, t := range s.ObjectTypes {
		for _, c := range children {
			if t == c {
				return true
			}
		}
	}
	return false
}

// ClassNestedRuleRefusal — ворота выдачи СИСТЕМНОМУ КЛАССУ роли с вложенными
// правилами (Р5, ND-05). Судится КАЖДОЕ вложенное правило роли:
//
//  1. контейнер объявлен (`publicReadToChildren`), иначе — текст SC-65 соседа;
//  2. тип вложенного правила — ПРЯМОЙ ребёнок контейнера, иначе — до внука
//     `public_reader` не доходит;
//  3. правило даёт ровно `get` и `list` и не сужено.
//
// Первое невыполненное условие — отказ с его текстом. Роль без вложенных
// воротам безразлична. `containers` — что живой каталог говорит о типах-
// владельцах; тип, о котором не сказано, читается необъявленным.
func ClassNestedRuleRefusal(role RoleID, rules Rules, containers map[string]PublicReadContainer) (string, bool) {
	for _, owner := range rules {
		if len(owner.Children) == 0 {
			continue
		}
		ownerType := owner.OwnerType()
		c := containers[ownerType]
		for _, child := range owner.EffectiveChildren() {
			for _, res := range child.Resources {
				nested := child.Module + "." + res
				switch {
				case !c.Declared:
					return UndeclaredContainerText(ownerType, role, nested), true
				case !containsString(c.ChildTypes, nested):
					return NestedRuleBeyondDirectChildText(ownerType, role, nested), true
				case !readsExactly(child.Arm(), child.Verbs):
					return NestedRuleNotWholeText(role, nested), true
				}
			}
		}
	}
	return "", false
}

// containsString — принадлежность малому перечню.
func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
