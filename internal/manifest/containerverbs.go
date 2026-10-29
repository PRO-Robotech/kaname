// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// containerverbs.go — КОНТЕЙНЕРНОЕ ДЕЙСТВИЕ ресурса и СЕЛЕКТОР СОЗДАТЕЛЯ правила
// роли (задача PRO-Robotech/kaname#1003; приёмка
// docs/engineering/acceptance/service-account-creation-is-its-own-right.md, Р2а,
// сценарий SAC-42).
//
// # Что это и зачем третий механизм
//
// Право роли до сих пор выражалось двумя механизмами: поимённым действием
// ресурса (`verbs:`) и классом (`classes:`, включая подстановку `*`). Оба пишут
// кортежи на объекте ТИПА ресурса. «Создать учётку в аккаунте» — действие, которое
// авторизуется отношением на РОДИТЕЛЕ: учётки ещё нет, и спросить право можно только
// у аккаунта. Сделать его глаголом типа нельзя: подстановка `*` разворачивается в
// набор глаголов типа, и `iam.service_account.admin` (`classes: ["*"]`) молча
// получил бы право создавать учётки, а генератор модели вывел бы `v_create` на
// учётке вопреки шапке модели.
//
// Контейнерное действие объявляется ресурсом отдельно от `verbs`:
//
//	- name: serviceAccount
//	  parents: [account]
//	  containerVerbs:
//	    - {name: create, parent: account, relation: service_account_creator}
//
// и читается так: правило роли, ПОИМЁННО назвавшее `create` над `serviceAccount`,
// даёт субъекту выдачи отношение `service_account_creator` на объекте-родителе
// `account` — области выдачи. В набор глаголов типа действие не входит, классом
// и подстановкой оно не достигается, кортежа на объекте типа не пишет.
//
// # Где судится форма
//
// Здесь — всё, что манифест-внутреннее: указатель `parent` объявлен ресурсом,
// тип родителя объявлен ЭТИМ ЖЕ манифестом, отношение объявлено в его
// `relations` и не несёт приставки `v_`. Вид субъекта отношения спрашивается у
// МОДЕЛИ, как у выдачи отношением (relationgrant.go, «Допустимый вид получателя
// спрашивается У МОДЕЛИ»): оракул внесён — судится, не внесён — не утверждается
// ничего (relationoracle.go, «Чего отсутствие оракула НЕ означает»).
//
// Правило роли судится в `validateRuleContainerForm`: класс, названный именем
// контейнерного действия, — отказ (действие достигается только поимённо);
// селектор создателя — только в правиле над ресурсом с контейнерным действием
// `create` и без `resourceNames`/`matchLabels`.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// creatorContainerVerb — имя контейнерного действия, к которому привязан
// селектор создателя: «созданные субъектом» имеет смысл только у ресурса,
// который субъект вправе создавать.
const creatorContainerVerb = "create"

// creatorSubjectKind — вид субъекта, которому отношение контейнерного действия
// обязано выдаваться прямо (Р2а: роль создателя выдаётся только учётке), в
// написании манифеста.
const creatorSubjectKind = "serviceAccount"

var (
	// ErrContainerVerbNameRequired — контейнерное действие не назвало себя.
	ErrContainerVerbNameRequired = errors.New("manifest: container verb name is required")
	// ErrContainerVerbCollidesWithVerb — имя контейнерного действия совпадает с
	// действием типа или с другим контейнерным действием того же ресурса: одно имя
	// называло бы два права, и какое из них даёт правило, решал бы порядок чтения.
	ErrContainerVerbCollidesWithVerb = errors.New("manifest: container verb name collides with a verb of the resource")
	// ErrContainerVerbParentUnknown — `parent` не назван среди `parents` ресурса.
	ErrContainerVerbParentUnknown = errors.New("manifest: container verb parent is not a parent of the resource")
	// ErrContainerVerbParentForeign — тип родителя не объявлен этим манифестом:
	// отношение на нём принадлежит чужому блоку модели, и объявить его здесь нечем.
	ErrContainerVerbParentForeign = errors.New("manifest: container verb parent type is not declared by this manifest")
	// ErrContainerVerbRelationUndeclared — отношение не объявлено в `relations`
	// ресурса-родителя.
	ErrContainerVerbRelationUndeclared = errors.New("manifest: container verb relation is not declared by the parent resource")
	// ErrContainerVerbRelationVerbPrefix — имя отношения несёт приставку `v_`:
	// приставка объявляет глагол объекта, а контейнерное действие глаголом типа не
	// является и подстановкой не раздаётся.
	ErrContainerVerbRelationVerbPrefix = errors.New("manifest: container verb relation carries the verb prefix v_")
	// ErrContainerVerbRelationSubject — модель не выдаёт отношение учётке прямо.
	ErrContainerVerbRelationSubject = errors.New("manifest: container verb relation does not accept a service account directly")
	// ErrRoleRuleClassIsContainerVerb — класс назван именем контейнерного
	// действия: оно достигается только поимённо (`verbs:`).
	ErrRoleRuleClassIsContainerVerb = errors.New("manifest: role rule names a container verb as a class")
	// ErrRuleCreatorSelectorWithoutContainer — селектор создателя у правила над
	// ресурсом, не объявившим контейнерное действие `create`.
	ErrRuleCreatorSelectorWithoutContainer = errors.New("manifest: createdBySubject on a resource without the container verb create")
	// ErrRuleCreatorSelectorWithSelector — селектор создателя рядом с
	// `resourceNames` или `matchLabels`: селекторы у правила взаимоисключающи.
	ErrRuleCreatorSelectorWithSelector = errors.New("manifest: createdBySubject combined with resourceNames or matchLabels")
	// ErrRuleCreatorSelectorFalse — ключ записан со значением `false`: второй способ
	// сказать «селектора нет».
	ErrRuleCreatorSelectorFalse = errors.New("manifest: createdBySubject written as false")
)

// ContainerVerb — контейнерное действие ресурса (kaname#1003, Р2а).
type ContainerVerb struct {
	// Name — имя действия, которым его называет правило роли (`create`).
	Name string `yaml:"name"`
	// Parent — ИМЯ указателя этого ресурса (`parents`), на объекте которого лежит
	// отношение.
	Parent string `yaml:"parent"`
	// Relation — отношение на родителе, которое действие даёт.
	Relation string `yaml:"relation"`
}

// ParentTypeOf — тип модели родителя контейнерного действия по указателю
// ресурса; пусто, если указателя с таким именем нет.
func (r Resource) ParentTypeOf(cv ContainerVerb) string {
	for _, p := range r.Parents {
		if p.Name == cv.Parent {
			return p.Type
		}
	}
	return ""
}

// ContainerVerbNamed — контейнерное действие ресурса по имени.
func (r Resource) ContainerVerbNamed(name string) (ContainerVerb, bool) {
	for _, cv := range r.ContainerVerbs {
		if cv.Name == name {
			return cv, true
		}
	}
	return ContainerVerb{}, false
}

// validateContainerVerbs — форма раздела `containerVerbs` каждого ресурса.
// Находки собираются ВСЕ.
func validateContainerVerbs(m *Manifest, doc *yaml.Node, oracle RelationOracle) []error {
	var faults []error
	for i := range m.Resources {
		r := &m.Resources[i]
		seen := map[string]bool{}
		for _, v := range r.Verbs {
			seen[v.Name] = true
		}
		for k, cv := range r.ContainerVerbs {
			at := func(key string) docCoord { return locate(doc, "resources", i, "containerVerbs", k, key) }
			label := fmt.Sprintf("resources[%d].containerVerbs[%d]", i, k)
			if strings.TrimSpace(cv.Name) == "" {
				faults = append(faults, linkFault{kind: ErrContainerVerbNameRequired, coord: at("name"),
					detail: label + ": контейнерное действие без имени правило роли назвать не может"})
				continue
			}
			if seen[cv.Name] {
				faults = append(faults, linkFault{kind: ErrContainerVerbCollidesWithVerb, coord: at("name"),
					detail: fmt.Sprintf("%s: имя %q у ресурса %q уже называет действие — одно имя называло бы "+
						"два права", label, cv.Name, r.Name)})
				continue
			}
			seen[cv.Name] = true
			faults = append(faults, validateContainerRelation(m, r, cv, label, at, oracle)...)
		}
	}
	return faults
}

// validateContainerRelation — родитель и отношение одного контейнерного действия.
func validateContainerRelation(m *Manifest, r *Resource, cv ContainerVerb, label string,
	at func(string) docCoord, oracle RelationOracle) []error {
	parentType := r.ParentTypeOf(cv)
	if parentType == "" {
		names := make([]string, 0, len(r.Parents))
		for _, p := range r.Parents {
			names = append(names, p.Name)
		}
		return []error{linkFault{kind: ErrContainerVerbParentUnknown, coord: at("parent"),
			detail: fmt.Sprintf("%s: %q не родитель ресурса %q — указатели ресурса: %s; право на объекте, "+
				"которого блок модели ресурса не несёт, создать в нём ничего не даёт",
				label, cv.Parent, r.Name, strings.Join(names, ", "))}}
	}
	var parent *Resource
	for j := range m.Resources {
		if m.Resources[j].ObjectType == parentType {
			parent = &m.Resources[j]
		}
	}
	if parent == nil {
		return []error{linkFault{kind: ErrContainerVerbParentForeign, coord: at("parent"),
			detail: fmt.Sprintf("%s: тип родителя %q (указатель %q ресурса %q) этим манифестом не объявлен — "+
				"отношение на нём принадлежит чужому блоку модели", label, parentType, cv.Parent, r.Name)}}
	}
	if strings.HasPrefix(cv.Relation, "v_") {
		return []error{linkFault{kind: ErrContainerVerbRelationVerbPrefix, coord: at("relation"),
			detail: fmt.Sprintf("%s: отношение %q несёт приставку v_ — приставка объявляет глагол объекта, "+
				"глаголы разворачивает подстановка `*`, а контейнерное действие подстановкой не раздаётся; "+
				"назовите отношение без приставки, как `member_remover`", label, cv.Relation)}}
	}
	declared := false
	var names []string
	for _, rel := range parent.Relations {
		names = append(names, rel.Name)
		if rel.Name == cv.Relation {
			declared = true
		}
	}
	if !declared {
		sort.Strings(names)
		return []error{linkFault{kind: ErrContainerVerbRelationUndeclared, coord: at("relation"),
			detail: fmt.Sprintf("%s: отношение %q ресурс-родитель %q в `relations` не объявляет; "+
				"объявлены: %s", label, cv.Relation, parent.Name, strings.Join(names, ", "))}}
	}
	if oracle == nil {
		return nil
	}
	decl, ok := oracle.RelationDeclaration(parentType, cv.Relation)
	if !ok || !decl.IsDirect() || !decl.AcceptsKind(creatorSubjectKind) {
		accepted := "—"
		if ok {
			accepted = strings.Join(decl.AcceptedKinds(), ", ")
		}
		return []error{linkFault{kind: ErrContainerVerbRelationSubject, coord: at("relation"),
			detail: fmt.Sprintf("%s: модель прав не выдаёт отношение %q типа %q учётке прямо "+
				"(принимает прямо: %s) — роль с этим действием выдаётся учётке, и выдача не "+
				"материализовалась бы", label, cv.Relation, parentType, accepted)}}
	}
	return nil
}

// containerVerbsOf — контейнерные действия названных ресурсов этого манифеста
// по имени действия.
func containerVerbsOf(m *Manifest, resources []string) map[string]bool {
	want := map[string]bool{}
	for _, r := range resources {
		want[r] = true
	}
	out := map[string]bool{}
	for i := range m.Resources {
		if !want[m.Resources[i].Name] {
			continue
		}
		for _, cv := range m.Resources[i].ContainerVerbs {
			out[cv.Name] = true
		}
	}
	return out
}

// validateRuleContainerForm — правило роли и контейнерные действия ресурсов,
// которые оно называет: класс именем контейнерного действия — отказ; селектор
// создателя — только над ресурсом с контейнерным действием `create` и без
// второго селектора.
func validateRuleContainerForm(m *Manifest, rule Rule, roleID string, doc *yaml.Node, i, j int) []error {
	var faults []error
	if rule.Module == "" || rule.Module == m.Module {
		containers := containerVerbsOf(m, rule.Resources)
		for _, c := range rule.Classes {
			if !containers[c] {
				continue
			}
			faults = append(faults, linkFault{kind: ErrRoleRuleClassIsContainerVerb,
				coord: locate(doc, "roles", i, "rules", j, "classes"),
				detail: fmt.Sprintf("roles[%d].rules[%d].classes: роль %q называет классом %q, а у ресурса "+
					"%s это контейнерное действие — классом и подстановкой оно не достигается; "+
					"назовите его поимённо: `verbs: [%s]`",
					i, j, roleID, c, strings.Join(rule.Resources, ", "), c)})
		}
	}
	coord := locate(doc, "roles", i, "rules", j, "createdBySubject")
	if !rule.CreatedBySubject {
		// `false` — второй способ сказать «селектора нет», и его разбор от
		// отсутствия ключа не отличил бы: значение выражается ОДНИМ способом.
		if n := mapValue(seqItem(mapValue(seqItem(mapValue(doc, "roles"), i), "rules"), j), "createdBySubject"); n != nil {
			faults = append(faults, linkFault{kind: ErrRuleCreatorSelectorFalse, coord: coord,
				detail: fmt.Sprintf("roles[%d].rules[%d].createdBySubject: роль %q пишет ключ со значением %q — "+
					"селектора нет, и это выражается отсутствием ключа", i, j, roleID, n.Value)})
		}
		return faults
	}
	if len(rule.ResourceNames) > 0 || len(rule.MatchLabels) > 0 {
		faults = append(faults, linkFault{kind: ErrRuleCreatorSelectorWithSelector, coord: coord,
			detail: fmt.Sprintf("roles[%d].rules[%d]: роль %q несёт createdBySubject вместе с "+
				"resourceNames или matchLabels — селекторы у правила взаимоисключающи", i, j, roleID)})
	}
	for _, res := range rule.Resources {
		ok := false
		if rule.Module == "" || rule.Module == m.Module {
			for k := range m.Resources {
				if m.Resources[k].Name != res {
					continue
				}
				if _, has := m.Resources[k].ContainerVerbNamed(creatorContainerVerb); has {
					ok = true
				}
			}
		}
		if ok {
			continue
		}
		faults = append(faults, linkFault{kind: ErrRuleCreatorSelectorWithoutContainer, coord: coord,
			detail: fmt.Sprintf("roles[%d].rules[%d]: роль %q несёт createdBySubject над ресурсом %q, "+
				"а у него нет контейнерного действия %s этого манифеста — «созданные субъектом» "+
				"без права создавать не выбирают ничего", i, j, roleID, res, creatorContainerVerb)})
	}
	return faults
}
