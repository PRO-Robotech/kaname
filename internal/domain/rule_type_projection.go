// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// RuleTypeWildcard называет подстановку ТИПОВ правила, отдельно от его глаголов.
type RuleTypeWildcard uint8

const (
	RuleTypeWildcardNone RuleTypeWildcard = iota
	RuleTypeWildcardAllModules
	RuleTypeWildcardModuleResources
)

// RuleTypeProjection — точный результат действующего производителя типов.
// ObjectTypes — нынешний перечень, а не обещание замкнутости будущего каталога.
// Подстановка и её подавление сохранены даже при пустом результате: компилятор
// не вправе принять такой перечень за доказательство пустого полного эффекта.
type RuleTypeProjection struct {
	ObjectTypes        []string
	WildcardKind       RuleTypeWildcard
	WildcardModule     string
	WildcardSuppressed bool
}

// UsesStaticRegistry сообщает, раскрыта ли подстановка по реестру сборки
// AllMaterializableTypes. Живой каталог может уже содержать другие типы;
// доказательство будущего эффекта требует отдельного обоснования замкнутости.
func (p RuleTypeProjection) UsesStaticRegistry() bool {
	return p.WildcardKind != RuleTypeWildcardNone && !p.WildcardSuppressed
}

// MaterializedTypeProjection — общий расчёт для материализатора и анализа
// выдачи. Область — область НОСИТЕЛЯ выдачи, а не место хранения роли.
// Функция не заменяет Rule.Validate и не вычисляет права на якоре области:
// ScopeSelfVerbs и эмиссия прежних ролей имеют собственные общие производители.
// Подавление на cluster не производит system_admin или system_viewer.
func (r Rule) MaterializedTypeProjection(scope Scope) RuleTypeProjection {
	return r.materializedTypeProjection(scopeIsBounded(scope))
}

// materializedTypeProjection обслуживает также индекс роли: он раскрывает
// подстановку независимо от области, как прежний MaterializingSelectors.
func (r Rule) materializedTypeProjection(expandWildcard bool) RuleTypeProjection {
	if r.Module == wildcard {
		out := RuleTypeProjection{
			WildcardKind:       RuleTypeWildcardAllModules,
			WildcardModule:     wildcard,
			WildcardSuppressed: !expandWildcard,
		}
		if expandWildcard {
			out.ObjectTypes = AllMaterializableTypes()
		}
		return out
	}
	out := RuleTypeProjection{ObjectTypes: make([]string, 0, len(r.Resources))}
	for _, res := range r.Resources {
		if res == wildcard {
			out.WildcardKind = RuleTypeWildcardModuleResources
			out.WildcardModule = r.Module
			out.WildcardSuppressed = !expandWildcard
			if expandWildcard {
				out.ObjectTypes = materializableTypesForModule(r.Module)
				return out
			}
			continue
		}
		out.ObjectTypes = append(out.ObjectTypes, r.Module+"."+res)
	}
	return out
}
