// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package catalog

import (
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Facts — НЕИЗМЕНЯЕМЫЙ каталожный факт на один момент времени.
//
// Значение собирается один раз и после этого не правится: обновление снимка
// строит НОВОЕ значение и подменяет указатель. Поэтому вызывающий, взявший факт,
// держит согласованное множество до конца своего вычисления — половины
// обновления он не увидит ни при какой конкуренции.
type Facts struct {
	// verbsByFGAType — набор глаголов ЖИВОГО типа, в имени словаря МОДЕЛИ
	// (`vpc_network`), отсортированный. Ключ переведён здесь, один раз, а не у
	// каждого вызывающего: соединение колонок разных словарей не совпадает
	// никогда и молча.
	verbsByFGAType map[string][]string
	common         []string
	all            []string
}

// NewFacts собирает факт из живых строк каталога.
//
// ПУСТОЕ МНОЖЕСТВО ОТВЕРГАЕТСЯ, и это не перестраховка. Пустой снимок отверг бы
// ВСЕ правила арендатора разом, и снаружи это читалось бы как «продукт сломан»,
// а не как «миграции не применены». На старте до этого не доходит — страж
// отказывает в пуске раньше, — но обновление снимка идёт БЕЗ стража, и пустой
// ответ там обязан быть отказом обновления, а не новым снимком.
func NewFacts(rows Rows) (*Facts, error) {
	if len(rows.Modules) == 0 || len(rows.Resources) == 0 || len(rows.Verbs) == 0 {
		return nil, fmt.Errorf("каталог модуля пуст: строк модулей/ресурсов/глаголов %d/%d/%d — "+
			"пустой снимок отверг бы ВСЕ правила разом, и это читалось бы как поломка продукта, "+
			"а не как непринятые миграции (kacho#1816, IAM-CT-2-02)",
			len(rows.Modules), len(rows.Resources), len(rows.Verbs))
	}

	live := make(map[string]bool, len(rows.Resources))
	for _, r := range rows.Resources {
		live[r.Module+"."+r.Resource] = true
	}

	byDotted := make(map[string][]string, len(rows.Resources))
	for _, v := range rows.Verbs {
		dotted := v.Module + "." + v.Resource
		// Глагол СНЯТОГО ресурса не считается. В базе согласие держит внешний
		// ключ, но читатель обязан быть верен и на строках, пришедших из будущей
		// формы снятия: ресурс без живой строки глаголов не объявляет.
		if !live[dotted] {
			continue
		}
		// ЯРУСНАЯ строка в набор типа НЕ ВХОДИТ, и это несущее место, а не
		// фильтр для порядка. Набор типа — то, по чему материализуются кортежи
		// (`GrantedVerbs` → `role_verb` → реконсайлер); пропустить сюда
		// авторский глагол без пообъектного отношения значило бы вернуть
		// `v_create`, снятый с 23 типов осознанно (#1863, замер снятия — в
		// `verb-create-withdrawal.md`).
		//
		// Строка при этом ОСТАЁТСЯ в `rows.Verbs` и остаётся живой: по ней
		// резолвится ключ объявления правила, и в этом смысл разделения — ключ
		// судит авторский словарь, набор типа остаётся пообъектным.
		if !v.PerObject {
			continue
		}
		byDotted[dotted] = append(byDotted[dotted], v.Verb)
	}

	f := &Facts{verbsByFGAType: make(map[string][]string, len(byDotted))}
	for dotted, verbs := range byDotted {
		fgaType, ok := authzmap.FGAObjectType(dotted)
		if !ok {
			// Строка есть, а имени типа модели у неё нет — тип чужой либо снят с
			// канона. Отношения `v_*` у него не существует, поэтому набор
			// глаголов для него не имеет адресата: пара в проекции указывала бы
			// на отношение, которого нет в модели.
			continue
		}
		sort.Strings(verbs)
		f.verbsByFGAType[fgaType] = verbs
	}
	f.common, f.all = vocabularies(f.verbsByFGAType)
	return f, nil
}

// vocabularies — ПЕРЕСЕЧЕНИЕ и ОБЪЕДИНЕНИЕ наборов живых типов.
//
// Вопросы разные, и путать их нельзя: «что даёт ЛЮБОЙ ресурс» против «что бывает
// вообще». Первый спрашивает публичное поле каталога, второй — запасной набор
// для якоря без собственного (кластер). Пока наборы типов совпадали, обе
// величины были одним числом, и вызывающему, которому нужно «всё», доставалось
// пересечение — по совпадению, а не по существу.
func vocabularies(byType map[string][]string) (common, all []string) {
	var inter map[string]bool
	union := map[string]bool{}
	for _, set := range byType {
		if len(set) == 0 {
			continue
		}
		in := make(map[string]bool, len(set))
		for _, v := range set {
			in[v] = true
			union[v] = true
		}
		if inter == nil {
			inter = in
			continue
		}
		for v := range inter {
			if !in[v] {
				delete(inter, v)
			}
		}
	}
	common = make([]string, 0, len(inter))
	for v := range inter {
		common = append(common, v)
	}
	all = make([]string, 0, len(union))
	for v := range union {
		all = append(all, v)
	}
	sort.Strings(common)
	sort.Strings(all)
	return common, all
}

// VerbsOfType — ГЛАГОЛЫ, объявленные ЖИВЫМ типом, отсортированно; nil у типа,
// чья строка снята либо которого в каталоге нет вовсе (`cluster`).
//
// Возвращается КОПИЯ: значение снимка вызывающему не принадлежит, а испортить
// его он мог бы одной сортировкой на месте.
func (f *Facts) VerbsOfType(fgaType string) []string {
	set := f.verbsByFGAType[fgaType]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, len(set))
	copy(out, set)
	return out
}

// CommonVerbVocabulary — глаголы, общие ДЛЯ ВСЕХ живых глагольных типов.
func (f *Facts) CommonVerbVocabulary() []string {
	out := make([]string, len(f.common))
	copy(out, f.common)
	return out
}

// AllVerbVocabulary — глаголы, которые объявляет ХОТЬ ОДИН живой глагольный тип.
func (f *Facts) AllVerbVocabulary() []string {
	out := make([]string, len(f.all))
	copy(out, f.all)
	return out
}

// GrantedVerbs — глаголы, которые правило с авторскими глаголами `authored` даёт
// НА ТИПЕ `fgaType`.
//
// Предикат ОДИН на обе стороны и живёт у владельца правила
// (`authzmap.GrantedVerbsWithDeclared`); отсюда приходит единственный факт,
// который зависит от каталога, — объявляет ли ЖИВОЙ тип набор глаголов вообще.
// Повторить вычисление здесь значило бы завести второе место об одном предмете:
// ровно так роль-администратор однажды давала движку всё, а проекции — ничего.
func (f *Facts) GrantedVerbs(fgaType string, authored, typeVerbs []string) []string {
	return authzmap.GrantedVerbsWithDeclared(fgaType, len(f.verbsByFGAType[fgaType]) > 0,
		authored, typeVerbs)
}

// RoleVerbsFromSelectors — проекция «тип × глагол» из тех же селекторов,
// которыми роль материализуется, по ЖИВОМУ каталогу.
//
// Тип в проекции остаётся ТОЧЕЧНЫМ — тем же, каким он назван в селекторах и
// каким его читает вердикт (`role_verb.object_type`); набор глаголов
// спрашивается по имени МОДЕЛИ, поэтому перевод делается здесь ровно один раз.
//
// Тип, чья строка СНЯТА, пар не даёт — и это предмет задачи #1816: пара по
// снятому типу дошла бы до внешнего ключа `role_verb_type_fk` и была бы им
// отвергнута, то есть отказ пришёл бы ЧУЖОЙ полосой.
func (f *Facts) RoleVerbsFromSelectors(selectors []domain.RuleSelector) []domain.RoleVerb {
	seen := make(map[domain.RoleVerb]bool)
	out := make([]domain.RoleVerb, 0, len(selectors))
	for _, sel := range selectors {
		for _, dotted := range sel.ObjectTypes {
			if dotted == "" {
				continue
			}
			fgaType, ok := authzmap.FGAObjectType(dotted)
			if !ok {
				continue
			}
			for _, verb := range f.GrantedVerbs(fgaType, sel.Verbs, f.VerbsOfType(fgaType)) {
				pair := domain.RoleVerb{ObjectType: dotted, Verb: verb}
				if seen[pair] {
					continue
				}
				seen[pair] = true
				out = append(out, pair)
			}
		}
	}
	return out
}
