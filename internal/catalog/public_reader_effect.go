// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// PublicReaderRuleFPPrefix — приставка отдельного члена публичного чтения.
const PublicReaderRuleFPPrefix = "public_reader:"

// PublicReaderClassesSep отделяет отпечатки правил от полного набора классов.
const PublicReaderClassesSep = "@"

// PublicReaderGrant — прямой эффект производителя НА выбранном контейнере.
// Дальнейшие права определяет модель отношений, а не перечень ChildRuleFPs:
// правило над одним ребёнком может включить чтение других детей по модели.
// Recipients сохраняет тип класса и исходный порядок; RuleFP — прежний ключ
// отдельного члена, включающий все основания и полный набор классов выдачи.
type PublicReaderGrant struct {
	ObjectType   string
	FGAType      string
	Relation     string
	RuleFP       string
	ChildRuleFPs []string
	Recipients   []domain.Subject
}

// PublicReaderEffect — общий предикат реального производителя и компилятора.
// selectedOwnerFPs называет правила, которыми ОДИН контейнер уже выбран в
// пределах цели и области выдачи. Материализатор подтверждает это действующим
// членом; компилятор обязан доказать тот же отбор символически. Простого
// наличия правила в роли недостаточно. Для точного RuleFP нужен ПОЛНЫЙ
// перечень subjects; срез по получателю описывает лишь его часть эффекта.
func (f *Facts) PublicReaderEffect(selectors []domain.RuleSelector, subjects []domain.Subject,
	objectType string, selectedOwnerFPs map[string]bool) (PublicReaderGrant, bool) {
	classes := domain.SystemClassSubjects(subjects)
	if len(classes) == 0 {
		return PublicReaderGrant{}, false
	}
	children := f.PublicReadChildren(objectType)
	if len(children) == 0 {
		return PublicReaderGrant{}, false
	}
	classReadOwners := domain.PublicReaderOwnerRuleFPs(selectors)
	var fps []string
	for _, sel := range selectors {
		if sel.Container == nil || !selectedOwnerFPs[sel.Container.OwnerFP] || !classReadOwners[sel.Container.OwnerFP] {
			continue
		}
		sel.Verbs = domain.ClassReadVerbs(sel.Verbs)
		if sel.PublicReadsChildOf(objectType, children) {
			fps = append(fps, sel.RuleFP)
		}
	}
	if len(fps) == 0 {
		return PublicReaderGrant{}, false
	}
	fgaType, ok := f.FGAObjectType(objectType)
	if !ok {
		return PublicReaderGrant{}, false
	}
	sort.Strings(fps)
	keyClasses := make([]string, 0, len(classes))
	for _, subject := range classes {
		keyClasses = append(keyClasses, domain.FGASubjectRef(string(subject.Type), string(subject.ID)))
	}
	sort.Strings(keyClasses)
	return PublicReaderGrant{
		ObjectType: objectType, FGAType: fgaType, Relation: domain.PublicReaderRelation,
		RuleFP:       PublicReaderRuleFPPrefix + strings.Join(fps, ",") + PublicReaderClassesSep + strings.Join(keyClasses, ","),
		ChildRuleFPs: fps, Recipients: classes,
	}, true
}

// Tuples адресует общий эффект на конкретный выбранный контейнер, сохраняя
// порядок классов. Проверка отбора контейнера остаётся у вызывающего.
func (g PublicReaderGrant) Tuples(objectID string) []domain.MembershipTuple {
	out := make([]domain.MembershipTuple, 0, len(g.Recipients))
	for _, subject := range g.Recipients {
		out = append(out, domain.MembershipTuple{
			User:     domain.FGASubjectRef(string(subject.Type), string(subject.ID)),
			Relation: g.Relation, Object: g.FGAType + ":" + objectID,
		})
	}
	return out
}
