// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// creator.go — материализация роли создателя (задача PRO-Robotech/kaname#1003;
// приёмка `service-account-creation-is-its-own-right.md`, Р2 пп.1–3, Р2а, Р3).
//
// # Две проекции одной выдачи
//
//  1. КОНТЕЙНЕРНОЕ действие (правило 1 роли C, `{iam, [serviceAccount], [create]}`):
//     поимённо названное действие, объявленное каталогом контейнерным, даёт
//     субъекту выдачи отношение на РОДИТЕЛЕ — на объекте области выдачи
//     (`account:<A>#service_account_creator@service_account:<S>`). Пообъектного
//     кортежа на учётках оно не пишет: в набор глаголов типа не входит, и яруса,
//     выводимого из него, на учётках тоже нет (`objectVerbsOf`).
//  2. СЕЛЕКТОР СОЗДАТЕЛЯ (правило 2, `createdBySubject`): глаголы правила
//     материализуются на учётке только для того субъекта выдачи, который её
//     создал (`creatorGrantees`), и только глаголами — ярус на учётке не
//     материализуется (Р2 п.3).
//
// # Конец выдачи — тем же путём, что у любого члена
//
// Обе проекции — члены выдачи со своими строками реестра выпущенного. Отзыв,
// удаление и истечение снимают реестр выдачи целиком; общий кортеж второй
// действующей выдачи того же субъекта держит свёртка факта по держателям
// (Р3 п.1). Своего пути снятия у роли создателя нет — и нечему расходиться.
//
// # Порядок под конкурентной записью
//
// Создание учётки и выдача роли C материализуют член одним и тем же решением
// (`desiredMemberForObject`) из двух сторон: проход по объекту и проход по выдаче.
// Снятие выдачи берёт строку выдачи `FOR UPDATE` раньше чтения реестра, а оба
// прохода читают её `FOR KEY SHARE` (kaname#919): член, записанный проходом,
// увидевшим выдачу действующей, снятие дождётся и снимет; проход, пришедший после
// снятия, увидит выдачу REVOKED и не запишет ничего (Р3 п.4).

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// creatorGrantees — субъекты выдачи, которым правило с селектором создателя
// даёт глаголы на объекте `o`: ровно субъект, чья ссылка совпадает с создателем
// объекта. Объект без записанного создателя не даёт никому (сторона отказа).
// У правила без селектора — все `gs` как есть.
func creatorGrantees(sel domain.RuleSelector, gs []grantee, o domain.MirrorObject) []grantee {
	if !sel.CreatedBySubject {
		return gs
	}
	if o.CreatedBy == "" {
		return nil
	}
	var out []grantee
	for _, g := range gs {
		if g.subject == o.CreatedBy {
			out = append(out, g)
		}
	}
	return out
}

// objectVerbsOf — глаголы правила, которые пишут кортежи на объекте типа
// `objectType`: контейнерные действия типа вычитаются (они дают отношение на
// родителе, а не на объекте, и яруса на объекте не выводят).
func objectVerbsOf(cat *catalog.Facts, objectType string, verbs []string) []string {
	out := make([]string, 0, len(verbs))
	for _, v := range verbs {
		if _, ok := cat.ContainerVerb(objectType, v); ok {
			continue
		}
		out = append(out, v)
	}
	return out
}

// verbTuplesOnly — кортежи глаголов без яруса: правило с селектором создателя
// ярус на объекте не материализует (Р2 п.3).
func verbTuplesOnly(tuples []domain.MembershipTuple) []domain.MembershipTuple {
	out := tuples[:0:0]
	for _, t := range tuples {
		if strings.HasPrefix(t.Relation, "v_") {
			out = append(out, t)
		}
	}
	return out
}

// creatorSubjectIDs — идентификаторы учёток среди субъектов выдачи: создателями,
// которых ищет селектор создателя, бывают только они (роль создателя выдаётся
// только учётке, Р2).
func creatorSubjectIDs(bs BindingScope) []string {
	var out []string
	for _, s := range bs.Subjects {
		if s.Type == domain.SubjectTypeServiceAccount {
			out = append(out, string(s.ID))
		}
	}
	return out
}

// containerMembers — члены выдачи на объекте ОБЛАСТИ от контейнерных действий её
// правил: по одному члену на правило, кортежи — отношение на родителе каждому
// субъекту-учётке. Только у выдачи на всю область: выдача по названным объектам
// права на область не даёт (тот же довод, что у scope-self). Тип родителя обязан
// совпасть с типом области — контейнерное действие на чужом родителе область
// выдачи не адресует.
func containerMembers(cat *catalog.Facts, bs BindingScope) []DesiredMember {
	if len(bs.Target.Resources) > 0 || bs.Scope.ID == "" {
		return nil
	}
	var subjects []string
	for _, id := range creatorSubjectIDs(bs) {
		subjects = append(subjects, domain.FGASubjectRef(string(domain.SubjectTypeServiceAccount), id))
	}
	if len(subjects) == 0 {
		return nil
	}
	var out []DesiredMember
	for _, sel := range bs.Selectors {
		if sel.Container != nil {
			continue
		}
		seen := map[domain.MembershipTuple]bool{}
		var tuples []domain.MembershipTuple
		for _, typ := range sel.ObjectTypes {
			for _, v := range sel.Verbs {
				g, ok := cat.ContainerVerb(typ, v)
				if !ok || g.ParentType != bs.Scope.Type {
					continue
				}
				for _, subj := range subjects {
					t := domain.MembershipTuple{User: subj, Relation: g.Relation, Object: g.ParentType + ":" + bs.Scope.ID}
					if seen[t] {
						continue
					}
					seen[t] = true
					tuples = append(tuples, t)
				}
			}
		}
		if len(tuples) == 0 {
			continue
		}
		out = append(out, DesiredMember{
			RuleFP:     sel.RuleFP,
			ObjectType: "iam." + bs.Scope.Type,
			ObjectID:   bs.Scope.ID,
			Status:     domain.VerificationActive,
			Tuples:     tuples,
		})
	}
	return out
}

// selectorWritesObjects — правило пишет кортежи хотя бы на одном объекте своих
// типов: у него есть глагол, который не контейнерное действие типа.
// Подстановка `*` — глаголы типа, значит пишет.
func selectorWritesObjects(cat *catalog.Facts, sel domain.RuleSelector) bool {
	for _, typ := range sel.ObjectTypes {
		if len(objectVerbsOf(cat, typ, sel.Verbs)) > 0 {
			return true
		}
	}
	return false
}

// matchCreatorObjects — кандидаты правила с селектором создателя: объекты его
// типов в области выдачи, создатель которых — одна из учёток-субъектов выдачи.
// Выдача по названным объектам сужает их целью, как у всякого правила.
func (r *Reconciler) matchCreatorObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector,
	bs BindingScope) ([]domain.MirrorObject, error) {
	creators := creatorSubjectIDs(bs)
	if len(creators) == 0 {
		return nil, nil
	}
	_, iamTypes := partitionByFeed(sel.ObjectTypes)
	if len(iamTypes) == 0 {
		// Факт создателя хранится только у собственных объектов iam: у объекта
		// зеркала создателя нет, и селектор его не выбирает (сторона отказа).
		return nil, nil
	}
	objs, err := s.MatchCreatedByIAMDirect(ctx, iamTypes, bs.Scope, creators)
	if err != nil {
		return nil, fmt.Errorf("match creator selector %s: %w", sel.RuleFP, err)
	}
	if len(bs.Target.Resources) > 0 {
		objs = filterMatchedToTarget(objs, bs.Target)
	}
	return objs, nil
}
