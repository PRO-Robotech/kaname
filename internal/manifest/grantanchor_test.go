// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// grantanchor_test.go — ЯКОРЬ выдачи посева судится ПО ЗНАЧЕНИЮ, и одинаково
// для обеих форм выдачи (задача продукта #1953).
//
// # Что здесь было неверно
//
// Опубликованная схема пинит якорь двумя `const` — `scopeType: iam.cluster` и
// `scopeId: cluster_kacho_root`, — а единственный объявленный судья формы
// (загрузчик) значения не судил. Он требовал лишь, чтобы ключ был назван
// непустым. Схема судьёй не является и судьёй не станет — она КОНТРАКТ для
// автора манифеста и его редактора (см. шапку пакета), — поэтому `const` без
// отказа у загрузчика есть обещание без исполнителя.
//
// Замер ВЫЗОВОМ, а не чтением, на ревизии заведения задачи: загрузчик принимал
// `scopeType: iam.project`, `iam.account` и даже выдуманный `iam.galaxy`, а
// `scopeId: cluster_something_else` проходил у ОБЕИХ форм выдачи — включая ту,
// которую #1936 только что укрепил. То есть радиус шире, чем названо задачей:
// #1936 запинил у формы отношения ОДИН ключ якоря из двух.
//
// # Почему судья ОДИН на обе формы, а не ветвь на каждую
//
// Якорь есть свойство ВЫДАЧИ, а не того, чем она наделяет: выдача действует на
// объекте яруса независимо от того, роль это или отношение. Ветвь на форму дала
// бы одному полю два режима по соседним ветвям — ровно тот дрейф, из-за которого
// два правила об одном предмете расходятся молча.
//
// # Отрицания стоят В ПАРЕ с положительным
//
// Отказ без законного близнеца зеленеет на реализации, отвергающей всё. Поэтому
// каждое отрицание ниже сопровождается прогоном законного якоря — и у ОБЕИХ
// форм, иначе «судится одинаково» осталось бы недоказанным для одной из них.
package manifest_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// bindingRoleAt — выдача РОЛЬЮ на названном якоре.
//
// Раздела `roles` в оболочке нет намеренно: при необъявленном разделе связность
// ссылку на роль не сверяет (`roles.declared == false`), поэтому проба портит
// РОВНО якорь и ничего сверх него. Инъекция, роняющая заодно соседнюю проверку,
// доказательством не является — красное пришло бы от соседа.
func bindingRoleAt(scopeType, scopeID string) string {
	return `    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      roleId: vpc.network.admin
      scopeType: ` + scopeType + `
      scopeId: ` + scopeID + `
      target: allInScope
`
}

// bindingRelationAt — выдача ОТНОШЕНИЕМ на названном якоре. Отношение взято то
// же, что несут две живые строки посева, — иначе проба мерила бы не тот отказ.
func bindingRelationAt(scopeType, scopeID string) string {
	return `    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: ` + scopeType + `
      scopeId: ` + scopeID + `
      target: allInScope
`
}

// TestGrantAnchorScopeTypeIsRefusedByValueForBothGrantForms — ярус якоря судится
// по ЗНАЧЕНИЮ, и у формы роли тоже.
//
// До этой работы форма роли не судилась вовсе, а форма отношения судилась своей
// ветвью в relationgrant.go. Проба требует ОДНОГО отказа от обеих.
func TestGrantAnchorScopeTypeIsRefusedByValueForBothGrantForms(t *testing.T) {
	// Ярусы, на которых посев модуля выдач не делает. Перечень ВЫВЕДЕН из
	// закрытой таблицы ярусов домена, а не выписан: вторая копия разошлась бы
	// с первой на первом же новом ярусе.
	var wrongTiers []string
	for _, dotted := range []string{
		domain.ScopeTypeAccountDotted,
		domain.ScopeTypeProjectDotted,
	} {
		wrongTiers = append(wrongTiers, dotted)
	}
	// Плюс ярус, которого нет вовсе: он проверяет, что отказ приходит от
	// сверки со ЗНАЧЕНИЕМ, а не от неудачного резолва в таблице.
	wrongTiers = append(wrongTiers, "iam.galaxy")

	forms := map[string]func(string, string) string{
		"роль":      bindingRoleAt,
		"отношение": bindingRelationAt,
	}

	for formName, form := range forms {
		for _, tier := range wrongTiers {
			t.Run(formName+"/"+tier, func(t *testing.T) {
				doc := seedWithBinding(form(tier, domain.ClusterSingletonID))
				msg := mustRefuseGrant(t, doc, manifest.ErrBindingAnchor,
					"scopeType", tier, domain.ScopeTypeClusterDotted)
				if !strings.Contains(msg, "seed.accessBindings[0]") {
					t.Errorf("отказ не называет координату выдачи: %s", msg)
				}
			})
		}
	}
}

// TestGrantAnchorScopeIdIsRefusedByValueForBothGrantForms — ОБЪЕКТ якоря
// судится по значению у обеих форм.
//
// Этот ключ не судился ни у одной формы: #1936 запинил у формы отношения только
// ярус. Кластер — singleton, поэтому объект у него ровно один, и «другой
// кластер» есть строка, которой не отвечает ни одна живая.
func TestGrantAnchorScopeIdIsRefusedByValueForBothGrantForms(t *testing.T) {
	forms := map[string]func(string, string) string{
		"роль":      bindingRoleAt,
		"отношение": bindingRelationAt,
	}
	for formName, form := range forms {
		t.Run(formName, func(t *testing.T) {
			doc := seedWithBinding(form(domain.ScopeTypeClusterDotted, "cluster_something_else"))
			msg := mustRefuseGrant(t, doc, manifest.ErrBindingAnchor,
				"scopeId", "cluster_something_else", domain.ClusterSingletonID)
			if !strings.Contains(msg, "seed.accessBindings[0]") {
				t.Errorf("отказ не называет координату выдачи: %s", msg)
			}
		})
	}
}

// TestGrantAnchorLegalValuePassesForBothGrantForms — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к
// обоим отрицаниям выше.
//
// Без него оба зеленели бы на загрузчике, отвергающем всякую выдачу, и
// утверждение «якорь судится по значению» осталось бы недоказанным.
func TestGrantAnchorLegalValuePassesForBothGrantForms(t *testing.T) {
	forms := map[string]func(string, string) string{
		"роль":      bindingRoleAt,
		"отношение": bindingRelationAt,
	}
	for formName, form := range forms {
		t.Run(formName, func(t *testing.T) {
			doc := seedWithBinding(form(domain.ScopeTypeClusterDotted, domain.ClusterSingletonID))
			mustLoadGrantOK(t, doc, "законный якорь обеих форм обязан проходить")
		})
	}
}

// TestGrantAnchorRefusalNamesTheKeyAndNotTheForm — отказ не ссылается на форму
// выдачи.
//
// До этой работы текст говорил «выдача ролью этой проверкой не затронута
// (#1953)» — верно на своей ревизии и ложь после неё. Утверждение, пережившее
// свой предмет, читается чаще всего именно в отказе: его видит автор манифеста.
func TestGrantAnchorRefusalNamesTheKeyAndNotTheForm(t *testing.T) {
	doc := seedWithBinding(bindingRelationAt(domain.ScopeTypeProjectDotted, domain.ClusterSingletonID))
	msg := mustRefuseGrant(t, doc, manifest.ErrBindingAnchor, "scopeType")
	for _, stale := range []string{"выдача ролью этой проверкой не затронута", "#1953"} {
		if strings.Contains(msg, stale) {
			t.Errorf("отказ несёт утверждение, пережившее свой предмет (%q): %s", stale, msg)
		}
	}
}
