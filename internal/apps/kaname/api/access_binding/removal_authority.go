// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// removal_authority.go — право отозвать и удалить выдачу (задача
// PRO-Robotech/kaname#986, Р1а приёмки
// docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md).
//
// До этой задачи `AccessBindingService.Revoke` и `Delete` судила ДВЕРЬ
// слушателя: аннотация `v_delete` на `iam_access_binding:<id>`, и обработчик
// спрашивал только право выдавать на области. У делегата на объекте его выдачи
// нет ни одного отношения модели, и дверь отвергла бы его до обработчика,
// поэтому аннотация обоих глаголов стала `<exempt>` · `HANDLER_DECIDES`. Чтобы
// снятие двери не расширило прежний путь, её вопрос ПЕРЕЕХАЛ сюда дословно — тем
// же портом и с тем же надзором администратора облака (`authzguard.AllowsVerb`).
// Задаёт его ОДНА функция, общая для отзыва и удаления (условие CE-01 разбора
// классов); литерала отношения в обработчиках больше нет.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Вопрос, который до kaname#986 задавала дверь слушателя отзыву и удалению
// выдачи. Единый источник для обработчика и проб, читавших строку каталога
// (условие CE-17): отношение и тип объекта модели.
const (
	// RemovalRelation — отношение, которое держатель права выдавать обязан иметь
	// на объекте выдачи, чтобы отозвать или удалить её прежним путём.
	RemovalRelation = "v_delete"
	// RemovalObjectType — тип объекта выдачи в модели прав.
	RemovalObjectType = fgaBindingObjectType
)

// removalAuthority — право отозвать или удалить выдачу. Порядок путей (Р2):
//
//  1. прежний путь — вопрос двери `v_delete` на объекте выдачи И право выдавать
//     на области выдачи (как до kaname#986);
//  2. делегированный путь — только когда прежний ОТКАЗАЛ: выдача несёт ссылку на
//     действующее делегирование вызывающего.
//
// У вопроса `v_delete` три исхода: «да» ведёт к праву выдавать, «нет» — к
// делегированному пути, неполадка хранилища — `UNAVAILABLE` `authz backend
// unavailable`, и ни в отказ, ни в делегированный путь она не уходит (условие
// CE-02). Скрытие существования выдачи — у вызывающего, до этой функции.
func removalAuthority(ctx context.Context, repo Repo, relations clients.RelationStore, delegated *DelegatedGrantPath, b domain.AccessBinding) error {
	err := priorRemovalAuthority(ctx, repo, relations, b)
	if err == nil {
		return nil
	}
	if !isPermissionDenied(err) {
		return err
	}
	_, derr := delegatedGrantAuthority(ctx, delegated, b, true)
	return derr
}

// priorRemovalAuthority — прежний путь: вопрос двери, переехавший в обработчик,
// затем право выдавать на области выдачи.
func priorRemovalAuthority(ctx context.Context, repo Repo, relations clients.RelationStore, b domain.AccessBinding) error {
	allowed, err := authzguard.AllowsVerb(ctx, relations, RemovalRelation, RemovalObjectType, string(b.ID))
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if !allowed {
		return authzguard.PermissionDenied()
	}
	return requireGrantAuthority(ctx, repo, relations, string(b.ResourceType), b.ResourceID)
}
