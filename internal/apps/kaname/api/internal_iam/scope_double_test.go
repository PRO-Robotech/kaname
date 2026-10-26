// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// scope_double_test.go — дублёр чтений вывода родителя (kaname#982) для проб на
// подставных портах (без базы).
//
// Дублёр знает ровно то, что в него вписала проба: проекты с их аккаунтами,
// зарегистрированные контейнеры с их областью и факты указателя. Незнакомый
// проект — «проекта нет», незнакомый контейнер — «не зарегистрирован»: так же
// отвечает настоящий читатель, и вход, которого проба не построила, отвергается
// выводом, а не проходит молча.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Проект и аккаунт сцены проб на подставных портах: регистрации проб ложатся
// под него указателем `project`.
const (
	unitProject = "prj_unit"
	unitAccount = "acc_unit"
)

// sceneScopes — дублёр порта registrationScopeReader.
type sceneScopes struct {
	projects   map[string]string                // проект → аккаунт
	containers map[string]domain.ContainerScope // «тип:id» → записанная область
	pointers   map[string][]string              // «тип:id» → субъекты фактов указателя
}

// unitScopes — сцена по умолчанию: проекты, под которыми регистрируют пробы на
// подставных портах, каждый в своём аккаунте.
func unitScopes() sceneScopes {
	return sceneScopes{projects: map[string]string{
		unitProject:            unitAccount,
		"prj-1":                "acc-1",
		"prj-2":                "acc-2",
		"prj_1":                "acc_1",
		"prj_home":             "acc_home",
		"prj0000000000000proj": "acc0000000000000acc1",
	}}
}

// deliveredRegistryTypes — каталог после доставки манифеста registry с записью
// `writes: owner` (документ W приёмки kaname#982): политика посева плюс запись
// создателя человеком либо учёткой у обоих типов registry. Нужен пробам, чей
// «Дано» — потребитель, пишущий `owner`: при одном посеве такая запись — отказ
// политики, и сцена не строилась бы.
type deliveredRegistryTypes struct{ seededCatalogTypes }

// WritePolicyTx — политика посева; у типов registry — плюс запись `owner`.
func (d deliveredRegistryTypes) WritePolicyTx(ctx context.Context, tx service.Tx, typeName string) (string, domain.WritePolicy, bool, error) {
	dotted, policy, live, err := d.seededCatalogTypes.WritePolicyTx(ctx, tx, typeName)
	if err != nil || !live {
		return dotted, policy, live, err
	}
	if policy.ObjectType == "registry_registry" || policy.ObjectType == "registry_repository" {
		for _, s := range domain.WriteSubjectTypes() {
			policy.Writes = append(policy.Writes, domain.WriteGrant{Relation: "owner", SubjectType: s})
		}
	}
	return dotted, policy, true, nil
}

func (s sceneScopes) ProjectAccountTx(_ context.Context, _ service.Tx, projectID string) (string, bool, error) {
	acc, ok := s.projects[projectID]
	return acc, ok, nil
}

func (s sceneScopes) ContainerScopeTx(_ context.Context, _ service.Tx, modelType, id string) (domain.ContainerScope, error) {
	return s.containers[modelType+":"+id], nil
}

func (s sceneScopes) PointerSubjectsTx(_ context.Context, _ service.Tx, modelType, id string, _ []string) ([]string, error) {
	return s.pointers[modelType+":"+id], nil
}

// BindingRefusesTx — привязок у сцены проб на подставных портах нет: их держит
// база (kaname#983), и судят их пробы на живой базе.
func (s sceneScopes) BindingRefusesTx(context.Context, service.Tx, string, string, string, []string) (bool, error) {
	return false, nil
}
