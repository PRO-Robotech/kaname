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

// unitScopes — сцена по умолчанию: один проект prj_unit в аккаунте acc_unit.
func unitScopes() sceneScopes {
	return sceneScopes{projects: map[string]string{unitProject: unitAccount}}
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
