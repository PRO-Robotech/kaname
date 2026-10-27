// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// creator_gates.go — структурные условия выдачи роли, правило которой называет
// КОНТЕЙНЕРНОЕ действие либо несёт СЕЛЕКТОР СОЗДАТЕЛЯ (задача
// PRO-Robotech/kaname#1003; приёмка `service-account-creation-is-its-own-right.md`,
// Р2, тексты Р6, сценарий SAC-02).
//
// Такая роль — роль создателя: право создавать учётки на аккаунте и ведение
// созданных. Её выдача имеет смысл ровно в одной форме:
//
//	область — iam.account   право создавать лежит на аккаунте (родитель учётки),
//	                        и ведение созданного считается по создателю В аккаунте;
//	цель — allInScope       выдача по названным объектам права на область не даёт;
//	субъект — учётка        «кто создал» у группы неоднозначно, у человека есть
//	                        `editor` (§8 В3).
//
// Порядок — на месте структурных ворот (`structural_gates.go`, ORDERING): ПОСЛЕ
// права выдавать, поэтому отказ ничего не раскрывает постороннему. Условия
// судятся в порядке таблицы приёмки — область, цель, субъекты, — и первый отказ
// называет первое нарушенное.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// isCreatorRole — роль называет контейнерное действие (по живому каталогу) либо
// несёт селектор создателя. Каталог не провязан — контейнерных действий не
// видно, и решает один селектор: ошибка в сторону УЖЕСТОЧЕНИЯ, а не пропуска,
// у роли создателя есть оба признака.
func isCreatorRole(facts *catalog.Facts, rules domain.Rules) bool {
	for _, r := range rules {
		if r.CreatedBySubject {
			return true
		}
		if facts != nil && len(facts.ContainerGrants(r.Module, r.Resources, r.Verbs)) > 0 {
			return true
		}
	}
	return false
}

// validateCreatorRoleGates — три структурных условия роли создателя (Р2);
// у прочих ролей — nil.
func (u *CreateAccessBindingUseCase) validateCreatorRoleGates(role domain.Role, b domain.AccessBinding) error {
	var facts *catalog.Facts
	if u.cat != nil {
		facts = u.cat.Facts()
	}
	if !isCreatorRole(facts, role.Rules) {
		return nil
	}
	if b.ResourceType != "account" {
		return status.Errorf(codes.FailedPrecondition,
			"role %s grants service account creation on iam.account scope only", role.ID)
	}
	if len(b.Target.Resources) > 0 {
		return status.Errorf(codes.FailedPrecondition, "role %s requires target allInScope", role.ID)
	}
	for _, s := range b.Subjects {
		if s.Type != domain.SubjectTypeServiceAccount {
			return status.Errorf(codes.FailedPrecondition,
				"role %s can only be granted to SUBJECT_TYPE_SERVICE_ACCOUNT", role.ID)
		}
	}
	return nil
}
