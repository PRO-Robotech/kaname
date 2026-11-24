// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Регистрация не наследует административные вопросы D1. Полный набор её
// вопросов состоит только из OLD+NEW аккаунтов канонического владельца.
func resourceRegistrationQuestions(serviceName string, accounts []domain.AccountID) (*nativePolicyQuestions, error) {
	if !nativeQuestionToken(serviceName) || len(accounts) == 0 || len(accounts) > kaname.MaxAuthorityFenceAccounts {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	actor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(authzguard.ServiceAccountIDForService(serviceName))}
	questions := newNativePolicyQuestions()
	for _, account := range accounts {
		if err := questions.add(actor, authzguard.RelationWriteRelation, "account", string(account)); err != nil {
			return nil, err
		}
	}
	return questions, nil
}

// Новая форма отношения требует нового набора зависимостей. Проверка прямого
// SA-only объявления не разрешает admin, wildcard или наследование от кластера.
func validateResourceRegistrationModel(bundle *granteffect.Bundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	model, err := authzplan.ParseModel(bundle.ModelSource())
	if err != nil {
		return err
	}
	account := model.Type("account")
	if account == nil {
		return kaname.ErrSourceUnconfirmed
	}
	relation := account.Rel(authzguard.RelationWriteRelation)
	if relation == nil || len(relation.Terms) != 1 || relation.Terms[0].Kind != authzplan.TermDirect || len(relation.Terms[0].Direct) != 1 {
		return kaname.ErrSourceUnconfirmed
	}
	subject := relation.Terms[0].Direct[0]
	if subject.Type != "service_account" || subject.Wildcard || subject.Userset != "" || subject.Object != "" || subject.Condition != "" {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}
