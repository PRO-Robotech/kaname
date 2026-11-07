// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"strings"

	"github.com/PRO-Robotech/corelib/platformmodules"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// registrationAuthority распознаёт настоящий модуль при каждом входе и определяет
// полномочия аккаунта после допуска. Отсутствующая зависимость всегда отвергает запись.
type registrationAuthority interface {
	Authorize(context.Context) (string, error)
	AuthorizeAccount(context.Context, string) error
}

// registrationAdmission несёт результат существующих канонических чтений. Его
// никогда не передаёт вызывающий и не восстанавливают из утверждений запроса.
type registrationAdmission struct {
	catalogType string
	hierarchies []domain.ParentHierarchy
	authorities []domain.ContainerScope
}

func (uc *RegisterResourceUseCase) WithRegistrationAuthority(a registrationAuthority) *RegisterResourceUseCase {
	uc.authority = a
	return uc
}

// authorizeIntent аутентифицирует до открытия транзакции. Принадлежность
// сверяется со строкой каталога этой транзакции, а не с вшитым словарём типов.
func (uc *RegisterResourceUseCase) authorizeIntent(ctx context.Context, t tupleIntent) (string, error) {
	if uc.authority == nil {
		return "", proxyWriteRefusal()
	}
	module, err := uc.authority.Authorize(ctx)
	if err != nil {
		return "", err
	}
	if err := validateRegistrationShape(module, t.subject, t.relation, t.object); err != nil {
		return "", err
	}
	return module, nil
}

func authorizeCatalogOwner(module, owner string) error {
	if module == "" || strings.ContainsAny(module, "* \t\n") || owner == "" {
		return proxyWriteRefusal()
	}
	// Сохраняем объявленные псевдонимы платформы (nlb -> loadbalancer). В остальных случаях
	// аутентифицированный списком установки сервис точно называет свой модуль.
	catalogModule, known := platformmodules.CatalogModuleOfService(module)
	if !known {
		catalogModule = module
	}
	if catalogModule != owner {
		return proxyWriteRefusal()
	}
	return nil
}

// authorizeCatalogType принимает и снятые строки: очистка/публикация — не
// регистрация и не должны требовать живого типа или разрешения текущих записей.
func (uc *RegisterResourceUseCase) authorizeCatalogType(ctx context.Context, tx service.Tx, module string, t tupleIntent) (string, error) {
	typ, id := t.splitObject()
	identity, known, err := uc.catalogTypes.CatalogTypeTx(ctx, tx, typ)
	if err != nil {
		return "", err
	}
	if !known {
		return "", proxyWriteRefusal()
	}
	if err := authorizeCatalogOwner(module, identity.Module); err != nil {
		return "", err
	}
	if err := validateRegistrationShape(module, t.subject, t.relation, identity.ObjectType+":"+id); err != nil {
		return "", err
	}
	return identity.Dotted, nil
}

func (uc *RegisterResourceUseCase) authorizeScopes(ctx context.Context, hs []domain.ContainerScope) error {
	if uc.authority == nil || len(hs) == 0 {
		return proxyWriteRefusal()
	}
	seen := map[string]bool{}
	for _, h := range hs {
		if !h.Registered || h.AccountID == "" {
			return proxyWriteRefusal()
		}
		if seen[h.AccountID] {
			continue
		}
		seen[h.AccountID] = true
		if err := uc.authority.AuthorizeAccount(ctx, h.AccountID); err != nil {
			return err
		}
	}
	return nil
}

// savedRegistrationScopeReader учитывает постоянную выдачу проекта лишь для
// ранее зарегистрированного ключа. Неизвестные ключи не получают отметки снятия для очистки.
type savedRegistrationScopeReader interface {
	SavedRegistrationScopesTx(context.Context, service.Tx, string, string) ([]domain.ContainerScope, error)
	SaveRegistrationScopesTx(context.Context, service.Tx, string, string, []domain.ContainerScope) error
}

func (uc *RegisterResourceUseCase) savedAuthorityScopes(ctx context.Context, tx service.Tx, t tupleIntent) ([]domain.ContainerScope, error) {
	r, ok := uc.scopes.(savedRegistrationScopeReader)
	if !ok {
		return nil, proxyWriteRefusal()
	}
	typ, id := t.splitObject()
	scopes, err := r.SavedRegistrationScopesTx(ctx, tx, typ, id)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return nil, proxyWriteRefusal()
	}
	for _, s := range scopes {
		if !s.Registered || s.AccountID == "" {
			return nil, proxyWriteRefusal()
		}
	}
	return scopes, nil
}

// registrationAuthorities отделяет полномочия аккаунта от проецируемой иерархии,
// используемой для проверки утверждений. Пропущенный проект остаётся пропущенным (DP-14).
// Лишь уже допущенному контейнеру с H=[K] нужно чтение сохранённых полномочий.
func (uc *RegisterResourceUseCase) registrationAuthorities(ctx context.Context, tx service.Tx, hs []domain.ParentHierarchy) ([]domain.ContainerScope, error) {
	var out []domain.ContainerScope
	seen := map[string]bool{}
	for _, h := range hs {
		if h.AccountID != "" {
			out = append(out, domain.ContainerScope{Registered: true, ProjectID: h.ProjectID, AccountID: h.AccountID})
			continue
		}
		if len(h.Links) != 1 {
			return nil, proxyWriteRefusal()
		}
		if seen[h.Links[0]] {
			continue
		}
		seen[h.Links[0]] = true
		typ, id, ok := strings.Cut(h.Links[0], ":")
		if !ok || typ == "project" {
			return nil, proxyWriteRefusal()
		}
		saved, err := uc.savedAuthorityScopes(ctx, tx, tupleIntent{object: typ + ":" + id})
		if err != nil {
			return nil, err
		}
		out = append(out, saved...)
	}
	if len(out) == 0 {
		return nil, proxyWriteRefusal()
	}
	return out, nil
}
