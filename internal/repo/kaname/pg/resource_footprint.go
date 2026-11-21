// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Footprint отделяет проверяемые аккаунты регистрации от всех аккаунтов записи.
// Иностранный carrier участвует в замках и invalidation, но не порождает
// требование installation-права модуля на его аккаунт.
// Данные наполняет только RR collector; сама структура не доказывает полноту.
type resourceFootprint struct {
	global        bool
	sourceEffects map[resourceSourceEffect]struct{}
	registration  map[domain.AccountID]struct{}
	mutation      map[domain.AccountID]struct{}
	owners        map[kaname.AuthorityOwnerRef]struct{}
	objects       map[domain.ResourceRef]struct{}
}

// SourceEffect называет authored carrier/role, реально изменяемый pure
// withdrawal планом. Это proposal для server compiler, не complete-флаг.
type resourceSourceEffect struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

type resourceFenceFootprint struct {
	sourceEffects []resourceSourceEffect
	sourceWrite   bool
	plan          kaname.AuthorityFencePlan
	registration  []domain.AccountID
	owners        []kaname.AuthorityOwnerRef
	objects       []domain.ResourceRef
}

func newResourceFootprint() *resourceFootprint {
	return &resourceFootprint{
		sourceEffects: make(map[resourceSourceEffect]struct{}), registration: make(map[domain.AccountID]struct{}), mutation: make(map[domain.AccountID]struct{}),
		owners: make(map[kaname.AuthorityOwnerRef]struct{}), objects: make(map[domain.ResourceRef]struct{}),
	}
}

// Вызывается отдельно для OLD и NEW канонических scopes. Неполное наблюдение
// не подменяется аккаунтом актора, заявленным parent или пустым GLOBAL.
func (f *resourceFootprint) addRegistrationScopes(scopes []domain.ContainerScope) error {
	if f == nil || len(scopes) == 0 {
		return kaname.ErrSourceUnconfirmed
	}
	for _, scope := range scopes {
		if !scope.Registered || !nativeQuestionToken(scope.AccountID) {
			return kaname.ErrSourceUnconfirmed
		}
	}
	for _, scope := range scopes {
		id := domain.AccountID(scope.AccountID)
		f.registration[id] = struct{}{}
		if err := f.addMutationAccount(id); err != nil {
			return err
		}
	}
	return nil
}

func (f *resourceFootprint) addMutationAccount(account domain.AccountID) error {
	if f == nil || !nativeQuestionToken(string(account)) {
		return kaname.ErrSourceUnconfirmed
	}
	f.mutation[account] = struct{}{}
	f.owners[kaname.AuthorityOwnerRef{Kind: "account", ID: string(account)}] = struct{}{}
	return nil
}

// Владение носителя перечитывается coordinator отдельно от его effect accounts.
// Получатель факта сюда не добавляется: его домашний аккаунт не является
// аккаунтом изменяемого объекта. SOURCE зависимости получателя читаются shared.
func (f *resourceFootprint) addCarrier(kind, id string, accounts []domain.AccountID) error {
	if f == nil || (kind != "binding" && kind != "role") || !nativeQuestionToken(id) || len(accounts) == 0 {
		return kaname.ErrSourceUnconfirmed
	}
	for _, account := range accounts {
		if !nativeQuestionToken(string(account)) {
			return kaname.ErrSourceUnconfirmed
		}
	}
	f.owners[kaname.AuthorityOwnerRef{Kind: kind, ID: id}] = struct{}{}
	for _, account := range accounts {
		if err := f.addMutationAccount(account); err != nil {
			return err
		}
	}
	return nil
}

func (f *resourceFootprint) addObject(object domain.ResourceRef) error {
	if f == nil || !nativeQuestionToken(object.Type) || !nativeQuestionToken(object.ID) {
		return kaname.ErrSourceUnconfirmed
	}
	f.objects[object] = struct{}{}
	return nil
}

// Этот путь предназначен только для полностью классифицированного local плана.
// Превышение bound не превращает его в GLOBAL и не усекает набор аккаунтов.
// Подлинный global effect получает отдельный заранее классифицированный profile.
func (f *resourceFootprint) local() (resourceFenceFootprint, error) {
	if f == nil || f.global || len(f.mutation) == 0 || len(f.mutation) > kaname.MaxAuthorityFenceAccounts || len(f.owners) > kaname.MaxAuthorityOwnershipRefs || len(f.objects) == 0 {
		return resourceFenceFootprint{}, kaname.ErrSourceUnconfirmed
	}
	out := resourceFenceFootprint{sourceWrite: len(f.sourceEffects) != 0, sourceEffects: f.orderedSourceEffects(), plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts}}
	for account := range f.mutation {
		out.plan.Accounts = append(out.plan.Accounts, account)
	}
	for account := range f.registration {
		out.registration = append(out.registration, account)
	}
	for owner := range f.owners {
		out.owners = append(out.owners, owner)
	}
	for object := range f.objects {
		out.objects = append(out.objects, object)
	}
	slices.Sort(out.plan.Accounts)
	slices.Sort(out.registration)
	slices.SortFunc(out.owners, func(a, b kaname.AuthorityOwnerRef) int {
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	slices.SortFunc(out.objects, func(a, b domain.ResourceRef) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}

// Глобальный профиль выбирается только по захваченному кластерному носителю,
// а не как запасной путь при неизвестной области или превышении лимита.
func (f *resourceFootprint) addGlobalCarrier(kind, id string) error {
	if f == nil || (kind != "binding" && kind != "role") || !nativeQuestionToken(id) {
		return kaname.ErrSourceUnconfirmed
	}
	f.global = true
	f.owners[kaname.AuthorityOwnerRef{Kind: kind, ID: id}] = struct{}{}
	return nil
}

func (f *resourceFootprint) classified() (resourceFenceFootprint, error) {
	if f == nil {
		return resourceFenceFootprint{}, kaname.ErrSourceUnconfirmed
	}
	if !f.global {
		return f.local()
	}
	if len(f.owners) > kaname.MaxAuthorityOwnershipRefs || len(f.registration) > kaname.MaxAuthorityFenceAccounts || len(f.objects) == 0 {
		return resourceFenceFootprint{}, kaname.ErrSourceUnconfirmed
	}
	out := resourceFenceFootprint{sourceWrite: len(f.sourceEffects) != 0, sourceEffects: f.orderedSourceEffects(), plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	for account := range f.registration {
		out.registration = append(out.registration, account)
	}
	for owner := range f.owners {
		out.owners = append(out.owners, owner)
	}
	for object := range f.objects {
		out.objects = append(out.objects, object)
	}
	slices.Sort(out.registration)
	slices.SortFunc(out.owners, func(a, b kaname.AuthorityOwnerRef) int {
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	slices.SortFunc(out.objects, func(a, b domain.ResourceRef) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out, nil
}

// Профиль объявляется до entry. Нельзя повысить его после source recheck:
// изменение actual effect требует заново выполнить всю RR→RC попытку.
func (f *resourceFootprint) addSourceEffect(kind, id string) error {
	if f == nil || f.sourceEffects == nil || (kind != "binding" && kind != "role") || !nativeQuestionToken(id) {
		return kaname.ErrSourceUnconfirmed
	}
	f.sourceEffects[resourceSourceEffect{Kind: kind, ID: id}] = struct{}{}
	if len(f.sourceEffects) > kaname.MaxAuthorityOwnershipRefs {
		return kaname.ErrSourceReadLimit
	}
	return nil
}
func (f *resourceFootprint) orderedSourceEffects() []resourceSourceEffect {
	out := make([]resourceSourceEffect, 0, len(f.sourceEffects))
	for effect := range f.sourceEffects {
		out = append(out, effect)
	}
	slices.SortFunc(out, func(a, b resourceSourceEffect) int {
		if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}
