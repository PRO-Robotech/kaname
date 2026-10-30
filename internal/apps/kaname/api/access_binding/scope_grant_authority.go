// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// scope_grant_authority.go — право выдавать на ОБЛАСТЯХ действующих выдач: то же
// право, что спрашивает `AccessBindingService.Create`, заданное правке, которая
// меняет содержимое уже выданного (приёмка role-rights-stay-within-what-is-named.md,
// Р2 и Р3, Д-2; задачи PRO-Robotech/kaname#1036, PRO-Robotech/kaname#1037).
//
// # Зачем
//
// Правка правил роли меняет права каждого, кому роль выдана, а добавление
// участника в группу выдаёт ему всё, что выдано группе. Без этой проверки правящий
// роль (группу) получал больше, чем сам вправе выдать: дописать в роль `*` и тем
// самым выдать её держателям всё — на областях, где у правящего права выдавать нет.
//
// # Что спрашивается
//
// По каждой РАЗЛИЧНОЙ области действующих выдач — тот же вопрос, что у выдачи
// (`requireGrantAuthority`): администратор облака, владелец аккаунта области либо
// ярус `admin` на объекте области. Цена вопроса к хранилищу отношений НЕ растёт с
// числом областей — а оно растёт с тем, что уже выдано, и до проверки ничем не
// ограничено:
//
//   - надзор администратора облака — один вопрос на всю проверку: он о личности
//     вызывающего, а не об области;
//   - ярус `admin` — один партийный вопрос о всех областях сразу
//     (`authzfilter.HeldOn`): по партии на тип области (`account`, `project`,
//     `cluster`), ceil(n / authzfilter.MaxBatchChecksPerRequest) запросов на тип;
//   - владелец аккаунта — только для областей, где яруса нет, чтением в ОДНОЙ
//     читающей транзакции, открытой ПОСЛЕ вопросов к хранилищу (довод — у
//     `scopeOwnerUserID`, kaname#1015), до первой области без права.
//
// Цена закреплена пробой `TestScopeGrantAuthority_RelationQuestionsDoNotGrowWithScopes`.
//
// Делегированный путь права выдавать (PRO-Robotech/kaname#986) правом здесь не считается (Д-2):
// делегирование ограничено ролями и целями модуля, а правка роли аккаунта и
// состав группы в его перечень не входят.
//
// # Какие выдачи — действующие
//
// Неотозванные (`ListActiveByRole`, та же выборка, что у веера сверки при правке
// роли): ровно те выдачи, чьи кортежи следуют правилам роли. Отозванная права не
// открывает и в проверке не участвует (Д-6).
//
// # Исходы
//
// Пустой набор областей — разрешено: проверять нечего (ESC-11, ESC-21). Отказ —
// `authzguard.PermissionDenied()`, побайтово как отказ без права. Хранилище
// отношений не ответило — `authzguard.AuthzBackendUnavailable()`, повтор осмыслен.

import (
	"context"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// grantScope — область выдачи: тип (`account` | `project` | `cluster`) и id.
type grantScope struct{ resourceType, resourceID string }

// GrantAuthorityRelations — дверь решения проверки права выдавать на областях:
// одиночный вопрос надзора (`Check`) и партийный вопрос о наборе областей
// (`BatchCheckWithContext`). Партийная форма объявлена в порту, а не спрошена у
// значения: провязка без неё — ошибка компиляции, а не тихий возврат к вопросу на
// область.
type GrantAuthorityRelations interface {
	clients.RelationStore
	authzfilter.BatchObjectChecker
}

// ScopeGrantAuthority — право вызывающего выдавать на областях действующих выдач
// роли либо группы-субъекта.
type ScopeGrantAuthority struct {
	repo      Repo
	relations GrantAuthorityRelations
}

// NewScopeGrantAuthority — над тем же хранилищем и той же дверью решения, что
// `CreateAccessBindingUseCase`.
func NewScopeGrantAuthority(repo Repo, relations GrantAuthorityRelations) *ScopeGrantAuthority {
	return &ScopeGrantAuthority{repo: repo, relations: relations}
}

// RequireForRole — вызывающий вправе выдавать роль `id` на каждой области её
// действующих выдач (Р2).
func (a *ScopeGrantAuthority) RequireForRole(ctx context.Context, id domain.RoleID) error {
	scopes, err := a.activeScopesOfRole(ctx, id)
	if err != nil {
		return err
	}
	return a.requireOnScopes(ctx, scopes)
}

// activeScopesOfRole — различные области действующих выдач роли, по порядку.
// Читающая транзакция закрывается ДО вопросов к хранилищу отношений: вопрос
// берёт соединение того же пула (довод — у `scopeOwnerUserID`, kaname#1015).
func (a *ScopeGrantAuthority) activeScopesOfRole(ctx context.Context, id domain.RoleID) ([]grantScope, error) {
	rd, err := a.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	bindings, err := rd.AccessBindings().ListActiveByRole(ctx, id)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return distinctScopes(bindings), nil
}

// distinctScopes — различные области выдач в детерминированном порядке: отказ
// называет одну и ту же область при одном и том же наборе.
func distinctScopes(bindings []domain.AccessBinding) []grantScope {
	seen := make(map[grantScope]struct{}, len(bindings))
	out := make([]grantScope, 0, len(bindings))
	for _, b := range bindings {
		s := grantScope{resourceType: string(b.ResourceType), resourceID: b.ResourceID}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].resourceType != out[j].resourceType {
			return out[i].resourceType < out[j].resourceType
		}
		return out[i].resourceID < out[j].resourceID
	})
	return out
}

// requireOnScopes — право выдавать на КАЖДОЙ области набора. Надзор
// администратора облака — один вопрос на весь набор; ярус `admin` — один
// партийный вопрос о всех областях; владелец — только там, где яруса нет.
//
// Исходы те же, что у requireGrantAuthority на каждой области по очереди:
// хранилище не ответило — `AuthzBackendUnavailable`; область без права —
// `PermissionDenied`; ошибка чтения владельца — её отображение.
func (a *ScopeGrantAuthority) requireOnScopes(ctx context.Context, scopes []grantScope) error {
	if len(scopes) == 0 {
		return nil
	}
	admin, err := authzguard.IsClusterAdminE(ctx, a.relations)
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if admin {
		return nil
	}
	held, err := a.scopeAdminHeld(ctx, scopes)
	if err != nil {
		// «Спросить не удалось» ≠ «не положено»: повтор осмыслен.
		return authzguard.AuthzBackendUnavailable()
	}
	unheld := make([]grantScope, 0, len(scopes))
	for _, s := range scopes {
		if !held[fgaAdminObject(s.resourceType, s.resourceID)] {
			unheld = append(unheld, s)
		}
	}
	return a.requireOwnerOfEach(ctx, unheld)
}

// scopeAdminHeld — объекты областей, на которых вызывающий держит ярус `admin`,
// одним партийным вопросом (authzfilter.HeldOn). Без двери либо без субъекта
// (аноним, неизвестный тип принципала) — пустой набор без вопроса: право даёт
// только Путь 1, как у fgaHoldsScopeAdminE.
func (a *ScopeGrantAuthority) scopeAdminHeld(ctx context.Context, scopes []grantScope) (map[string]bool, error) {
	if a.relations == nil {
		return map[string]bool{}, nil
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return map[string]bool{}, nil
	}
	objects := make([]string, 0, len(scopes))
	for _, s := range scopes {
		objects = append(objects, fgaAdminObject(s.resourceType, s.resourceID))
	}
	return authzfilter.HeldOn(ctx, a.relations, subject, "admin", objects)
}

// requireOwnerOfEach — Путь 1 на каждой области, где яруса `admin` нет:
// вызывающий — владелец аккаунта области. Одна читающая транзакция на весь
// остаток, открытая после вопросов к хранилищу отношений; первая область без
// права — отказ, дальше не читается. У области без владельца на стороне
// хранилища (`cluster`) Путь 1 не срабатывает.
func (a *ScopeGrantAuthority) requireOwnerOfEach(ctx context.Context, scopes []grantScope) error {
	if len(scopes) == 0 {
		return nil
	}
	if a.repo == nil {
		return authzguard.PermissionDenied()
	}
	rd, err := a.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	for _, s := range scopes {
		owner, err := scopeOwnerUserIDIn(ctx, rd, s.resourceType, s.resourceID)
		if err != nil {
			return err
		}
		if owner == "" || !authzguard.IsSelf(ctx, owner) {
			return authzguard.PermissionDenied()
		}
	}
	return nil
}
