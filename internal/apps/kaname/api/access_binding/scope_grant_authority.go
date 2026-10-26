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
// ярус `admin` на объекте области. Надзор администратора облака не зависит от
// области и задаётся один раз на всю проверку, а не на каждую область. Число
// вопросов к хранилищу не больше числа различных областей плюс один.
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
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// grantScope — область выдачи: тип (`account` | `project` | `cluster`) и id.
type grantScope struct{ resourceType, resourceID string }

// ScopeGrantAuthority — право вызывающего выдавать на областях действующих выдач
// роли либо группы-субъекта.
type ScopeGrantAuthority struct {
	repo      Repo
	relations clients.RelationStore
}

// NewScopeGrantAuthority — над тем же хранилищем и той же дверью решения, что
// `CreateAccessBindingUseCase`.
func NewScopeGrantAuthority(repo Repo, relations clients.RelationStore) *ScopeGrantAuthority {
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

// RequireForGroup — вызывающий вправе выдавать на каждой области действующих
// выдач, называющих группу `id` субъектом (Р3): новый участник получает всё, что
// выдано группе.
func (a *ScopeGrantAuthority) RequireForGroup(ctx context.Context, id domain.GroupID) error {
	scopes, err := a.activeScopesOfGroup(ctx, id)
	if err != nil {
		return err
	}
	return a.requireOnScopes(ctx, scopes)
}

// groupBindingsPage — страница чтения выдач группы: тот же предел, что у
// перечней выдач.
const groupBindingsPage = 1000

// activeScopesOfGroup — различные области неотозванных выдач, где группа —
// субъект (парой строки выдачи либо строкой набора субъектов). Перечень читается
// постранично до конца: область, оставшаяся за границей страницы, осталась бы
// непроверенной.
func (a *ScopeGrantAuthority) activeScopesOfGroup(ctx context.Context, id domain.GroupID) ([]grantScope, error) {
	rd, err := a.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	var active []domain.AccessBinding
	token := ""
	for {
		page, next, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeGroup, domain.SubjectID(id),
			abrepo.PageFilter{PageSize: groupBindingsPage, PageToken: token})
		if err != nil {
			return nil, shared.MapRepoErr(err)
		}
		for _, b := range page {
			if b.Status != domain.AccessBindingStatusRevoked {
				active = append(active, b)
			}
		}
		if next == "" {
			return distinctScopes(active), nil
		}
		token = next
	}
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
// администратора облака — один вопрос на весь набор: он о личности вызывающего, а
// не об области.
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
	for _, s := range scopes {
		if err := grantAuthorityBeyondClusterAdmin(ctx, a.repo, a.relations, s.resourceType, s.resourceID); err != nil {
			return err
		}
	}
	return nil
}
